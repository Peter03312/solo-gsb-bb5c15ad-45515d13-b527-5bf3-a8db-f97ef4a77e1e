"""multipart/form-data 字段检查：逐个容器按原顺序列出直接叶子字段。

规则（对当前解析或编辑后的树做静态分析，类型与 name/filename 一律按节点
**当前头部**判断，编辑后即时生效）：

* 容器：当前 Content-Type 为 ``multipart/form-data`` 的 multipart 节点
  （含嵌套；嵌套的 form-data 子树各自成为独立容器）；
* 记录：容器的**直接叶子**（``kind == "part"``），按原顺序列出；重复
  name 保留为多条有序记录；嵌套 multipart 子节点不是叶子，不列入父容器；
* 带 ``filename``（普通或 RFC 2231 扩展参数）的叶子标为**文件项**，
  不计入文本字段，也不做文本解码；
* 文本字符集优先级：叶子 Content-Type 的 ``charset`` → 同容器首个有效的
  ``_charset_`` 字段值 → UTF-8。``_charset_`` 与字段出现位置无关，
  即使排在后面也作用于本容器全部字段；多个 ``_charset_`` 时按顺序取
  第一个“值可读出且为已知文本字符集”的；
* CTE 畸形（malformed）/ 未知 CTE（passthrough）的未编辑叶子、未知
  字符集、解码失败：``value`` 为 ``null`` 并给出原因，绝不用替换字符
  伪造文本。
"""

from __future__ import annotations

import codecs
from typing import Optional

from .attachments import has_filename_param, parse_disposition, resolve_filename
from .cidcheck import node_media_type
from .mime import _encode_text, find_header, parse_content_type

# HTML 表单惯例：隐藏字段 _charset_ 的值声明本次提交使用的字符集
CHARSET_FIELD = "_charset_"
DEFAULT_CHARSET = "utf-8"


# --------------------------------------------------------------------------- #
# 字符集
# --------------------------------------------------------------------------- #

def _valid_charset(name: str) -> bool:
    """已知且可用于文本解码的字符集（排除 base64/hex 等字节编解码器）。"""
    try:
        codecs.lookup(name)
        b"".decode(name)
    except (LookupError, TypeError, ValueError):
        return False
    return True


def _leaf_charset(node: dict) -> Optional[str]:
    """叶子当前 Content-Type 的 charset 参数；未声明返回 None。"""
    h = find_header(node.get("headers") or [], "Content-Type")
    if h is None or not (h.get("value") or "").strip():
        return None
    throwaway: list[dict] = []
    _mt, params = parse_content_type(h["value"], throwaway)
    charset = (params.get("charset") or "").strip()
    return charset or None


# --------------------------------------------------------------------------- #
# 叶子字节（与附件导出同一口径：编辑通道还原；畸形/未知 CTE 未编辑不可取）
# --------------------------------------------------------------------------- #

def _leaf_bytes(node: dict):
    """返回 ``(bytes|None, status|None, reason|None)``。"""
    edited = bool(node.get("bodyEdited"))
    state = node.get("decodeState", "raw")
    if edited or state in ("raw", "decoded"):
        return (_encode_text(node.get("body", ""),
                             node.get("bodyEncoding", "utf-8")), None, None)
    cte = node.get("transferEncoding") or "?"
    if state == "malformed":
        return None, "cte-malformed", (
            f"Content-Transfer-Encoding（{cte}）的传输正文畸形，"
            "未编辑时无法保证 CTE 解码字节正确；请在结构树中编辑该节点后重试")
    return None, "cte-unknown", (
        f"未知的 Content-Transfer-Encoding（{cte}），无法进行传输解码；"
        "请在结构树中编辑该节点后重试")


def _container_charset(leaves: list[dict]) -> Optional[str]:
    """同容器首个有效的 ``_charset_`` 字段值（与位置无关，作用于整个容器）。

    “有效”：是文本字段（无 filename）、CTE 字节可取、值可按 ASCII 读出
    （字符集名本就是 ASCII）且为已知的文本字符集。多个 ``_charset_``
    字段时按容器内顺序取首个有效值。
    """
    for leaf in leaves:
        _disp, params = parse_disposition(leaf.get("headers") or [])
        if (params.get("name") or "") != CHARSET_FIELD:
            continue
        if has_filename_param(params):
            continue
        data, _status, _reason = _leaf_bytes(leaf)
        if data is None:
            continue
        try:
            candidate = data.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        if candidate and len(candidate) <= 100 and _valid_charset(candidate):
            return candidate
    return None


def _decode_text(data: bytes, charset: str):
    """严格解码，返回 ``(text|None, status|None, reason|None)``。

    未知字符集 / 解码失败都返回原因；绝不使用替换字符伪造文本。
    """
    if not _valid_charset(charset):
        return None, "unknown-charset", (
            f"未知或不可用于文本解码的字符集 {charset!r}；"
            "请修正该叶子的 Content-Type charset 或容器的 _charset_ 字段")
    try:
        return data.decode(charset), None, None
    except UnicodeDecodeError as exc:
        return None, "decode-failed", (
            f"正文无法按字符集 {charset!r} 解码（{exc}）；"
            "已保留原始字节，不使用替换字符伪造文本")


# --------------------------------------------------------------------------- #
# 字段记录
# --------------------------------------------------------------------------- #

def _field_record(leaf: dict, container_charset: Optional[str]) -> dict:
    headers = leaf.get("headers") or []
    _disp, params = parse_disposition(headers)
    record = {
        "path": leaf.get("path") or "",
        "name": params.get("name"),
        "mediaType": node_media_type(leaf) or "application/octet-stream",
        "kind": "text",
        "status": "ok",
        "charset": None,
        "charsetSource": None,
        "value": None,
        "filename": None,
        "reason": None,
    }

    # 带 filename 的叶子：文件项，不计入文本字段，不做文本解码
    if has_filename_param(params):
        filename, _source, _note = resolve_filename(params)
        record.update(kind="file", status="file", filename=filename)
        return record

    data, err_status, err_reason = _leaf_bytes(leaf)
    if data is None:
        record["status"] = err_status
        record["reason"] = err_reason
        return record

    leaf_cs = _leaf_charset(leaf)
    if leaf_cs:
        charset, source = leaf_cs, "leaf"
    elif container_charset:
        charset, source = container_charset, "container"
    else:
        charset, source = DEFAULT_CHARSET, "default"
    record["charset"] = charset
    record["charsetSource"] = source

    text, status, reason = _decode_text(data, charset)
    if text is None:
        record["status"] = status
        record["reason"] = reason
    else:
        record["value"] = text
    return record


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #

def inspect_form_data(tree: dict) -> dict:
    """对当前（可能已编辑的）树执行 multipart/form-data 字段检查。"""
    if not isinstance(tree, dict):
        return {"ok": False, "error": "报文树格式错误",
                "summary": {}, "containers": []}

    containers: list[dict] = []

    def walk(node):
        if not isinstance(node, dict) or node.get("kind") != "multipart":
            return
        if node_media_type(node) == "multipart/form-data":
            leaves = [c for c in (node.get("parts") or [])
                      if isinstance(c, dict) and c.get("kind") == "part"]
            container_cs = _container_charset(leaves)
            fields = [_field_record(leaf, container_cs) for leaf in leaves]
            containers.append({
                "path": node.get("path") or "",
                "mediaType": node_media_type(node) or "multipart/form-data",
                "defaultCharset": container_cs,
                "fieldCount": sum(1 for f in fields if f["kind"] == "text"),
                "fileCount": sum(1 for f in fields if f["kind"] == "file"),
                "errorCount": sum(1 for f in fields
                                  if f["status"] not in ("ok", "file")),
                "fields": fields,
            })
        for child in node.get("parts") or []:
            walk(child)

    walk(tree)
    summary = {
        "containers": len(containers),
        "fields": sum(c["fieldCount"] for c in containers),
        "files": sum(c["fileCount"] for c in containers),
        "errors": sum(c["errorCount"] for c in containers),
    }
    return {"ok": True, "summary": summary, "containers": containers}
