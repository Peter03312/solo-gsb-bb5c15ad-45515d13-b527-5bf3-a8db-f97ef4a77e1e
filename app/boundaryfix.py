"""定界符冲突修复：为可编辑 MIME 树中冲突的 multipart 层生成新 boundary。

检查口径与 /api/encode 的**实际回写字节**完全一致（复用
``mime._assemble_node`` 组装逻辑）：未编辑叶子回写 ``rawBodyBase64``
保存的原始传输字节，已编辑叶子按所选 CTE 重新编码。

算法（自内向外）：
1. 后序递归，先处理所有内层 multipart（内层修复会改变外层看到的字节）；
2. 对本层的序言与每个子实体字节做行首检查：若存在行首 ``--boundary``
   （会被本层解析器误认作定界符），则只为该层生成新 boundary；
3. 新 boundary 符合 RFC 2046（bchars、长度 ≤ 70），且其行首形式
   ``--new`` 不出现在本层序言/子实体中；由于检查自内向外进行、外层
   冲突（含内层新 boundary 与外层相同的情形）会在外层修复时被捕获，
   等价于在完整输出中不冲突；
4. 修复值同步到节点 Content-Type 头部。

修复是**原子**的：全部操作在树的深拷贝上进行，任一层无法安全修复时
返回错误，调用方持有的原树保持不变。
"""

from __future__ import annotations

import copy
import hashlib

from .mime import (
    BOUNDARY_BCHARS_RE,
    CRLF,
    DASHDASH,
    _assemble_node,
    _encode_text,
    _sync_boundary_header,
)

# 候选 boundary 的最大尝试次数（确定性派生，正常第一个即成功）
MAX_CANDIDATES = 64

# RFC 2046 bcharsnospace（生成的 boundary 不含空格，天然满足 bchars）
_BCHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'()+_,-./:=?"


def _child_path(parent_path: str, index: int) -> str:
    """与前端 reindexPaths 一致的路径规则：root -> parts[0] -> parts[0].parts[1]。"""
    if parent_path == "root":
        return f"parts[{index}]"
    return f"{parent_path}.parts[{index}]"


def _line_start_conflict(data: bytes, delim: bytes) -> bool:
    """data 中是否存在行首的 delim（会被本层解析器误认作定界符）。

    data 的起点本身即行首：序言之前是头部空行 CRLF（或不带顶层头部时的
    报文起点，解析器同样按行首处理）；子实体之前是定界符行的 CRLF。
    """
    return data.startswith(delim) or (CRLF + delim) in data


def _entity_bytes(child: dict, path: str, scratch: list) -> bytes:
    """子实体在完整输出中的实际回写字节（head + 空行 + body）。

    与 _assemble_node 的 multipart 分支拼装方式完全一致；未编辑叶子由
    其内部逻辑回写 rawBodyBase64 保存的原始传输字节。
    """
    chead, cbody = _assemble_node(child, scratch, path)
    entity = (chead + CRLF) if chead else b""
    return entity + cbody


def _layer_bytes(node: dict, path: str, scratch: list):
    """本层回写字节：``(preamble, [entity, ...])``。"""
    preamble = _encode_text(node.get("preamble", ""),
                            node.get("preambleEncoding", "utf-8"))
    entities = [
        _entity_bytes(child, _child_path(path, i), scratch)
        for i, child in enumerate(node.get("parts", []))
    ]
    return preamble, entities


def _has_conflict(node: dict, preamble: bytes, entities: list) -> bool:
    """本层序言或子实体中是否存在会被误认作本层定界符的行首内容。"""
    delim = DASHDASH + (node.get("boundary") or "").encode("utf-8", "replace")
    if _line_start_conflict(preamble, delim):
        return True
    return any(_line_start_conflict(e, delim) for e in entities)


def _candidate_boundaries(original: str, path: str):
    """确定性地生成 RFC 2046 合规候选 boundary（bchars、长度 ≤ 70）。

    从原 boundary 过滤出的合法字符加哈希后缀派生；同一输入总是产生同一
    候选序列，便于测试与复现。
    """
    base = "".join(ch for ch in original if ch in _BCHARS)[:40] or "boundary"
    for attempt in range(MAX_CANDIDATES):
        digest = hashlib.sha256(
            f"mime-boundary-fix|{path}|{original}|{attempt}".encode("utf-8")
        ).hexdigest()[:16]
        candidate = f"{base}-fix-{digest}"
        if BOUNDARY_BCHARS_RE.fullmatch(candidate.encode("ascii")):
            yield candidate


def fix_boundary_conflicts(tree: dict) -> dict:
    """检查并修复整棵树中的定界符冲突。

    返回：
      * 有修复：``{"ok": True, "changed": True, "fixes": [...], "tree": 新树}``
        （``fixes`` 每项含 ``path`` / ``oldBoundary`` / ``newBoundary``）；
      * 无冲突：``{"ok": True, "changed": False, "fixes": [], "tree": None}``；
      * 无法安全修复：``{"ok": False, "changed": False, "error": 原因}``，
        传入的树保持不变。
    """
    if not isinstance(tree, dict):
        return {"ok": False, "changed": False, "fixes": [],
                "error": "报文树格式错误"}
    work = copy.deepcopy(tree)
    fixes: list[dict] = []

    def visit(node: dict, path: str):
        """自内向外修复；返回 None 表示成功，否则返回错误消息。"""
        if node.get("kind") != "multipart":
            return None
        for i, child in enumerate(node.get("parts", [])):
            err = visit(child, _child_path(path, i))
            if err is not None:
                return err
        scratch: list = []  # 组装副产物（诊断）与本功能无关，丢弃
        preamble, entities = _layer_bytes(node, path, scratch)
        if not _has_conflict(node, preamble, entities):
            return None
        old = node.get("boundary") or ""
        for candidate in _candidate_boundaries(old, path):
            delim = DASHDASH + candidate.encode("ascii")
            if _line_start_conflict(preamble, delim):
                continue
            if any(_line_start_conflict(e, delim) for e in entities):
                continue
            node["boundary"] = candidate
            _sync_boundary_header(node.setdefault("headers", []),
                                  node.get("mediaType") or "multipart/mixed",
                                  candidate, scratch, path)
            fixes.append({"path": path, "oldBoundary": old,
                          "newBoundary": candidate})
            return None
        return (f"{path}：序言/子实体内容与本层定界符冲突，但 "
                f"{MAX_CANDIDATES} 个候选 boundary 均无法在完整输出中"
                "保证不冲突，该层无法安全修复")

    err = visit(work, "root")
    if err is not None:
        return {"ok": False, "changed": False, "fixes": [],
                "error": err + "；整棵树保持不变"}
    if not fixes:
        return {"ok": True, "changed": False, "fixes": [], "tree": None,
                "message": "未发现定界符冲突，无需修复"}

    # 最终验证（双保险）：修复后的树按相同口径不应再有任何冲突
    def verify(node: dict, path: str):
        if node.get("kind") != "multipart":
            return None
        for i, child in enumerate(node.get("parts", [])):
            err2 = verify(child, _child_path(path, i))
            if err2 is not None:
                return err2
        scratch2: list = []
        preamble, entities = _layer_bytes(node, path, scratch2)
        if _has_conflict(node, preamble, entities):
            return f"{path}：修复后仍存在定界符冲突"
        return None

    err = verify(work, "root")
    if err is not None:
        return {"ok": False, "changed": False, "fixes": [],
                "error": err + "；整棵树保持不变"}

    return {"ok": True, "changed": True, "fixes": fixes, "tree": work}
