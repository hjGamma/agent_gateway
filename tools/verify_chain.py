#!/usr/bin/env python3
"""
Agent Gateway - 独立审计链验证器

仅依赖 Python 标准库, 可脱离项目独立运行, 用于验证审计日志文件
(app.audit_logger 产出的 JSON 文件) 的 SHA-256 哈希链完整性。

仿照 MCP-PEP 的 tools/verify_chain.py 设计:
  - 支持传入文件或目录 (目录递归查找 .json)
  - 逐文件验证, 汇总输出
  - 输出格式: "Summary: N PASS, M FAIL out of K files"

用法:
    python tools/verify_chain.py <file_or_dir> [<file_or_dir> ...]

示例:
    python tools/verify_chain.py audit_log.json
    python tools/verify_chain.py logs/
    python tools/verify_chain.py log1.json log2.json logs/

退出码:
    0 - 全部文件验证通过
    1 - 存在验证失败的文件
    2 - 参数错误或无可验证文件
"""
import hashlib
import json
import os
import sys
from typing import List, Tuple


# 创世哈希: 64 个 '0' (与 app.audit_logger.GENESIS_PREV_HASH 保持一致)
GENESIS_PREV_HASH = '0' * 64


def _compute_event_hash(event: dict) -> str:
    """计算单个事件的 SHA-256 哈希

    对除 event_hash 外的所有字段做
    json.dumps(sort_keys=True, ensure_ascii=False, default=str) 后再 sha256。
    与 app.audit_logger.HashChainedAuditLogger._compute_hash 完全一致。
    """
    data = {k: v for k, v in event.items() if k != 'event_hash'}
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def verify_chain_file(filepath: str) -> Tuple[bool, int, int, str]:
    """验证单个审计日志文件的哈希链完整性

    Args:
        filepath: 审计日志文件路径 (JSON)

    Returns:
        (is_valid, passed, failed, message) 元组:
          - is_valid: 整体是否有效 (failed == 0 且文件成功加载且有事件)
          - passed:   通过验证的事件数
          - failed:   未通过验证的事件数
          - message:  人类可读的描述信息
    """
    if not os.path.exists(filepath):
        return False, 0, 0, f"file not found: {filepath}"

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, 0, 0, f"invalid JSON in {filepath}: {e}"
    except OSError as e:
        return False, 0, 0, f"read error for {filepath}: {e}"

    # 兼容两种格式:
    #   1. 顶层为 {"events": [...], ...} (HashChainedAuditLogger.save_to_file 产出)
    #   2. 顶层直接为事件列表 [...]
    if isinstance(data, list):
        events = data
    elif isinstance(data, dict):
        events = data.get('events', [])
    else:
        return False, 0, 0, f"unexpected top-level JSON type in {filepath}"

    if not isinstance(events, list):
        return False, 0, 0, f"'events' is not a list in {filepath}"

    if len(events) == 0:
        # 空链视为有效 (没有任何事件可被篡改)
        return True, 0, 0, "empty chain (0 events)"

    passed = 0
    failed = 0
    expected_prev = GENESIS_PREV_HASH
    first_failure = None

    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            failed += 1
            if first_failure is None:
                first_failure = f"event#{idx}: not a JSON object"
            # 无法继续链接, 期望的 prev_hash 未知
            expected_prev = None
            continue

        # 1. 验证 prev_hash 链接
        actual_prev = event.get('prev_hash')
        if expected_prev is None or actual_prev != expected_prev:
            failed += 1
            if first_failure is None:
                exp = (expected_prev[:12] + '...') if expected_prev else 'None'
                got = (str(actual_prev)[:12] + '...') if actual_prev else 'None'
                first_failure = (
                    f"event#{idx} (seq={event.get('seq')}): prev_hash mismatch "
                    f"(expected {exp}, got {got})"
                )
            expected_prev = event.get('event_hash')
            continue

        # 2. 验证 event_hash
        stored_hash = event.get('event_hash')
        recomputed = _compute_event_hash(event)
        if stored_hash != recomputed:
            failed += 1
            if first_failure is None:
                s = (str(stored_hash)[:12] + '...') if stored_hash else 'None'
                r = recomputed[:12] + '...'
                first_failure = (
                    f"event#{idx} (seq={event.get('seq')}): event_hash mismatch "
                    f"(stored {s}, recomputed {r})"
                )
            expected_prev = stored_hash
            continue

        passed += 1
        expected_prev = stored_hash

    is_valid = (failed == 0)
    if is_valid:
        message = f"OK: {passed} event(s) verified, chain intact"
    else:
        message = f"FAIL: {passed} passed, {failed} failed; first failure: {first_failure}"

    return is_valid, passed, failed, message


def _collect_files(paths: List[str]) -> List[str]:
    """从路径列表收集所有 .json 文件 (目录递归查找)

    不存在的路径也会保留, 以便在验证阶段报告明确的错误。
    """
    files: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, fnames in os.walk(p):
                for fname in sorted(fnames):
                    if fname.endswith('.json'):
                        files.append(os.path.join(root, fname))
        else:
            # 文件或不存在路径, 一律保留
            files.append(p)
    return files


def main(argv: List[str] = None) -> int:
    """命令行主入口

    Returns:
        退出码: 0 全部通过, 1 存在失败, 2 参数错误
    """
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        prog = os.path.basename(sys.argv[0]) if sys.argv else 'verify_chain.py'
        print(f"Usage: python {prog} <file_or_dir> [<file_or_dir> ...]")
        print("  Verifies SHA-256 hash chain integrity of audit log files.")
        print("  Arguments can be .json files or directories (searched recursively).")
        return 2

    files = _collect_files(argv)

    if not files:
        print("No files to verify (no .json files found in given paths).")
        return 2

    total_files = len(files)
    files_ok = 0
    files_bad = 0
    total_events_pass = 0
    total_events_fail = 0

    print(f"Verifying {total_files} file(s)...")
    print("-" * 70)

    for filepath in files:
        is_valid, passed, failed, message = verify_chain_file(filepath)
        total_events_pass += passed
        total_events_fail += failed
        if is_valid:
            files_ok += 1
            status = "PASS"
        else:
            files_bad += 1
            status = "FAIL"
        print(f"[{status}] {filepath}")
        print(f"        {message}")

    print("-" * 70)
    # 按要求输出汇总行
    print(f"Summary: {files_ok} PASS, {files_bad} FAIL out of {total_files} files")
    print(f"         ({total_events_pass} events passed, {total_events_fail} events failed)")

    return 0 if files_bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
