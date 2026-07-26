#!/usr/bin/env python3
"""
审计链篡改检测实验
==================
验证 HashChainedAuditLogger 的 SHA-256 哈希链对各类篡改的检测能力。

实验流程:
  1. 创建 HashChainedAuditLogger 实例
  2. 生成 100 条正常审计日志 (模拟工具调用验证事件)
  3. 验证正常链通过 (assert failed == 0)
  4. 测试 5 种篡改模式:
       - value_modification : 修改业务字段值
       - hash_forgery       : 篡改非 hash 字段使 event_hash 失配 (伪造哈希)
       - event_deletion     : 删除中间事件
       - event_reorder      : 交换两个事件位置
       - tail_truncation    : 截断尾部事件
  5. 对每种篡改: 通过 JSON 序列化/反序列化深拷贝正常链 events,
     执行篡改, 验证链, 记录是否检出 (failed >= 1 即检出)
  6. 输出表格格式结果, 保存到 results/audit_tampering.json

注意:
  hash_forgery 篡改应修改某个非 hash 字段的值, 而不是直接修改 event_hash。
  (直接改 event_hash 是平凡检测; 真实的"哈希伪造"是改了内容却保留旧哈希,
   使得重算的 event_hash 与存储的不一致, 从而被 verify_chain 检出。)
"""
import sys
import os
import json
import time

# 导入上级模块 (app 包)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.audit_logger import HashChainedAuditLogger, GENESIS_PREV_HASH


# ============================================================
# 配置
# ============================================================
NUM_EVENTS = 100
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'audit_tampering.json')

# 模拟工具池
TOOL_POOL = [
    'web_search', 'file_read', 'shell_exec',
    'code_exec', 'data_analysis', 'summarizer',
    'db_query', 'http_request', 'image_gen', 'translator',
]


# ============================================================
# 辅助函数
# ============================================================
def build_normal_chain(n: int = NUM_EVENTS) -> HashChainedAuditLogger:
    """构建一条长度为 n 的正常审计链 (模拟工具调用验证事件)"""
    logger = HashChainedAuditLogger()
    for i in range(n):
        tool_id = TOOL_POOL[i % len(TOOL_POOL)]
        # 模拟工具调用验证事件: 每条事件带 tool_id / nullifier / commit / status
        logger.log(
            'call_verified',
            tool_id=tool_id,
            nullifier=f'null_{i:04d}_{os.urandom(4).hex()}',
            commit=f'commit_{i:04d}',
            agent_id=f'agent_{i % 5}',
            status='verified',
            seq_no=i,
        )
    return logger


def deep_copy_events(events):
    """通过 JSON 序列化/反序列化实现 events 列表的深拷贝"""
    return json.loads(json.dumps(events, ensure_ascii=False, default=str))


def make_logger_from_events(events):
    """用一份 events 深拷贝构造一个新的 HashChainedAuditLogger"""
    logger = HashChainedAuditLogger()
    logger.events = events
    # 同步 prev_hash 为最后一条事件的 event_hash
    if events:
        logger.prev_hash = events[-1].get('event_hash', GENESIS_PREV_HASH)
    else:
        logger.prev_hash = GENESIS_PREV_HASH
    return logger


# ============================================================
# 5 种篡改模式
# ============================================================
def tamper_value_modification(logger: HashChainedAuditLogger) -> dict:
    """篡改模式 1: 修改业务字段值 (tool_id)"""
    target_seq = NUM_EVENTS // 2  # 中间事件
    ok = logger.tamper_value(seq=target_seq, field='tool_id', new_value='EVIL_TOOL')
    return {'target_seq': target_seq, 'field': 'tool_id', 'applied': ok}


def tamper_hash_forgery(logger: HashChainedAuditLogger) -> dict:
    """篡改模式 2: 哈希伪造

    注意: 不直接修改 event_hash, 而是修改某个非 hash 字段的值,
    使存储的 event_hash 与重算结果不一致 (相当于保留了旧哈希的伪造事件)。
    """
    target_seq = NUM_EVENTS // 3
    ok = logger.tamper_value(seq=target_seq, field='status', new_value='forged')
    return {'target_seq': target_seq, 'field': 'status', 'applied': ok}


def tamper_event_deletion(logger: HashChainedAuditLogger) -> dict:
    """篡改模式 3: 删除中间事件"""
    target_seq = NUM_EVENTS // 2
    ok = logger.tamper_delete(seq=target_seq)
    return {'target_seq': target_seq, 'applied': ok}


def tamper_event_reorder(logger: HashChainedAuditLogger) -> dict:
    """篡改模式 4: 交换两个事件位置"""
    i, j = 10, 60
    ok = logger.tamper_reorder(i, j)
    return {'i': i, 'j': j, 'applied': ok}


def tamper_tail_truncation(logger: HashChainedAuditLogger) -> dict:
    """篡改模式 5: 截断尾部事件"""
    n = 5
    removed = logger.tamper_truncate_tail(n=n)
    return {'removed': removed, 'applied': removed > 0}


# 篡改模式注册表
TAMPER_MODES = [
    ('value_modification', tamper_value_modification),
    ('hash_forgery',       tamper_hash_forgery),
    ('event_deletion',     tamper_event_deletion),
    ('event_reorder',      tamper_event_reorder),
    ('tail_truncation',    tamper_tail_truncation),
]


# ============================================================
# 主实验
# ============================================================
def run_experiment():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print('=' * 70)
    print('  审计链篡改检测实验 (HashChainedAuditLogger)')
    print('=' * 70)

    # 1. 构建正常链
    print(f'\n[1] 生成 {NUM_EVENTS} 条正常审计日志 ...')
    normal_logger = build_normal_chain(NUM_EVENTS)
    print(f'    事件数: {len(normal_logger)}')

    # 2. 验证正常链通过
    print('\n[2] 验证正常链完整性 ...')
    passed, failed = normal_logger.verify_chain()
    print(f'    passed={passed}, failed={failed}')
    assert failed == 0, f'正常链应当全部通过, 但 failed={failed}'
    assert passed == NUM_EVENTS, f'正常链 passed 应等于 {NUM_EVENTS}, 实际 {passed}'
    print('    [OK] 正常链完整性验证通过')

    # 3. 保存正常链 events 的原始快照 (用于每次深拷贝)
    original_events = normal_logger.events

    # 4. 逐种篡改测试
    print('\n[3] 执行 5 种篡改模式测试 ...')
    results = []
    for mode_name, tamper_fn in TAMPER_MODES:
        # 深拷贝正常链 events
        events_copy = deep_copy_events(original_events)
        tampered_logger = make_logger_from_events(events_copy)

        # 执行篡改
        tamper_info = tamper_fn(tampered_logger)

        # 验证链
        t_passed, t_failed = tampered_logger.verify_chain()

        # 是否检出: failed >= 1 即认为检出
        detected = t_failed >= 1

        result = {
            'tamper_mode': mode_name,
            'tamper_detail': tamper_info,
            'events_after_tamper': len(tampered_logger),
            'passed': t_passed,
            'failed': t_failed,
            'detected': detected,
        }
        results.append(result)

    # 5. 输出表格
    print('\n[4] 篡改检测结果:')
    print('-' * 70)
    header = f'{"篡改模式":<22}{"事件数":>8}{"passed":>10}{"failed":>10}{"检出":>8}'
    print(header)
    print('-' * 70)
    for r in results:
        flag = 'YES' if r['detected'] else 'NO'
        print(f'{r["tamper_mode"]:<22}{r["events_after_tamper"]:>8}'
              f'{r["passed"]:>10}{r["failed"]:>10}{flag:>8}')
    print('-' * 70)

    detected_count = sum(1 for r in results if r['detected'])
    print(f'\n检出率: {detected_count}/{len(results)} '
          f'({detected_count / len(results) * 100:.1f}%)')

    # 说明: 纯哈希链无法检测尾部截断 (剩余链仍自洽),
    # 这是哈希链的固有盲点, 需配合外部锚定/长度签名等机制弥补。
    not_detected = [r['tamper_mode'] for r in results if not r['detected']]
    if not_detected:
        print(f'\n[NOTE] 以下篡改未被检出 (哈希链固有盲点): {", ".join(not_detected)}')
        print('       尾部截断会保留剩余链的自洽性, 需配合外部锚定/长度签名等机制弥补。')

    # 6. 保存结果
    summary = {
        'experiment': 'audit_tampering_detection',
        'module': 'app.audit_logger.HashChainedAuditLogger',
        'num_normal_events': NUM_EVENTS,
        'normal_chain': {
            'passed': passed,
            'failed': failed,
            'intact': failed == 0,
        },
        'tamper_modes': results,
        'detected_count': detected_count,
        'total_modes': len(results),
        'detection_rate': detected_count / len(results),
        'not_detected_modes': not_detected,
        'note': ('纯哈希链无法检测尾部截断 (剩余链仍自洽), '
                 '这是哈希链的固有盲点, 需配合外部锚定/长度签名等机制弥补。'),
        'timestamp': time.time(),
    }
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f'\n[5] 结果已保存到: {os.path.abspath(RESULTS_FILE)}')

    # 7. 关键篡改 (内容/结构类) 必须被检出; 尾部截断为已知盲点不强制要求
    critical_modes = {'value_modification', 'hash_forgery',
                      'event_deletion', 'event_reorder'}
    critical_detected = {r['tamper_mode'] for r in results if r['detected']}
    missing = critical_modes - critical_detected
    assert not missing, f'关键篡改未被检出: {missing}'
    print('\n[OK] 所有内容/结构类篡改均被检测出, 哈希链具备防篡改能力。')
    print('     (尾部截断为哈希链固有盲点, 已在结果中标注)')
    print('=' * 70)
    return summary


if __name__ == '__main__':
    run_experiment()
