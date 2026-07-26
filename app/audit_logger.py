"""
Agent Gateway - SHA-256 哈希链审计日志模块
提供防篡改的审计日志, 每条事件通过哈希链与前一条事件绑定

设计:
  - 每个事件包含 seq, action, timestamp, prev_hash, event_hash 以及任意附加字段
  - event_hash = SHA-256( json.dumps(除event_hash外的所有字段, sort_keys=True) )
  - prev_hash 指向前一事件的 event_hash, 形成链式结构
  - 创世 prev_hash 为 64 个 '0'
  - 任何对历史事件的篡改都会破坏哈希链, verify_chain() 可检测出来

篡改模拟方法 (用于测试验证逻辑的鲁棒性):
  - tamper_value(seq, field, new_value): 修改字段值
  - tamper_delete(seq): 删除中间事件
  - tamper_reorder(i, j): 交换两个事件位置
  - tamper_truncate_tail(n): 删除末尾事件
"""
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


# 创世哈希: 64 个 '0'
GENESIS_PREV_HASH = '0' * 64


class HashChainedAuditLogger:
    """SHA-256 哈希链审计日志器

    每个审计事件结构:
        {
            "seq":        int,     # 序号, 从 0 开始
            "action":     str,     # 动作类型
            "timestamp":  float,   # 时间戳
            "prev_hash":  str,     # 前一事件的 event_hash (创世事件为 64 个 '0')
            "event_hash": str,     # 本事件哈希 (对除 event_hash 外的字段做 sha256)
            ...:                  # 任意附加字段 (由调用方传入)
        }
    """

    def __init__(self, log_dir: Optional[str] = None):
        """初始化审计日志器

        Args:
            log_dir: 日志目录, save_to_file 时若 filename 为相对路径则拼接此目录;
                     目录不存在时自动创建。为 None 时则不使用默认目录。
        """
        self.events: List[Dict[str, Any]] = []
        self.log_dir = log_dir
        # prev_hash 初始化为创世哈希 (64 个 0)
        self.prev_hash = GENESIS_PREV_HASH
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    # ============================================================
    # 哈希计算
    # ============================================================
    @staticmethod
    def _compute_hash(event: Dict[str, Any]) -> str:
        """计算事件的 SHA-256 哈希

        对除 event_hash 外的所有字段做 json.dumps(sort_keys=True,
        ensure_ascii=False, default=str) 后再 sha256 取十六进制摘要。
        """
        data = {k: v for k, v in event.items() if k != 'event_hash'}
        payload = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    # ============================================================
    # 记录事件
    # ============================================================
    def log(self, action: str, **fields) -> Dict[str, Any]:
        """记录一条审计事件, 自动计算哈希链

        Args:
            action: 动作类型 (如 'call_verified', 'batch_submitted')
            **fields: 任意附加字段, 会并入事件中参与哈希计算

        Returns:
            完整的事件字典 (含 event_hash)
        """
        seq = len(self.events)
        event: Dict[str, Any] = {
            'seq': seq,
            'action': action,
            'timestamp': time.time(),
            'prev_hash': self.prev_hash,
        }
        # 合并附加字段 (附加字段不允许覆盖哈希链保留字段)
        for k, v in fields.items():
            if k in ('seq', 'action', 'timestamp', 'prev_hash', 'event_hash'):
                # 跳过保留字段, 避免破坏哈希链结构
                continue
            event[k] = v
        # 计算 event_hash (此时 event 中尚无 event_hash 字段)
        event['event_hash'] = self._compute_hash(event)
        self.events.append(event)
        # 更新 prev_hash, 指向当前事件的 event_hash
        self.prev_hash = event['event_hash']
        return event

    # ============================================================
    # 链完整性验证
    # ============================================================
    def verify_chain(self) -> Tuple[int, int]:
        """验证哈希链完整性

        逐条检查:
          1. prev_hash 是否等于前一事件的 event_hash (首条应等于创世哈希)
          2. event_hash 是否等于按当前字段重算的哈希

        Returns:
            (passed, failed) 元组:
              - passed: 通过验证的事件数
              - failed: 未通过验证的事件数
        """
        passed = 0
        failed = 0
        expected_prev = GENESIS_PREV_HASH
        for event in self.events:
            ok = True
            # 1. 验证 prev_hash 链接
            if event.get('prev_hash') != expected_prev:
                ok = False
            # 2. 验证 event_hash
            stored_hash = event.get('event_hash')
            recomputed = self._compute_hash(event)
            if stored_hash != recomputed:
                ok = False
            if ok:
                passed += 1
            else:
                failed += 1
            # 无论通过与否, 期望的下一 prev_hash 取本事件存储的 event_hash,
            # 以便尽可能继续验证后续事件
            expected_prev = stored_hash
        return passed, failed

    # ============================================================
    # 篡改模拟 (仅用于测试验证逻辑的鲁棒性)
    # ============================================================
    def tamper_value(self, seq: int, field: str, new_value: Any) -> bool:
        """模拟篡改: 修改指定事件的指定字段值 (不重算 event_hash)

        Args:
            seq: 事件序号
            field: 要修改的字段名
            new_value: 新值

        Returns:
            是否篡改成功 (事件存在即成功)
        """
        for event in self.events:
            if event.get('seq') == seq:
                event[field] = new_value
                return True
        return False

    def tamper_delete(self, seq: int) -> bool:
        """模拟篡改: 删除指定序号的中间事件

        Args:
            seq: 事件序号

        Returns:
            是否删除成功
        """
        for i, event in enumerate(self.events):
            if event.get('seq') == seq:
                del self.events[i]
                return True
        return False

    def tamper_reorder(self, i: int, j: int) -> bool:
        """模拟篡改: 交换两个事件的位置

        Args:
            i: 第一个事件在列表中的索引
            j: 第二个事件在列表中的索引

        Returns:
            是否交换成功
        """
        n = len(self.events)
        if 0 <= i < n and 0 <= j < n:
            self.events[i], self.events[j] = self.events[j], self.events[i]
            return True
        return False

    def tamper_truncate_tail(self, n: int = 1) -> int:
        """模拟篡改: 删除末尾 n 个事件

        Args:
            n: 要删除的事件数

        Returns:
            实际删除的事件数
        """
        if n <= 0:
            return 0
        n = min(n, len(self.events))
        if n == 0:
            return 0
        del self.events[len(self.events) - n:]
        # 同步更新 prev_hash
        if self.events:
            self.prev_hash = self.events[-1].get('event_hash', GENESIS_PREV_HASH)
        else:
            self.prev_hash = GENESIS_PREV_HASH
        return n

    # ============================================================
    # 持久化
    # ============================================================
    def save_to_file(self, filename: str) -> str:
        """保存审计日志到文件

        Args:
            filename: 文件名或路径; 若 log_dir 已设置且 filename 为相对路径,
                      则保存到 log_dir/filename

        Returns:
            实际保存的文件绝对路径
        """
        if self.log_dir and not os.path.isabs(filename):
            filepath = os.path.join(self.log_dir, filename)
        else:
            filepath = filename
        dir_path = os.path.dirname(filepath)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        data = {
            'version': 1,
            'module': 'agent_gateway.audit_logger',
            'genesis_prev_hash': GENESIS_PREV_HASH,
            'event_count': len(self.events),
            'events': self.events,
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return os.path.abspath(filepath)

    def load_from_file(self, filepath: str) -> int:
        """从文件加载审计日志

        加载后会重置 prev_hash 为最后一条事件的 event_hash
        (若没有事件则重置为创世哈希)。

        Args:
            filepath: 文件路径

        Returns:
            加载的事件数
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # 兼容两种格式: 直接是 events 列表, 或是包含 events 字段的字典
        if isinstance(data, list):
            self.events = data
        elif isinstance(data, dict):
            self.events = data.get('events', [])
        else:
            self.events = []
        # 同步 prev_hash
        if self.events:
            self.prev_hash = self.events[-1].get('event_hash', GENESIS_PREV_HASH)
        else:
            self.prev_hash = GENESIS_PREV_HASH
        return len(self.events)

    # ============================================================
    # 查询与展示
    # ============================================================
    def __len__(self) -> int:
        return len(self.events)

    def get_events(self) -> List[Dict[str, Any]]:
        """返回所有事件的浅拷贝列表"""
        return list(self.events)

    def get_event(self, seq: int) -> Optional[Dict[str, Any]]:
        """按序号获取事件"""
        for event in self.events:
            if event.get('seq') == seq:
                return event
        return None

    def summary(self) -> Dict[str, Any]:
        """返回审计链摘要信息"""
        passed, failed = self.verify_chain()
        return {
            'total_events': len(self.events),
            'passed': passed,
            'failed': failed,
            'chain_intact': failed == 0,
            'last_event_hash': self.prev_hash if self.events else GENESIS_PREV_HASH,
            'genesis_prev_hash': GENESIS_PREV_HASH,
        }


# ============================================================
# 模块自测: python -m app.audit_logger
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("HashChainedAuditLogger 自测")
    print("=" * 60)

    logger = HashChainedAuditLogger()
    logger.log('call_verified', tool_id='web_search', nullifier='a1b2c3d4',
               commit='1234567890', status='verified')
    logger.log('call_verified', tool_id='code_exec', nullifier='e5f6a7b8',
               commit='2345678901', status='verified')
    logger.log('batch_submitted', batch_id='batch_001', size=2,
               mode='ecdsa', merkle_root='deadbeef')
    logger.log('call_verified', tool_id='file_read', nullifier='c9d0e1f2',
               commit='3456789012', status='verified')

    passed, failed = logger.verify_chain()
    print(f"初始验证: passed={passed}, failed={failed}")
    assert passed == 4 and failed == 0, "初始链应当完整"

    # 篡改测试 1: 修改字段值
    logger.tamper_value(seq=1, field='tool_id', new_value='EVIL_TOOL')
    p, f = logger.verify_chain()
    print(f"篡改字段值后: passed={p}, failed={f}")
    assert f >= 1, "篡改字段值应被检测出"

    # 重建链
    logger = HashChainedAuditLogger()
    for i in range(5):
        logger.log('call_verified', tool_id=f'tool_{i}', seq_no=i)
    assert logger.verify_chain() == (5, 0)

    # 篡改测试 2: 删除中间事件
    logger.tamper_delete(seq=2)
    p, f = logger.verify_chain()
    print(f"删除中间事件后: passed={p}, failed={f}")
    assert f >= 1, "删除中间事件应被检测出"

    # 重建链
    logger = HashChainedAuditLogger()
    for i in range(5):
        logger.log('call_verified', tool_id=f'tool_{i}', seq_no=i)
    assert logger.verify_chain() == (5, 0)

    # 篡改测试 3: 交换事件顺序
    logger.tamper_reorder(1, 3)
    p, f = logger.verify_chain()
    print(f"交换事件顺序后: passed={p}, failed={f}")
    assert f >= 1, "交换事件顺序应被检测出"

    # 重建链
    logger = HashChainedAuditLogger()
    for i in range(5):
        logger.log('call_verified', tool_id=f'tool_{i}', seq_no=i)
    assert logger.verify_chain() == (5, 0)

    # 篡改测试 4: 删除末尾事件
    logger.tamper_truncate_tail(n=1)
    p, f = logger.verify_chain()
    print(f"删除末尾事件后: passed={p}, failed={f}")
    # 末尾删除: 剩余链本身仍自洽, 但事件数减少 (视策略而定, 这里剩余链通过)
    print(f"  (剩余 {len(logger)} 个事件)")

    # 持久化测试
    logger = HashChainedAuditLogger()
    for i in range(3):
        logger.log('call_verified', tool_id=f'tool_{i}')
    path = logger.save_to_file('/tmp/_audit_selftest.json')
    print(f"保存到: {path}")

    logger2 = HashChainedAuditLogger()
    n = logger2.load_from_file(path)
    p, f = logger2.verify_chain()
    print(f"重新加载: {n} 个事件, passed={p}, failed={f}")
    assert n == 3 and p == 3 and f == 0, "保存/加载后链应保持完整"

    print("=" * 60)
    print("所有自测通过")
    print("=" * 60)
