"""
Agent Gateway - 核心引擎
管理工具注册表、调用验证、签名聚合、状态持久化
"""
import hashlib, secrets, time, threading, json, os
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict

from .crypto import (
    MerkleTree, PedersenCommitment, BLSSigner, ORP,
    compute_nullifier, ToolRegistration, CallRecord,
    VerifyMode, SWITCH_THRESHOLD
)


class GatewayEngine:
    """网关核心引擎: 所有状态和验证逻辑的中心"""

    def __init__(self):
        # 工具注册表
        self.tools: Dict[str, ToolRegistration] = {}
        # Merkle树
        self.tree = MerkleTree()
        # Nullifier防重放集合
        self.nullifiers: set = set()
        # BLS签名器 (模拟治理委员会)
        self._bls_signer = BLSSigner()
        # Pedersen承诺参数
        self._pedersen = PedersenCommitment
        # 当前批次的调用记录
        self._records: List[CallRecord] = []
        self._agg_sig = None
        self._agg_pk = None
        self._tool_ids: List[str] = []
        # 线程安全锁
        self._lock = threading.RLock()
        # 调用历史 (审计日志)
        self._audit_log: List[dict] = []
        # 状态持久化
        self._state_file = None
        self._bls_available = self._bls_signer.available

    # ============================================================
    # 工具注册
    # ============================================================

    def register_tool(self, tool_id: str, name: str, endpoint: str,
                      code_hash: bytes = None) -> ToolRegistration:
        """注册工具到网关"""
        with self._lock:
            if tool_id in self.tools:
                raise ValueError(f"Tool '{tool_id}' already registered")

            if code_hash is None:
                code_hash = hashlib.sha256(f"{tool_id}:{endpoint}".encode()).digest()

            leaf_data = tool_id.encode() + code_hash
            sig = self._bls_signer.sign(leaf_data) if self._bls_available else None
            pk = self._bls_signer.public_key if self._bls_available else None

            reg = ToolRegistration(
                tool_id=tool_id,
                name=name,
                endpoint=endpoint,
                code_hash=code_hash,
                bls_sig=sig,
                bls_pk=pk,
                leaf_hash=self.tree._hash_leaf(leaf_data),
                merkle_index=self.tree.add_leaf(leaf_data),
                enabled=True
            )
            self.tools[tool_id] = reg
            return reg

    def finalize_registration(self) -> bytes:
        """构建Merkle树, 返回Root"""
        with self._lock:
            root = self.tree.build()
            for tid, reg in self.tools.items():
                for i, leaf in enumerate(self.tree.leaves):
                    if leaf == tid.encode() + reg.code_hash:
                        reg.merkle_index = i
                        break
            return root

    def list_tools(self) -> List[dict]:
        """列出所有已注册工具"""
        with self._lock:
            return [
                {
                    'tool_id': r.tool_id,
                    'name': r.name,
                    'endpoint': r.endpoint,
                    'enabled': r.enabled,
                    'merkle_index': r.merkle_index,
                    'leaf_hash': r.leaf_hash.hex()[:16] + '...',
                }
                for r in self.tools.values()
            ]

    def enable_tool(self, tool_id: str, enabled: bool):
        with self._lock:
            if tool_id not in self.tools:
                raise ValueError(f"Tool '{tool_id}' not found")
            self.tools[tool_id].enabled = enabled

    # ============================================================
    # 工具调用验证 (核心拦截逻辑)
    # ============================================================

    # 默认全部开启的消融开关
    DEFAULT_SWITCHES = {
        'merkle': True, 'pedersen': True,
        'nullifier': True, 'bls': True, 'orp': True,
    }

    def verify_and_record(self, tool_id: str, input_data: bytes,
                          switches: dict = None) -> CallRecord:
        """
        验证工具调用并记录 (支持消融开关)
        Agent每次调用工具时, 网关执行:
        1. 检查工具是否已注册且启用
        2. 验证工具的Merkle存在性 (switch: merkle)
        3. 生成Pedersen承诺隐藏输入参数 (switch: pedersen)
        4. 生成Nullifier防重放 (switch: nullifier)
        5. 增量聚合BLS签名 (switch: bls)

        switches: dict, 可选键:
            'merkle': bool - Merkle存在性验证
            'pedersen': bool - Pedersen承诺
            'nullifier': bool - Nullifier防重放
            'bls': bool - BLS签名聚合
            'orp': bool - ORP序列混淆 (仅影响submit_batch)
        """
        sw = {**self.DEFAULT_SWITCHES, **(switches or {})}

        with self._lock:
            # 1. 检查工具注册状态 (始终执行)
            if tool_id not in self.tools:
                raise ValueError(f"Tool '{tool_id}' not registered")
            reg = self.tools[tool_id]
            if not reg.enabled:
                raise PermissionError(f"Tool '{tool_id}' is disabled")

            # 2. Merkle存在性验证 (可关闭)
            if sw['merkle']:
                if not self._verify_merkle(reg):
                    raise PermissionError(f"Tool '{tool_id}' Merkle verification failed")

            # 3. Pedersen承诺 (可关闭)
            if sw['pedersen']:
                commit_val, m, r = self._pedersen.commit_bytes(input_data)
            else:
                commit_val, m, r = 0, 0, 0

            # 4. Nullifier防重放 (可关闭)
            if sw['nullifier']:
                nonce = secrets.token_bytes(16)
                result_hash = hashlib.sha256(input_data + nonce).digest()
                nullifier = compute_nullifier(tool_id, nonce)
                if nullifier in self.nullifiers:
                    raise ValueError(f"Nullifier collision, retry needed")
                self.nullifiers.add(nullifier)
            else:
                nonce = secrets.token_bytes(16)
                result_hash = hashlib.sha256(input_data + nonce).digest()
                nullifier = b'\x00' * 32

            # 5. BLS增量聚合 (可关闭)
            if sw['bls'] and reg.bls_sig is not None and self._bls_available:
                if self._agg_sig is None:
                    self._agg_sig = reg.bls_sig
                    self._agg_pk = reg.bls_pk
                else:
                    self._agg_sig = BLSSigner.incremental_aggregate(self._agg_sig, reg.bls_sig)
                    self._agg_pk = BLSSigner.incremental_aggregate_pk(self._agg_pk, reg.bls_pk)

            # 6. 创建调用记录
            record = CallRecord(
                tool_id=tool_id,
                input_commit=commit_val,
                input_blinding=r,
                input_hash=hashlib.sha256(input_data).digest(),
                result_hash=result_hash,
                nullifier=nullifier,
                timestamp=time.time(),
                status="verified"
            )
            self._records.append(record)
            self._tool_ids.append(tool_id)

            # 审计日志
            self._audit_log.append({
                'action': 'call_verified',
                'tool_id': tool_id,
                'nullifier': nullifier.hex()[:16] + '...',
                'timestamp': record.timestamp,
                'commit': str(commit_val)[:16] + '...',
            })

            return record

    def _verify_merkle(self, reg: ToolRegistration) -> bool:
        """验证工具的Merkle存在性"""
        if reg.merkle_index < 0 or reg.merkle_index >= self.tree.num_leaves:
            return False
        proof, is_right = self.tree.get_proof(reg.merkle_index)
        return MerkleTree.verify_proof(reg.leaf_hash, proof, is_right, self.tree.root)

    # ============================================================
    # 批次提交
    # ============================================================

    def submit_batch(self, switches: dict = None) -> dict:
        """提交当前调用批次, 自动选择验证模式 (支持ORP消融)"""
        sw = {**self.DEFAULT_SWITCHES, **(switches or {})}
        with self._lock:
            n = len(self._records)
            if n == 0:
                raise ValueError("No calls to submit")

            mode = VerifyMode.BLS_AGG if n >= SWITCH_THRESHOLD else VerifyMode.ECDSA

            # ORP混淆调用序列 (可关闭)
            if sw['orp']:
                perm = ORP.random_permutation(n)
                shuffled_records = ORP.apply(self._records, perm)
                shuffled_tool_ids = [self._tool_ids[perm[i]] for i in range(n)]
            else:
                perm = list(range(n))
                shuffled_records = self._records[:]
                shuffled_tool_ids = self._tool_ids[:]

            batch = {
                'batch_id': secrets.token_hex(8),
                'records': [self._record_to_dict(r) for r in shuffled_records],
                'tool_ids': shuffled_tool_ids,
                'agg_sig': 'available' if self._agg_sig is not None else 'none',
                'merkle_root': self.tree.root.hex(),
                'mode': mode.value,
                'batch_size': n,
                'timestamp': time.time(),
                'orp_permutation': perm,
            }

            # 审计日志
            self._audit_log.append({
                'action': 'batch_submitted',
                'batch_id': batch['batch_id'],
                'size': n,
                'mode': mode.value,
                'timestamp': batch['timestamp'],
            })

            # 重置批次
            self._records = []
            self._tool_ids = []
            self._agg_sig = None
            self._agg_pk = None

            return batch

    def _record_to_dict(self, r: CallRecord) -> dict:
        return {
            'tool_id': r.tool_id,
            'input_commit': str(r.input_commit),
            'input_hash': r.input_hash.hex(),
            'result_hash': r.result_hash.hex(),
            'nullifier': r.nullifier.hex(),
            'timestamp': r.timestamp,
            'status': r.status,
        }

    # ============================================================
    # 查询和审计
    # ============================================================

    def verify_pedersen(self, record: CallRecord, original_input: bytes) -> bool:
        """验证Pedersen承诺 (争议仲裁)"""
        m = int.from_bytes(original_input, 'big') % self._pedersen.P
        return self._pedersen.verify(record.input_commit, m, record.input_blinding)

    def check_nullifier(self, nullifier: bytes) -> bool:
        """检查Nullifier是否已使用"""
        return nullifier in self.nullifiers

    def get_merkle_root(self) -> str:
        return self.tree.root.hex()

    def get_audit_log(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return self._audit_log[-limit:]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'registered_tools': len(self.tools),
                'total_nullifiers': len(self.nullifiers),
                'pending_records': len(self._records),
                'merkle_root': self.tree.root.hex()[:16] + '...',
                'merkle_leaves': self.tree.num_leaves,
                'bls_available': self._bls_available,
                'audit_log_entries': len(self._audit_log),
            }

    def get_pending_batch_size(self) -> int:
        with self._lock:
            return len(self._records)

    # ============================================================
    # 持久化
    # ============================================================

    def set_state_file(self, path: str):
        self._state_file = path

    def save_state(self):
        if self._state_file is None:
            return
        with self._lock:
            state = {
                'tools': {
                    tid: {
                        'tool_id': r.tool_id,
                        'name': r.name,
                        'endpoint': r.endpoint,
                        'code_hash': r.code_hash.hex(),
                        'enabled': r.enabled,
                        'merkle_index': r.merkle_index,
                    }
                    for tid, r in self.tools.items()
                },
                'merkle_leaves': [l.hex() for l in self.tree.leaves],
                'nullifiers': [n.hex() if isinstance(n, bytes) else str(n) for n in self.nullifiers],
                'audit_log': self._audit_log[-1000:],
            }
            with open(self._state_file, 'w') as f:
                json.dump(state, f, indent=2)

    def load_state(self):
        if self._state_file is None or not os.path.exists(self._state_file):
            return
        with self._lock:
            with open(self._state_file, 'r') as f:
                state = json.load(f)
            for tid, t in state.get('tools', {}).items():
                self.tools[tid] = ToolRegistration(
                    tool_id=t['tool_id'],
                    name=t['name'],
                    endpoint=t['endpoint'],
                    code_hash=bytes.fromhex(t['code_hash']),
                    enabled=t.get('enabled', True),
                    merkle_index=t.get('merkle_index', -1),
                )
            for leaf_hex in state.get('merkle_leaves', []):
                self.tree.add_leaf(bytes.fromhex(leaf_hex))
            self.tree.build()
            self.nullifiers = set(
                bytes.fromhex(n) if isinstance(n, str) else n
                for n in state.get('nullifiers', [])
            )
            self._audit_log = state.get('audit_log', [])
