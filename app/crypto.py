"""
Agent Gateway - 密码学核心模块
从V3协议移植, 提供Merkle树、Pedersen承诺、BLS签名、Nullifier
"""
import hashlib, secrets, time, threading
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


# ============================================================
# Merkle Tree
# ============================================================
class MerkleTree:
    def __init__(self):
        self.leaves: List[bytes] = []
        self.root: bytes = b'\x00' * 32
        self._built = False
        self._layers: List[List[bytes]] = []

    @staticmethod
    def _hash_leaf(data: bytes) -> bytes:
        return hashlib.sha256(b'\x00' + data).digest()

    @staticmethod
    def _hash_node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b'\x01' + left + right).digest()

    def add_leaf(self, data: bytes) -> int:
        self.leaves.append(data)
        self._built = False
        return len(self.leaves) - 1

    def build(self) -> bytes:
        current = [self._hash_leaf(l) for l in self.leaves]
        self._layers = [current[:]]
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                nxt.append(self._hash_node(left, right))
            self._layers.append(nxt)
            current = nxt
        self.root = current[0] if current else b'\x00' * 32
        self._built = True
        return self.root

    def get_proof(self, index: int) -> Tuple[List[bytes], List[bool]]:
        if not self._built:
            self.build()
        proof, is_right = [], []
        idx = index
        for layer in self._layers[:-1]:
            if idx % 2 == 0:
                sibling = layer[idx + 1] if idx + 1 < len(layer) else layer[idx]
                is_right.append(True)
            else:
                sibling = layer[idx - 1]
                is_right.append(False)
            proof.append(sibling)
            idx = idx // 2
        return proof, is_right

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: List[bytes], is_right: List[bool], root: bytes) -> bool:
        current = leaf_hash
        for i, sibling in enumerate(proof):
            if is_right[i]:
                current = MerkleTree._hash_node(current, sibling)
            else:
                current = MerkleTree._hash_node(sibling, current)
        return current == root

    @property
    def num_leaves(self) -> int:
        return len(self.leaves)


# ============================================================
# Pedersen Commitment
# ============================================================
class PedersenCommitment:
    P = 2**254 + 456604809
    G = 7
    H = 11

    @classmethod
    def commit(cls, message: int, blinding: int = None) -> Tuple[int, int]:
        if blinding is None:
            blinding = secrets.randbelow(cls.P)
        commitment = (message * cls.G + blinding * cls.H) % cls.P
        return commitment, blinding

    @classmethod
    def verify(cls, commitment: int, message: int, blinding: int) -> bool:
        expected = (message * cls.G + blinding * cls.H) % cls.P
        return commitment == expected

    @classmethod
    def commit_bytes(cls, data: bytes) -> Tuple[int, int, int]:
        m = int.from_bytes(data, 'big') % cls.P
        c, r = cls.commit(m)
        return c, m, r


# ============================================================
# BLS Signer
# ============================================================
class BLSSigner:
    def __init__(self):
        try:
            from blspy import AugSchemeMPL
            self._mpl = AugSchemeMPL
            self._sk = AugSchemeMPL.key_gen(secrets.token_bytes(32))
            self._pk = self._sk.get_g1()
            self._available = True
        except ImportError:
            self._available = False
            self._pk = None

    @property
    def available(self) -> bool:
        return self._available

    @property
    def public_key(self):
        return self._pk

    def sign(self, message: bytes):
        if not self._available:
            return None
        return self._mpl.sign(self._sk, message)

    @staticmethod
    def aggregate(sigs: list):
        try:
            from blspy import AugSchemeMPL
            return AugSchemeMPL.aggregate(sigs)
        except ImportError:
            return None

    @staticmethod
    def incremental_aggregate(agg_sig, new_sig):
        """增量聚合签名 (G2Element), 使用 + 运算符"""
        try:
            return agg_sig + new_sig
        except (TypeError, AttributeError):
            return None

    @staticmethod
    def incremental_aggregate_pk(agg_pk, new_pk):
        """增量聚合公钥 (G1Element), 使用 + 运算符"""
        try:
            return agg_pk + new_pk
        except (TypeError, AttributeError):
            return None

    @staticmethod
    def verify(pk, message: bytes, sig) -> bool:
        try:
            from blspy import AugSchemeMPL
            return AugSchemeMPL.verify(pk, message, sig)
        except ImportError:
            return False


# ============================================================
# Nullifier
# ============================================================
def compute_nullifier(tool_id: str, nonce: bytes) -> bytes:
    return hashlib.sha256(tool_id.encode() + nonce).digest()


# ============================================================
# Data Types
# ============================================================
class VerifyMode(Enum):
    ECDSA = "ecdsa"
    BLS_AGG = "bls_aggregate"

SWITCH_THRESHOLD = 33


@dataclass
class ToolRegistration:
    tool_id: str
    name: str
    endpoint: str          # 实际工具的HTTP地址
    code_hash: bytes
    bls_sig: Any = None
    bls_pk: Any = None
    leaf_hash: bytes = b''
    merkle_index: int = -1
    enabled: bool = True


@dataclass
class CallRecord:
    tool_id: str
    input_commit: int
    input_blinding: int
    input_hash: bytes
    result_hash: bytes
    nullifier: bytes
    timestamp: float = 0.0
    status: str = "pending"  # pending, forwarded, completed, failed
    response: Any = None
