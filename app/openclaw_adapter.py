"""
Agent Gateway - OpenClaw适配器
Agent无需修改代码, 只需将工具调用URL指向网关
"""
import os, json, requests, time
from typing import Optional, Dict, Any, List


class OpenClawGatewayClient:
    """
    OpenClaw Agent 网关客户端
    Agent通过此客户端调用工具, 所有调用自动经过网关验证
    """

    def __init__(self, gateway_url: str = "http://localhost:8400"):
        self.gateway_url = gateway_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    # --- 工具注册 ---

    def register_tool(self, tool_id: str, name: str, endpoint: str,
                      code_hash: str = None) -> dict:
        """注册工具 (通常由治理委员会调用)"""
        payload = {"tool_id": tool_id, "name": name, "endpoint": endpoint}
        if code_hash:
            payload["code_hash"] = code_hash
        resp = self.session.post(f"{self.gateway_url}/v1/tools/register", json=payload)
        resp.raise_for_status()
        return resp.json()

    def finalize_registration(self) -> dict:
        """完成注册, 构建Merkle树"""
        resp = self.session.post(f"{self.gateway_url}/v1/tools/finalize")
        resp.raise_for_status()
        return resp.json()

    def list_tools(self) -> List[dict]:
        resp = self.session.get(f"{self.gateway_url}/v1/tools")
        resp.raise_for_status()
        return resp.json().get("tools", [])

    # --- 工具调用 ---

    def call_tool(self, tool_id: str, input_data: str, forward: bool = True) -> dict:
        """
        通过网关调用工具
        网关自动执行: Merkle验证 + Pedersen承诺 + Nullifier + BLS聚合
        """
        payload = {"tool_id": tool_id, "input": input_data, "forward": forward}
        resp = self.session.post(f"{self.gateway_url}/v1/call", json=payload)
        if resp.status_code == 403:
            raise PermissionError(f"Tool '{tool_id}' verification failed: {resp.json()}")
        if resp.status_code == 404:
            raise ValueError(f"Tool '{tool_id}' not registered")
        resp.raise_for_status()
        return resp.json()

    # --- 批次提交 ---

    def submit_batch(self) -> dict:
        """提交当前调用批次, 自动选择ECDSA/BLS模式并应用ORP"""
        resp = self.session.post(f"{self.gateway_url}/v1/batch/submit")
        resp.raise_for_status()
        return resp.json()

    # --- 验证查询 ---

    def verify_merkle(self, tool_id: str) -> dict:
        resp = self.session.get(f"{self.gateway_url}/v1/verify/merkle/{tool_id}")
        resp.raise_for_status()
        return resp.json()

    def check_nullifier(self, nullifier_hex: str) -> dict:
        resp = self.session.get(f"{self.gateway_url}/v1/verify/nullifier/{nullifier_hex}")
        resp.raise_for_status()
        return resp.json()

    # --- 状态 ---

    def get_stats(self) -> dict:
        resp = self.session.get(f"{self.gateway_url}/v1/stats")
        resp.raise_for_status()
        return resp.json()

    def get_audit_log(self, limit: int = 50) -> List[dict]:
        resp = self.session.get(f"{self.gateway_url}/v1/audit?limit={limit}")
        resp.raise_for_status()
        return resp.json().get("logs", [])

    # --- 便捷方法: 模拟OpenClaw工具链 ---

    def call_chain(self, tool_calls: List[tuple]) -> List[dict]:
        """
        批量调用工具链
        tool_calls: [(tool_id, input_data), ...]
        """
        results = []
        for tool_id, input_data in tool_calls:
            result = self.call_tool(tool_id, input_data)
            results.append(result)
            print(f"  [Gateway] {tool_id} -> nullifier={result['nullifier'][:16]}..., "
                  f"pending={result['pending_batch_size']}")
        return results

    def submit_and_report(self) -> dict:
        """提交批次并打印报告"""
        batch = self.submit_batch()
        print(f"\n  [Batch] ID={batch['batch_id']}")
        print(f"          Size={batch['batch_size']}, Mode={batch['mode']}")
        print(f"          Merkle Root={batch['merkle_root'][:16]}...")
        print(f"          ORP applied: sequence shuffled")
        return batch
