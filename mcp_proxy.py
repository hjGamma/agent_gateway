#!/usr/bin/env python3
"""
Agent Gateway MCP 代理服务器
=============================
桥接 OpenClaw MCP 协议与 Agent Gateway HTTP API。

工作流:
  OpenClaw Agent → MCP tool call → 本代理 → Agent Gateway /v1/call → 实际工具后端

部署步骤:
  1. 启动 Agent Gateway:
     python -m uvicorn app.main:app --host 0.0.0.0 --port 8400

  2. 注册工具到网关 (通过 /v1/tools/register API)

  3. 在 OpenClaw config.json 的 mcp.servers 中添加:
     "agent-gateway": {
       "command": "python3",
       "args": ["/home/ubuntu/agent_gateway/mcp_proxy.py"],
       "cwd": "/home/ubuntu/agent_gateway",
       "env": { "GATEWAY_URL": "http://localhost:8400" }
     }

  4. 重启 OpenClaw
"""
import os
import sys
import json
import requests

# MCP SDK
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("[ERROR] 请安装 MCP SDK: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ============================================================
# 配置
# ============================================================
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8400").rstrip("/")
GATEWAY_TIMEOUT = int(os.environ.get("GATEWAY_TIMEOUT", "30"))

mcp = FastMCP("agent-gateway")


# ============================================================
# 辅助函数
# ============================================================
def _gateway_get(path: str) -> dict:
    resp = requests.get(f"{GATEWAY_URL}{path}", timeout=GATEWAY_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _gateway_post(path: str, payload: dict) -> tuple:
    resp = requests.post(f"{GATEWAY_URL}{path}", json=payload, timeout=GATEWAY_TIMEOUT)
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    return resp.status_code, body


# ============================================================
# MCP 工具定义
# ============================================================

@mcp.tool()
def call_tool(tool_id: str, input: str) -> str:
    """通过 Agent Gateway 验证后调用工具 (核心接口)

    网关自动执行:
      1. Merkle 存在性验证 (工具是否合法注册)
      2. Pedersen 承诺 (隐藏输入参数)
      3. Nullifier 生成 (防重放)
      4. BLS 增量聚合签名
      5. 转发到实际工具后端

    Args:
        tool_id: 工具唯一标识 (需已在网关注册, 如 "web_search")
        input:   调用输入参数 (字符串)

    Returns:
        JSON 格式的验证结果, 包含 nullifier, input_commit, tool_response 等
    """
    status, body = _gateway_post("/v1/call", {
        "tool_id": tool_id,
        "input": input,
        "forward": True,
    })

    if status == 403:
        return json.dumps({
            "status": "blocked",
            "reason": "verification_failed",
            "detail": body,
        }, ensure_ascii=False, indent=2)

    if status == 404:
        return json.dumps({
            "status": "blocked",
            "reason": "tool_not_registered",
            "detail": body,
        }, ensure_ascii=False, indent=2)

    if status != 200:
        return json.dumps({
            "status": "error",
            "http_status": status,
            "detail": body,
        }, ensure_ascii=False, indent=2)

    return json.dumps(body, ensure_ascii=False, indent=2)


@mcp.tool()
def list_tools() -> str:
    """列出 Agent Gateway 中已注册的所有工具

    Returns:
        JSON 格式的工具列表, 每个工具包含 tool_id, name, endpoint, enabled 状态
    """
    tools = _gateway_get("/v1/tools").get("tools", [])
    return json.dumps(tools, ensure_ascii=False, indent=2)


@mcp.tool()
def register_tool(tool_id: str, name: str, endpoint: str) -> str:
    """注册工具到 Agent Gateway (治理委员会操作)

    Args:
        tool_id:  工具唯一标识 (如 "web_search")
        name:     工具人类可读名称
        endpoint: 工具的实际 HTTP 后端地址 (如 "http://localhost:5001/search")

    Returns:
        JSON 格式的注册结果, 包含 merkle_index
    """
    status, body = _gateway_post("/v1/tools/register", {
        "tool_id": tool_id,
        "name": name,
        "endpoint": endpoint,
    })
    return json.dumps({"http_status": status, "result": body},
                      ensure_ascii=False, indent=2)


@mcp.tool()
def finalize_registration() -> str:
    """完成工具注册, 构建 Merkle 树

    在所有工具注册完毕后调用, 网关将构建 Merkle 树并生成 Root。

    Returns:
        JSON 格式, 包含 merkle_root
    """
    status, body = _gateway_post("/v1/tools/finalize", {})
    return json.dumps({"http_status": status, "result": body},
                      ensure_ascii=False, indent=2)


@mcp.tool()
def submit_batch() -> str:
    """提交当前调用批次, 自动选择 ECDSA/BLS 验证模式

    在一轮工具链调用完毕后提交, 网关将:
      - n < 33: 使用 ECDSA 模式
      - n >= 33: 使用 BLS 聚合签名模式

    Returns:
        JSON 格式的批次信息, 包含 batch_id, mode, merkle_root, batch_size
    """
    status, body = _gateway_post("/v1/batch/submit", {})
    return json.dumps({"http_status": status, "result": body},
                      ensure_ascii=False, indent=2)


@mcp.tool()
def gateway_stats() -> str:
    """查看 Agent Gateway 的运行状态统计

    Returns:
        JSON 格式, 包含已注册工具数, nullifier 数, Merkle 信息, BLS 状态等
    """
    return json.dumps(_gateway_get("/v1/stats"), ensure_ascii=False, indent=2)


@mcp.tool()
def verify_merkle(tool_id: str) -> str:
    """验证工具的 Merkle 存在性

    确认工具是否在治理委员会注册的白名单中。

    Args:
        tool_id: 要验证的工具 ID

    Returns:
        JSON 格式, 包含 exists (true/false) 和 merkle_root
    """
    return json.dumps(_gateway_get(f"/v1/verify/merkle/{tool_id}"),
                      ensure_ascii=False, indent=2)


@mcp.tool()
def get_audit_log(limit: int = 20) -> str:
    """获取 Agent Gateway 的审计日志

    Args:
        limit: 返回最近 N 条日志 (默认 20)

    Returns:
        JSON 格式的审计日志列表
    """
    return json.dumps(_gateway_get(f"/v1/audit?limit={limit}"),
                      ensure_ascii=False, indent=2)


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    # 启动前检查网关连通性
    try:
        health = _gateway_get("/health")
        print(f"[gateway-proxy] 网关连接成功: {GATEWAY_URL}", file=sys.stderr)
        print(f"[gateway-proxy] 健康状态: {health.get('status', 'unknown')}", file=sys.stderr)
    except Exception as e:
        print(f"[gateway-proxy] 警告: 无法连接网关 ({e})", file=sys.stderr)
        print(f"[gateway-proxy] 请确认网关已启动: {GATEWAY_URL}", file=sys.stderr)

    mcp.run()
