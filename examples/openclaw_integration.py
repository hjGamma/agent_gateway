#!/usr/bin/env python3
"""
OpenClaw Agent 集成示例

本示例演示如何将已部署的 OpenClaw Agent 接入 Agent Gateway,
使所有工具调用必须经过网关验证后才能到达实际工具。

集成方式有两种:
  方式一 (推荐): 将 Agent 的工具调用 URL 指向网关, 网关自动转发
  方式二: 在 Agent 代码中嵌入 GatewayClient, 显式调用

本示例展示方式一的典型配置流程。
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from app.openclaw_adapter import OpenClawGatewayClient


# ============================================================
# 1. 治理委员会: 注册工具 (一次性操作)
# ============================================================

def register_tools(gateway_url: str):
    """
    将 OpenClaw 当前可用的工具注册到网关。
    每个工具需要提供:
      - tool_id: 工具唯一标识 (与 OpenClaw 中的 tool name 一致)
      - name:    工具人类可读名称
      - endpoint: 工具的实际 HTTP 后端地址
    """
    client = OpenClawGatewayClient(gateway_url)

    # 列出 OpenClaw 当前已部署的工具及其后端地址
    # 这里以常见的 OpenClaw 工具为例
    openclaw_tools = [
        {
            "tool_id": "web_search",
            "name": "Web搜索工具",
            "endpoint": "http://openclaw-backend:5001/tools/web_search",
        },
        {
            "tool_id": "code_interpreter",
            "name": "代码解释器",
            "endpoint": "http://openclaw-backend:5001/tools/code_interpreter",
        },
        {
            "tool_id": "file_manager",
            "name": "文件管理工具",
            "endpoint": "http://openclaw-backend:5001/tools/file_manager",
        },
        {
            "tool_id": "database_query",
            "name": "数据库查询工具",
            "endpoint": "http://openclaw-backend:5001/tools/database_query",
        },
        {
            "tool_id": "email_sender",
            "name": "邮件发送工具",
            "endpoint": "http://openclaw-backend:5001/tools/email_sender",
        },
    ]

    print("[治理委员会] 注册工具到网关...")
    for tool in openclaw_tools:
        try:
            result = client.register_tool(
                tool_id=tool["tool_id"],
                name=tool["name"],
                endpoint=tool["endpoint"],
            )
            print(f"  + {tool['tool_id']}: merkle_index={result['merkle_index']}")
        except Exception as e:
            if "already registered" in str(e):
                print(f"  ~ {tool['tool_id']}: already registered, skipping")
            else:
                print(f"  [ERROR] {tool['tool_id']}: {e}")

    # 构建 Merkle 树, 生成 Root
    finalize = client.finalize_registration()
    print(f"\n  Merkle Root: {finalize['merkle_root']}")
    print(f"  已注册工具数: {len(client.list_tools())}")
    print("  [完成] 工具注册阶段完成\n")


# ============================================================
# 2. Agent 运行时: 通过网关调用工具
# ============================================================

def agent_tool_chain_example(gateway_url: str):
    """
    模拟 OpenClaw Agent 执行一个典型的工具链:
      搜索信息 -> 分析数据 -> 发送结果

    每次工具调用都经过网关验证:
      - Merkle 存在性验证 (工具是否合法注册)
      - Pedersen 承诺 (隐藏输入参数)
      - Nullifier 生成 (防重放)
      - BLS 增量聚合 (签名验证)
    """
    client = OpenClawGatewayClient(gateway_url)

    print("[Agent] 执行工具链...\n")

    # Agent 决策: 先搜索
    print("  Step 1: 搜索相关信息")
    result1 = client.call_tool("web_search", "OpenClaw agent security best practices 2026")
    print(f"    -> 验证通过, nullifier={result1['nullifier'][:16]}...")
    print(f"    -> 工具返回: {result1.get('tool_response', {})}")
    print(f"    -> 待提交批次: {result1['pending_batch_size']}\n")

    # Agent 决策: 分析搜索结果
    print("  Step 2: 分析数据")
    result2 = client.call_tool("code_interpreter",
                                "analyze the security patterns from search results")
    print(f"    -> 验证通过, nullifier={result2['nullifier'][:16]}...")
    print(f"    -> 待提交批次: {result2['pending_batch_size']}\n")

    # Agent 决策: 发送分析结果
    print("  Step 3: 发送邮件通知")
    result3 = client.call_tool("email_sender",
                                "send security report to admin@company.com")
    print(f"    -> 验证通过, nullifier={result3['nullifier'][:16]}...")
    print(f"    -> 待提交批次: {result3['pending_batch_size']}\n")

    # 提交批次 (自动选择 ECDSA 或 BLS 模式)
    print("  Step 4: 提交调用批次")
    batch = client.submit_batch()
    print(f"    -> Batch ID: {batch['batch_id']}")
    print(f"    -> 批次大小: {batch['batch_size']}")
    print(f"    -> 验证模式: {batch['mode']}")
    print(f"    -> Merkle Root: {batch['merkle_root'][:32]}...")
    print("  [完成] 工具链执行完毕\n")


# ============================================================
# 3. 安全验证: 检查工具合法性
# ============================================================

def verify_tool_security(gateway_url: str):
    """
    验证工具的 Merkle 存在性, 确保工具未被篡改。
    可在 Agent 启动时调用, 也可定期审计。
    """
    client = OpenClawGatewayClient(gateway_url)

    print("[安全审计] 验证工具合法性...")
    tools = client.list_tools()
    for tool in tools:
        result = client.verify_merkle(tool["tool_id"])
        status = "OK" if result["exists"] else "FAIL"
        print(f"  {tool['tool_id']:25s} -> {status}")

    # 检查审计日志
    print("\n  最近审计日志:")
    logs = client.get_audit_log(limit=10)
    for log in logs:
        target = log.get("tool_id", log.get("batch_id", "-"))
        print(f"    {log['action']:20s} | {target}")
    print()


# ============================================================
# 4. OpenClaw 配置文件示例
# ============================================================

OPENCLAW_CONFIG_EXAMPLE = """
# ============================================================
# OpenClaw 配置文件片段: 接入 Agent Gateway
# ============================================================

# 将 Agent 的工具调用 base URL 从原来的直接地址:
#   tool_base_url: "http://openclaw-backend:5001/tools"
# 改为指向网关:
#   tool_base_url: "http://agent-gateway:8400/v1/call"

agent:
  name: "openclaw-agent"
  model: "gpt-4"
  
  # 工具调用配置: 所有工具调用经过网关
  tool_execution:
    # 方式一 (推荐): 通过网关转发
    # Agent 发送 POST 到网关, 网关验证后转发到实际工具
    gateway_url: "http://agent-gateway:8400"
    gateway_endpoint: "/v1/call"
    
    # 请求格式:
    # POST http://agent-gateway:8400/v1/call
    # {
    #   "tool_id": "web_search",
    #   "input": "搜索内容",
    #   "forward": true
    # }

  # 工具列表 (需与网关注册一致)
  tools:
    - id: "web_search"
      description: "搜索网络信息"
    - id: "code_interpreter"
      description: "执行代码"
    - id: "file_manager"
      description: "管理文件"
    - id: "database_query"
      description: "查询数据库"
    - id: "email_sender"
      description: "发送邮件"
"""


# ============================================================
# 主函数
# ============================================================

def main():
    gateway_url = os.environ.get("GATEWAY_URL", "http://localhost:8400")

    print("=" * 60)
    print("  OpenClaw Agent Gateway 集成示例")
    print("=" * 60)

    # Step 1: 检查网关健康
    print(f"\n网关地址: {gateway_url}")
    client = OpenClawGatewayClient(gateway_url)
    try:
        stats = client.get_stats()
        print(f"网关状态: 工具数={stats['registered_tools']}, "
              f"BLS={stats['bls_available']}")
    except Exception as e:
        print(f"[ERROR] 无法连接到网关: {e}")
        print("请先启动网关: cd agent_gateway && python -m uvicorn app.main:app --port 8400")
        sys.exit(1)

    # Step 2: 注册工具 (治理委员会操作)
    register_tools(gateway_url)

    # Step 3: Agent 执行工具链
    agent_tool_chain_example(gateway_url)

    # Step 4: 安全验证
    verify_tool_security(gateway_url)

    # Step 5: 打印 OpenClaw 配置示例
    print("=" * 60)
    print("  OpenClaw 配置文件参考")
    print("=" * 60)
    print(OPENCLAW_CONFIG_EXAMPLE)


if __name__ == "__main__":
    main()
