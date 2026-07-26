#!/usr/bin/env python3
"""
Agent Gateway - 端到端测试
完整流程: 注册工具 -> Agent调用 -> 网关验证 -> 转发 -> 批次提交
"""
import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from app.openclaw_adapter import OpenClawGatewayClient

def main():
    print("=" * 60)
    print("  Agent Gateway - 端到端测试")
    print("=" * 60)

    client = OpenClawGatewayClient("http://localhost:8400")

    # Step 0: 检查网关状态
    print("\n[Step 0] 检查网关状态")
    try:
        stats = client.get_stats()
        print(f"  Tools: {stats['registered_tools']}")
        print(f"  BLS available: {stats['bls_available']}")
    except Exception as e:
        print(f"  [ERROR] 网关未启动? {e}")
        print(f"  请先运行: cd agent_gateway && python -m uvicorn app.main:app --port 8400")
        sys.exit(1)

    # Step 1: 注册工具
    print("\n[Step 1] 注册工具到网关")
    tools = [
        ("web_search", "Web搜索工具", "http://localhost:9100/search"),
        ("data_analysis", "数据分析工具", "http://localhost:9100/analyze"),
        ("summarizer", "文本摘要工具", "http://localhost:9100/summarize"),
        ("code_executor", "代码执行工具", "http://localhost:9100/execute"),
    ]
    for tid, name, endpoint in tools:
        try:
            result = client.register_tool(tid, name, endpoint)
            print(f"  + {tid}: index={result['merkle_index']}")
        except Exception as e:
            if "already registered" in str(e):
                print(f"  ~ {tid}: already registered")
            else:
                print(f"  [ERROR] {tid}: {e}")

    # 完成注册
    finalize = client.finalize_registration()
    print(f"  Merkle Root: {finalize['merkle_root'][:32]}...")

    # Step 2: 验证工具Merkle存在性
    print("\n[Step 2] 验证工具Merkle存在性")
    for tid, _, _ in tools:
        result = client.verify_merkle(tid)
        print(f"  {tid}: {'EXISTS' if result['exists'] else 'NOT FOUND'}")

    # Step 3: Agent执行工具链 (模拟OpenClaw调用)
    print("\n[Step 3] Agent执行工具链 (经过网关验证)")
    chain = [
        ("web_search", "AI agent security vulnerabilities 2026"),
        ("data_analysis", "analyze vulnerability patterns in search results"),
        ("summarizer", "summarize the security analysis"),
    ]
    results = client.call_chain(chain)

    # Step 4: 检查pending批次
    print(f"\n[Step 4] 当前待提交批次: {results[-1]['pending_batch_size']} 条调用")

    # Step 5: 提交批次
    print("\n[Step 5] 提交批次")
    batch = client.submit_and_report()

    # Step 6: 查看审计日志
    print("\n[Step 6] 审计日志 (最近5条)")
    logs = client.get_audit_log(limit=5)
    for log in logs:
        print(f"  {log['action']:20s} | {log.get('tool_id', log.get('batch_id', '-'))}")

    # Step 7: 大批量调用测试
    print("\n[Step 7] 大批量调用 (n=35, 触发BLS模式)")
    big_chain = [("web_search", f"batch_query_{i}") for i in range(35)]
    for tid, inp in big_chain:
        client.call_tool(tid, inp, forward=False)  # 不转发, 仅验证
    batch = client.submit_and_report()

    # Step 8: 最终状态
    print("\n[Step 8] 最终状态")
    stats = client.get_stats()
    print(f"  注册工具: {stats['registered_tools']}")
    print(f"  Nullifier总数: {stats['total_nullifiers']}")
    print(f"  审计日志: {stats['audit_log_entries']}条")

    print("\n" + "=" * 60)
    print("  端到端测试完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
