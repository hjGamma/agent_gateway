#!/usr/bin/env python3
"""
端到端评估脚本 (OpenClaw 集成)
==============================
通过 HTTP 请求调用网关 API (http://localhost:8400), 评估网关对各类攻击的
拦截能力与对良性调用的通过率。

评估内容:
  - 4 种攻击类型 × 10 次:
      * forgery     : 调用未注册工具            -> 期望网关拒绝 (HTTP 4xx)
      * tampering   : 正常调用但用 Pedersen 承诺绑定输入 -> 承诺非平凡即视为已绑定
      * replay      : 重复调用同一 (tool, input) -> 期望 nullifier 冲突拒绝
      * linkability : 多次调用同一工具          -> 期望进入批次
  - 50 次良性调用: 正常工具调用, 期望全部通过 (HTTP 200)
  - 统计: 攻击拦截率, 良性通过率, 平均延迟
  - 保存到 results/e2e_results.json

使用 requests 库。若网关未启动, 提示先启动。
"""
import sys
import os
import json
import time

import requests

# 导入上级模块 (app 包), 仅用于读取配置参考, 非必需
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ============================================================
# 配置
# ============================================================
GATEWAY_URL = "http://localhost:8400"
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'e2e_results.json')

# 4 种攻击 × 10 次; 50 次良性
ATTACK_RUNS = 10
BENIGN_RUNS = 50

# 待注册的 3 个工具
TOOLS = [
    ("web_search", "Web搜索工具", "http://localhost:9100/search"),
    ("file_read",  "文件读取工具", "http://localhost:9100/read"),
    ("shell_exec", "Shell执行工具", "http://localhost:9100/exec"),
]
REGISTERED_TOOL_IDS = [t[0] for t in TOOLS]

ATTACK_TYPES = ["forgery", "tampering", "replay", "linkability"]


# ============================================================
# 网关连通性检查
# ============================================================
def check_gateway() -> bool:
    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ============================================================
# 工具注册
# ============================================================
def register_tools():
    """注册 3 个工具 (web_search, file_read, shell_exec) 并 finalize"""
    print("[register] 注册工具到网关 ...")
    for tid, name, endpoint in TOOLS:
        payload = {"tool_id": tid, "name": name, "endpoint": endpoint}
        try:
            r = requests.post(f"{GATEWAY_URL}/v1/tools/register",
                              json=payload, timeout=10)
            if r.status_code == 200:
                print(f"  + {tid}: registered")
            elif r.status_code == 409:
                print(f"  ~ {tid}: already registered")
            else:
                print(f"  [WARN] {tid}: {r.status_code} {r.text[:80]}")
        except Exception as e:
            print(f"  [ERROR] {tid}: {e}")

    # finalize 构建 Merkle 树
    try:
        r = requests.post(f"{GATEWAY_URL}/v1/tools/finalize", timeout=10)
        if r.status_code == 200:
            root = r.json().get("merkle_root", "")
            print(f"  finalize: merkle_root={root[:24]}...")
        else:
            print(f"  [WARN] finalize: {r.status_code}")
    except Exception as e:
        print(f"  [ERROR] finalize: {e}")


# ============================================================
# 基础调用
# ============================================================
def call_tool(tool_id, input_data, forward=False):
    """通过 POST /v1/call 调用工具, 返回 (status_code, response_json, latency_ms)"""
    payload = {"tool_id": tool_id, "input": input_data, "forward": forward}
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{GATEWAY_URL}/v1/call", json=payload, timeout=30)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text}
        return r.status_code, body, latency_ms
    except Exception as e:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return -1, {"error": str(e)}, latency_ms


# ============================================================
# 攻击场景
# ============================================================
def run_attack_scenario(attack_type, runs=ATTACK_RUNS):
    """执行指定类型的攻击场景

    Args:
        attack_type: forgery / tampering / replay / linkability
        runs: 重复次数

    Returns:
        该攻击类型的汇总 dict
    """
    results = []
    for i in range(runs):
        if attack_type == "forgery":
            # 调用未注册工具, 期望被拒绝 (HTTP 4xx)
            status, body, lat = call_tool(
                f"fake_tool_{i:03d}", f"malicious_query_{i}", forward=False)
            intercepted = (status != 200)
            detail = f"unregistered tool fake_tool_{i:03d}"

        elif attack_type == "tampering":
            # 正常调用注册工具但提交恶意输入, 网关用 Pedersen 承诺绑定输入
            # 承诺非平凡即视为输入已被绑定 (篡改可事后被检出)
            status, body, lat = call_tool(
                "file_read",
                "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
                forward=False)
            commit = str(body.get("input_commit", "")) if isinstance(body, dict) else ""
            intercepted = (status == 200 and commit not in ("", "0", "None"))
            detail = f"commit={commit[:16]}..."

        elif attack_type == "replay":
            # 先发一次, 再用相同 (tool, input) 重放, 期望 nullifier 冲突拒绝
            inp = f"replay_query_{i}"
            s1, b1, l1 = call_tool("web_search", inp, forward=False)
            s2, b2, l2 = call_tool("web_search", inp, forward=False)  # 重放
            status = s2
            body = b2
            lat = l1 + l2
            # 拦截: 重放调用被拒绝 (nullifier 冲突)
            intercepted = (s2 != 200)
            detail = f"orig={s1}, replay={s2}"

        elif attack_type == "linkability":
            # 多次调用同一工具, 期望进入批次 (调用被接受并批处理)
            inputs = [f"link_q_{i}_{j}" for j in range(4)]
            statuses = []
            lat_total = 0.0
            pending = 0
            for inp in inputs:
                s, b, l = call_tool("web_search", inp, forward=False)
                statuses.append(s)
                lat_total += l
                if isinstance(b, dict):
                    pending = b.get("pending_batch_size", pending)
            status = 200 if all(s == 200 for s in statuses) else statuses[-1]
            body = {"pending_batch_size": pending}
            lat = lat_total
            # 缓解: 调用被接受进入批次
            intercepted = all(s == 200 for s in statuses) and pending > 0
            detail = f"4 calls, pending={pending}"

        else:
            continue

        results.append({
            "run": i,
            "attack_type": attack_type,
            "http_status": status,
            "intercepted": intercepted,
            "latency_ms": round(lat, 3),
            "detail": detail,
        })

    intercepted_count = sum(1 for r in results if r["intercepted"])
    latencies = [r["latency_ms"] for r in results]
    summary = {
        "attack_type": attack_type,
        "runs": runs,
        "intercepted": intercepted_count,
        "interception_rate": round(intercepted_count / runs, 4) if runs else 0.0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "detail": results,
    }
    print(f"  [{attack_type:<12}] 拦截 {intercepted_count}/{runs} "
          f"({summary['interception_rate'] * 100:.0f}%), "
          f"avg_latency={summary['avg_latency_ms']:.2f}ms")
    return summary


# ============================================================
# 良性场景
# ============================================================
def run_benign_scenario(runs=BENIGN_RUNS):
    """正常工具调用, 期望全部通过 (HTTP 200)"""
    print("[benign] 执行良性调用 ...")
    results = []
    benign_inputs = [
        ("web_search", "today's weather forecast"),
        ("file_read",  "/workspace/data.txt"),
        ("shell_exec", "ls -la /tmp"),
        ("web_search", "python asyncio tutorial"),
        ("file_read",  "/etc/hostname"),
    ]
    passed = 0
    latencies = []
    for i in range(runs):
        tid, inp = benign_inputs[i % len(benign_inputs)]
        status, body, lat = call_tool(tid, f"{inp}_{i}", forward=False)
        ok = (status == 200)
        if ok:
            passed += 1
        latencies.append(lat)
        results.append({
            "run": i,
            "tool_id": tid,
            "http_status": status,
            "passed": ok,
            "latency_ms": round(lat, 3),
        })

    summary = {
        "runs": runs,
        "passed": passed,
        "pass_rate": round(passed / runs, 4) if runs else 0.0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "detail": results,
    }
    print(f"  良性通过 {passed}/{runs} ({summary['pass_rate'] * 100:.0f}%), "
          f"avg_latency={summary['avg_latency_ms']:.2f}ms")
    return summary


# ============================================================
# 主入口
# ============================================================
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("  端到端评估 (OpenClaw 集成, Gateway API)")
    print("=" * 70)

    # 0. 检查网关是否启动
    if not check_gateway():
        print(f"\n[ERROR] 网关未启动或不可达: {GATEWAY_URL}")
        print("请先启动网关, 例如:")
        print("  cd agent_gateway && python -m uvicorn app.main:app --port 8400")
        print("  或: cd agent_gateway && python -m app.main")
        sys.exit(1)
    print(f"[OK] 网关可达: {GATEWAY_URL}")

    # 1. 注册工具
    print("\n[1] 注册工具 ...")
    register_tools()

    # 2. 运行 4 种攻击 × ATTACK_RUNS 次
    print(f"\n[2] 运行 {len(ATTACK_TYPES)} 种攻击 × {ATTACK_RUNS} 次 ...")
    attack_summaries = []
    all_attack_latencies = []
    total_intercepted = 0
    total_attacks = 0
    for atk in ATTACK_TYPES:
        s = run_attack_scenario(atk, runs=ATTACK_RUNS)
        attack_summaries.append(s)
        total_intercepted += s["intercepted"]
        total_attacks += s["runs"]
        all_attack_latencies.extend(r["latency_ms"] for r in s["detail"])

    overall_interception_rate = (total_intercepted / total_attacks) if total_attacks else 0.0

    # 3. 运行良性调用
    print(f"\n[3] 运行 {BENIGN_RUNS} 次良性调用 ...")
    benign_summary = run_benign_scenario(runs=BENIGN_RUNS)

    # 4. 汇总统计
    all_latencies = all_attack_latencies + [r["latency_ms"] for r in benign_summary["detail"]]
    avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0.0

    print("\n" + "=" * 70)
    print("  评估结果汇总")
    print("=" * 70)
    print(f"  攻击拦截率: {total_intercepted}/{total_attacks} "
          f"({overall_interception_rate * 100:.1f}%)")
    for s in attack_summaries:
        print(f"    - {s['attack_type']:<12}: {s['intercepted']}/{s['runs']} "
              f"({s['interception_rate'] * 100:.0f}%)")
    print(f"  良性通过率: {benign_summary['passed']}/{benign_summary['runs']} "
          f"({benign_summary['pass_rate'] * 100:.1f}%)")
    print(f"  平均延迟:   {avg_latency:.2f} ms")
    print("=" * 70)

    # 说明 replay 拦截情况
    replay_s = next((s for s in attack_summaries if s["attack_type"] == "replay"), None)
    if replay_s and replay_s["intercepted"] == 0:
        print("[NOTE] replay 拦截率为 0: 当前 nullifier 基于随机 nonce 生成,")
        print("       相同 (tool, input) 的重放不会触发 nullifier 冲突。")
        print("       建议将 nullifier 绑定到输入 (如 H(tool_id, input)) 以检测重放。")

    # 5. 保存结果
    summary = {
        "experiment": "e2e_openclaw",
        "gateway_url": GATEWAY_URL,
        "config": {
            "attack_runs": ATTACK_RUNS,
            "benign_runs": BENIGN_RUNS,
            "attack_types": ATTACK_TYPES,
            "tools": REGISTERED_TOOL_IDS,
        },
        "attacks": attack_summaries,
        "benign": benign_summary,
        "overall": {
            "attack_interception_rate": round(overall_interception_rate, 4),
            "benign_pass_rate": benign_summary["pass_rate"],
            "total_attacks": total_attacks,
            "total_intercepted": total_intercepted,
            "avg_latency_ms": round(avg_latency, 3),
        },
        "timestamp": time.time(),
    }
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n结果已保存到: {os.path.abspath(RESULTS_FILE)}")
    return summary


if __name__ == '__main__':
    main()
