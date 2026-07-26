#!/usr/bin/env python3
"""
工具链可扩展性测试
==================
评估 GatewayEngine 在不同 (工具数, Agent数) 组合下的调用验证性能。

实验流程:
  对每个 (n_tools, n_agents) 组合:
    1. 创建新的 GatewayEngine, 注册 n_tools 个工具, finalize_registration
    2. 运行 n_runs 次:
       - 每次 n_agents 个 Agent 各调用 chain_len 个工具 (共 n_agents*chain_len 次调用)
       - 测量总延迟 (ms) 和吞吐量 (ops/s)
    3. 返回中位数 (P50) 和 P95

性能指标:
  - latency_ms : 单次运行 (n_agents*chain_len 次调用) 的总延迟 (毫秒)
  - throughput  : 吞吐量 ops/s = ops / (latency_ms / 1000)

使用 time.perf_counter() 测量时间。
"""
import sys
import os
import time
import json
import statistics

# 导入上级模块 (app 包)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.gateway import GatewayEngine


# ============================================================
# 配置
# ============================================================
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'scalability.json')


# ============================================================
# 统计辅助
# ============================================================
def percentile(values, p):
    """计算 p 百分位数 (nearest-rank 方法)

    Args:
        values: 数值列表
        p: 百分位 (0-100)
    """
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    # nearest-rank
    k = max(0, min(n - 1, int(round(p / 100.0 * (n - 1)))))
    return s[k]


def median(values):
    return statistics.median(values) if values else 0.0


def mean(values):
    return statistics.fmean(values) if values else 0.0


# ============================================================
# 可扩展性测试
# ============================================================
def test_scalability(tool_counts=(10, 50, 100, 500, 1000),
                     n_agents=(1, 5, 10, 20),
                     chain_len=10,
                     n_runs=100):
    """工具链可扩展性测试

    Args:
        tool_counts: 待测工具数量列表
        n_agents: 待测 Agent 数量列表
        chain_len: 每个 Agent 单次运行调用的工具数
        n_runs: 每个组合的重复运行次数

    Returns:
        结果列表, 每项包含 latency_ms / throughput_ops 的 median 与 p95
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    results = []

    total_combos = len(tool_counts) * len(n_agents)
    combo_idx = 0
    print('=' * 78)
    print('  工具链可扩展性测试 (GatewayEngine)')
    print('=' * 78)
    print(f'  tool_counts={list(tool_counts)}')
    print(f'  n_agents={list(n_agents)}')
    print(f'  chain_len={chain_len}, n_runs={n_runs}')
    print('-' * 78)

    for n_tools in tool_counts:
        for n_ag in n_agents:
            combo_idx += 1
            ops_per_run = n_ag * chain_len
            print(f'[{combo_idx}/{total_combos}] n_tools={n_tools:<5} '
                  f'n_agents={n_ag:<3} ops/run={ops_per_run:<5} ...',
                  end=' ', flush=True)

            # 1. 每个组合使用全新的引擎
            engine = GatewayEngine()
            for i in range(n_tools):
                engine.register_tool(
                    tool_id=f'tool_{i}',
                    name=f'Tool {i}',
                    endpoint=f'http://localhost:9000/t{i}',
                )
            engine.finalize_registration()

            # 2. 预热 (1 次, 不计入统计, 消除冷启动抖动)
            _run_once(engine, n_ag, chain_len, n_tools, run_id=-1)
            # 清空预热产生的 pending 记录
            _flush(engine)

            # 3. 正式运行 n_runs 次
            latencies = []   # ms
            throughputs = []  # ops/s
            for run_id in range(n_runs):
                # 清空上一轮 pending (不计入计时)
                _flush(engine)

                start = time.perf_counter()
                _run_once(engine, n_ag, chain_len, n_tools, run_id=run_id)
                elapsed_s = time.perf_counter() - start

                latency_ms = elapsed_s * 1000.0
                throughput = ops_per_run / elapsed_s if elapsed_s > 0 else float('inf')
                latencies.append(latency_ms)
                throughputs.append(throughput)

            # 清空残余
            _flush(engine)

            # 4. 统计
            entry = {
                'n_tools': n_tools,
                'n_agents': n_ag,
                'chain_len': chain_len,
                'n_runs': n_runs,
                'ops_per_run': ops_per_run,
                'latency_ms': {
                    'median': round(median(latencies), 4),
                    'p95': round(percentile(latencies, 95), 4),
                    'mean': round(mean(latencies), 4),
                    'min': round(min(latencies), 4),
                    'max': round(max(latencies), 4),
                },
                'throughput_ops': {
                    'median': round(median(throughputs), 2),
                    'p95': round(percentile(throughputs, 95), 2),
                    'mean': round(mean(throughputs), 2),
                },
            }
            results.append(entry)
            print(f'latency median={entry["latency_ms"]["median"]:.3f}ms '
                  f'p95={entry["latency_ms"]["p95"]:.3f}ms | '
                  f'throughput median={entry["throughput_ops"]["median"]:.1f} ops/s')

    print('-' * 78)
    return results


def _run_once(engine, n_agents, chain_len, n_tools, run_id):
    """单次运行: n_agents 个 Agent 各调用 chain_len 个工具"""
    for agent in range(n_agents):
        for step in range(chain_len):
            tool_id = f'tool_{(agent * chain_len + step) % n_tools}'
            input_data = f'r{run_id}_a{agent}_s{step}'.encode('utf-8')
            try:
                engine.verify_and_record(tool_id, input_data)
            except ValueError:
                # 极小概率 nullifier 碰撞, 加随机盐重试一次
                engine.verify_and_record(tool_id, input_data + os.urandom(4))


def _flush(engine):
    """清空 pending 批次记录 (不计入性能统计)"""
    if engine.get_pending_batch_size() > 0:
        try:
            engine.submit_batch()
        except ValueError:
            pass


# ============================================================
# 结果展示
# ============================================================
def print_table(results):
    print('\n可扩展性测试结果汇总:')
    print('-' * 90)
    header = (f'{"tools":>6}{"agents":>8}{"ops/run":>10}'
              f'{"lat_med(ms)":>14}{"lat_p95(ms)":>14}'
              f'{"tps_med":>12}{"tps_p95":>12}')
    print(header)
    print('-' * 90)
    for r in results:
        print(f'{r["n_tools"]:>6}{r["n_agents"]:>8}{r["ops_per_run"]:>10}'
              f'{r["latency_ms"]["median"]:>14.4f}{r["latency_ms"]["p95"]:>14.4f}'
              f'{r["throughput_ops"]["median"]:>12.2f}'
              f'{r["throughput_ops"]["p95"]:>12.2f}')
    print('-' * 90)


def main():
    results = test_scalability(
        tool_counts=[10, 50, 100, 500, 1000],
        n_agents=[1, 5, 10, 20],
        chain_len=10,
        n_runs=100,
    )
    print_table(results)

    summary = {
        'experiment': 'scalability',
        'module': 'app.gateway.GatewayEngine',
        'config': {
            'tool_counts': [10, 50, 100, 500, 1000],
            'n_agents': [1, 5, 10, 20],
            'chain_len': 10,
            'n_runs': 100,
            'timer': 'time.perf_counter',
        },
        'results': results,
        'timestamp': time.time(),
    }
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f'\n结果已保存到: {os.path.abspath(RESULTS_FILE)}')
    print('=' * 78)
    return summary


if __name__ == '__main__':
    main()
