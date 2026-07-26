#!/usr/bin/env python3
"""
实验3: 网关开销微基准 (对标 MCP-PEP §4.5)

精确测量 verify_and_record() 各阶段的延迟分布:
  - Merkle 验证延迟
  - Pedersen 承诺延迟
  - Nullifier 计算延迟
  - 审计日志写入延迟
  - 端到端验证延迟 (不同输入大小)

用法:
  cd /workspace/agent_gateway
  python3 experiments/benchmark_latency.py
"""
import json
import os
import sys
import time
import statistics
import hashlib
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.gateway import GatewayEngine
from app.crypto import MerkleTree, PedersenCommitment, compute_nullifier


def percentile(data: list, p: float) -> float:
    """计算百分位数"""
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100)
    if idx >= len(sorted_data):
        idx = len(sorted_data) - 1
    return sorted_data[idx]


def benchmark_components(engine: GatewayEngine, n_runs: int = 5000) -> dict:
    """分阶段测量各组件开销"""
    print(f"\n  组件级基准 ({n_runs} 次)...")

    tool_id = list(engine.tools.keys())[0]
    reg = engine.tools[tool_id]
    input_data = b'test_input_data_for_benchmark'

    # 1. Merkle 验证
    merkle_times = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        proof, is_right = engine.tree.get_proof(reg.merkle_index)
        MerkleTree.verify_proof(reg.leaf_hash, proof, is_right, engine.tree.root)
        t1 = time.perf_counter_ns()
        merkle_times.append((t1 - t0) / 1000)  # 转微秒

    # 2. Pedersen 承诺
    pedersen_times = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        PedersenCommitment.commit_bytes(input_data)
        t1 = time.perf_counter_ns()
        pedersen_times.append((t1 - t0) / 1000)

    # 3. Nullifier 计算
    nullifier_times = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        nonce = secrets.token_bytes(16)
        compute_nullifier(tool_id, nonce)
        t1 = time.perf_counter_ns()
        nullifier_times.append((t1 - t0) / 1000)

    # 4. SHA-256 哈希 (用于 result_hash)
    hash_times = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        hashlib.sha256(input_data + secrets.token_bytes(16)).digest()
        t1 = time.perf_counter_ns()
        hash_times.append((t1 - t0) / 1000)

    # 5. 审计日志写入
    audit_times = []
    test_log = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        test_log.append({'action': 'bench', 'ts': time.time(), 'tool': tool_id})
        t1 = time.perf_counter_ns()
        audit_times.append((t1 - t0) / 1000)

    components = {}
    for name, times in [('merkle_verify', merkle_times),
                        ('pedersen_commit', pedersen_times),
                        ('nullifier_compute', nullifier_times),
                        ('sha256_hash', hash_times),
                        ('audit_log_append', audit_times)]:
        components[name] = {
            'p50': round(statistics.median(times), 1),
            'p95': round(percentile(times, 95), 1),
            'p99': round(percentile(times, 99), 1),
            'mean': round(statistics.mean(times), 1),
            'std': round(statistics.stdev(times), 1),
            'n': n_runs,
        }
        print(f"    {name:20s}: P50={components[name]['p50']:.1f}us  "
              f"P95={components[name]['p95']:.1f}us  "
              f"P99={components[name]['p99']:.1f}us")

    return components


def benchmark_verify(engine: GatewayEngine, input_sizes: list, n_runs: int = 5000) -> dict:
    """测量端到端验证延迟 (不同输入大小)"""
    print(f"\n  端到端验证基准 ({n_runs} 次)...")

    results = {}
    tool_id = list(engine.tools.keys())[0]

    for size in input_sizes:
        input_data = os.urandom(size)
        latencies = []

        for _ in range(n_runs):
            t0 = time.perf_counter_ns()
            try:
                engine.verify_and_record(tool_id, input_data)
            except (ValueError, PermissionError):
                pass
            t1 = time.perf_counter_ns()
            latencies.append((t1 - t0) / 1000)

        key = f'{size}B'
        results[key] = {
            'input_size_bytes': size,
            'p50': round(statistics.median(latencies), 1),
            'p95': round(percentile(latencies, 95), 1),
            'p99': round(percentile(latencies, 99), 1),
            'mean': round(statistics.mean(latencies), 1),
            'std': round(statistics.stdev(latencies), 1),
            'n': n_runs,
        }
        print(f"    {key:>8s}: P50={results[key]['p50']:.1f}us  "
              f"P95={results[key]['p95']:.1f}us  "
              f"P99={results[key]['p99']:.1f}us")

    return results


def benchmark_batch_submit(engine: GatewayEngine, batch_sizes: list, n_runs: int = 1000) -> dict:
    """测量批次提交延迟"""
    print(f"\n  批次提交基准 ({n_runs} 次)...")

    results = {}
    tool_ids = list(engine.tools.keys())

    for batch_size in batch_sizes:
        latencies = []

        for _ in range(n_runs):
            # 准备批次
            for i in range(batch_size):
                tid = tool_ids[i % len(tool_ids)]
                try:
                    engine.verify_and_record(tid, f'bench_{i}'.encode())
                except (ValueError, PermissionError):
                    pass

            # 测量 submit_batch
            t0 = time.perf_counter_ns()
            try:
                engine.submit_batch()
            except (ValueError, PermissionError):
                pass
            t1 = time.perf_counter_ns()
            latencies.append((t1 - t0) / 1000)

        key = f'batch_{batch_size}'
        results[key] = {
            'batch_size': batch_size,
            'p50': round(statistics.median(latencies), 1),
            'p95': round(percentile(latencies, 95), 1),
            'p99': round(percentile(latencies, 99), 1),
            'mean': round(statistics.mean(latencies), 1),
            'n': n_runs,
        }
        print(f"    batch={batch_size:>4d}: P50={results[key]['p50']:.1f}us  "
              f"P95={results[key]['p95']:.1f}us  "
              f"P99={results[key]['p99']:.1f}us")

    return results


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)

    print("=" * 70)
    print("  实验3: 网关开销微基准 (对标 MCP-PEP §4.5)")
    print("=" * 70)

    # 初始化引擎
    engine = GatewayEngine()
    engine.register_tool('bench_tool', 'Benchmark', 'http://localhost:9100')
    engine.finalize_registration()
    print(f"  已注册工具, Merkle root: {engine.get_merkle_root()[:16]}...")

    # 1. 组件级基准
    print("\n--- 1. 组件级延迟 ---")
    components = benchmark_components(engine, n_runs=5000)

    # 2. 端到端延迟
    print("\n--- 2. 端到端验证延迟 ---")
    sizes = [64, 256, 1024, 4096, 16384]
    e2e = benchmark_verify(engine, sizes, n_runs=5000)

    # 3. 批次提交延迟
    print("\n--- 3. 批次提交延迟 ---")
    batch_sizes = [10, 33, 50, 100]
    batch_results = benchmark_batch_submit(engine, batch_sizes, n_runs=1000)

    # 保存结果
    results = {
        'components': components,
        'e2e_by_input_size': e2e,
        'batch_submit': batch_results,
        'metadata': {
            'n_runs_components': 5000,
            'n_runs_e2e': 5000,
            'n_runs_batch': 1000,
            'timestamp': time.time(),
        }
    }
    output_path = os.path.join(results_dir, 'latency_benchmark.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n结果已保存到: {output_path}")

    # 打印汇总表
    print("\n" + "=" * 70)
    print("  汇总表 (Table 3: Gateway Overhead Microbenchmark)")
    print("=" * 70)
    print(f"{'Component':<25} {'P50 (us)':>10} {'P95 (us)':>10} {'P99 (us)':>10}")
    print("-" * 57)
    for name, stats in components.items():
        print(f"{name:<25} {stats['p50']:>10.1f} {stats['p95']:>10.1f} {stats['p99']:>10.1f}")
    print("-" * 57)
    for name, stats in e2e.items():
        print(f"E2E {name:<21} {stats['p50']:>10.1f} {stats['p95']:>10.1f} {stats['p99']:>10.1f}")


if __name__ == '__main__':
    main()
