#!/usr/bin/env python3
"""
双模签名临界点验证
==================
对比 ECDSA 逐个签名/验证 与 BLS 聚合签名/验证 的性能, 找到效率交叉点,
并与配置的 SWITCH_THRESHOLD (默认 33) 比较。

原理:
  - ECDSA: n 个签名需要 n 次 sign + n 次 verify, 总成本 O(n)
  - BLS  : n 个签名需要 n 次 sign + 1 次 aggregate + 1 次 aggregate_verify,
           验证成本近似 O(1), 故 n 较大时 BLS 更优

测量:
  - benchmark_ecdsa        : 测量单次 sign / verify 的 P50 延迟 (微秒),
                             批次总成本 = n * (sign + verify)
  - benchmark_bls_aggregate: 测量 n 次 sign / aggregate / aggregate_verify 的 P50 延迟
  - find_crossover         : 找到 BLS 总成本首次低于 ECDSA 总成本的 n

使用 time.perf_counter_ns() 测量时间。
"""
import sys
import os
import json
import time
import secrets

# 导入上级模块 (app 包), 读取配置的 SWITCH_THRESHOLD
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from app.crypto import SWITCH_THRESHOLD
except Exception:
    SWITCH_THRESHOLD = 33  # config/gateway.toml: [batch] switch_threshold = 33


# ============================================================
# 配置
# ============================================================
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'signature_benchmark.json')


# ============================================================
# 统计辅助
# ============================================================
def percentile(values, p):
    """nearest-rank 百分位数 (输入为 ns 列表)"""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    k = max(0, min(n - 1, int(round(p / 100.0 * (n - 1)))))
    return s[k]


def ns_to_us(ns_value):
    """纳秒 -> 微秒"""
    return ns_value / 1000.0


# ============================================================
# ECDSA 基准: 逐个签名 + 验证
# ============================================================
def benchmark_ecdsa(n_range=range(1, 101, 2), n_runs=200):
    """测量 ECDSA (NIST256p) 单次 sign / verify 的 P50 延迟 (微秒)

    对每个 n:
      - 生成 n 个密钥对 (仅一次, 不计入计时)
      - 重复 n_runs 次: 测量 1 次 sign + 1 次 verify
      - 记录 sign / verify 的 P50 延迟 (微秒)
      - 批次总成本 total_us = n * (sign_p50 + verify_p50)  [ECDSA 各签名相互独立]

    Returns:
        结果列表, 每项: {n, sign_us, verify_us, total_us}
        若 ecdsa 库未安装, 打印提示并返回 None。
    """
    try:
        from ecdsa import SigningKey, NIST256p
    except ImportError:
        print('[ECDSA] ecdsa 库未安装, 请运行: pip install ecdsa')
        return None

    print('[ECDSA] 开始基准测试 ...')
    max_n = max(n_range)

    # 预生成 max_n 个密钥对 (不计入计时)
    print(f'[ECDSA] 预生成 {max_n} 个 NIST256p 密钥对 ...')
    sks = [SigningKey.generate(curve=NIST256p) for _ in range(max_n)]
    vks = [sk.get_verifying_key() for sk in sks]

    results = []
    for n in n_range:
        sign_ns_list = []
        verify_ns_list = []
        for run in range(n_runs):
            # 轮流使用前 n 个密钥中的某一个, 模拟批次内的不同签名者
            idx = run % n
            msg = f'ecdsa_msg_{n}_{run}'.encode('utf-8')

            # sign
            t0 = time.perf_counter_ns()
            sig = sks[idx].sign(msg)
            sign_ns = time.perf_counter_ns() - t0
            sign_ns_list.append(sign_ns)

            # verify
            t0 = time.perf_counter_ns()
            vks[idx].verify(sig, msg)
            verify_ns = time.perf_counter_ns() - t0
            verify_ns_list.append(verify_ns)

        sign_p50 = ns_to_us(percentile(sign_ns_list, 50))
        verify_p50 = ns_to_us(percentile(verify_ns_list, 50))
        # ECDSA 批次总成本: n 次签名 + n 次验证 (线性)
        total_p50 = n * (sign_p50 + verify_p50)

        results.append({
            'n': n,
            'sign_us': round(sign_p50, 3),
            'verify_us': round(verify_p50, 3),
            'total_us': round(total_p50, 3),
        })
        if n % 19 == 1 or n == max_n:
            print(f'  n={n:<3} sign={sign_p50:.2f}us verify={verify_p50:.2f}us '
                  f'total={total_p50:.2f}us')

    print('[ECDSA] 完成')
    return results


# ============================================================
# BLS 基准: 聚合签名 + 验证
# ============================================================
def benchmark_bls_aggregate(n_range=range(1, 101, 2), n_runs=200):
    """测量 BLS (blspy AugSchemeMPL) 聚合签名/验证的 P50 延迟 (微秒)

    对每个 n:
      - 生成 n 个密钥对 (仅一次, 不计入计时)
      - 重复 n_runs 次:
          * sign      : 对 n 条消息各签名一次
          * aggregate : 聚合 n 个签名为 1 个
          * verify    : aggregate_verify n 个公钥/消息/聚合签名
      - 记录 sign / aggregate / verify 的 P50 延迟 (微秒)
      - 批次总成本 total_us = sign_p50 + aggregate_p50 + verify_p50

    Returns:
        结果列表, 每项: {n, sign_us, aggregate_us, verify_us, total_us}
        若 blspy 库未安装, 打印提示并返回 None。
    """
    try:
        from blspy import AugSchemeMPL
    except ImportError:
        print('[BLS] blspy 库未安装, 跳过 BLS 基准测试。')
        print('[BLS] 请运行: pip install blspy')
        return None

    print('[BLS] 开始基准测试 ...')
    max_n = max(n_range)

    # 预生成 max_n 个密钥对
    print(f'[BLS] 预生成 {max_n} 个 BLS 密钥对 ...')
    sks = [AugSchemeMPL.key_gen(secrets.token_bytes(32)) for _ in range(max_n)]
    pks = [sk.get_g1() for sk in sks]

    results = []
    for n in n_range:
        sub_sks = sks[:n]
        sub_pks = pks[:n]
        sign_ns_list = []
        agg_ns_list = []
        verify_ns_list = []
        total_ns_list = []

        for run in range(n_runs):
            # 消息必须两两不同 (aggregate_verify 要求)
            msgs = [f'bls_msg_{n}_{run}_{i}'.encode('utf-8') for i in range(n)]

            # sign n
            t0 = time.perf_counter_ns()
            sigs = [AugSchemeMPL.sign(sk, msg) for sk, msg in zip(sub_sks, msgs)]
            sign_ns = time.perf_counter_ns() - t0
            sign_ns_list.append(sign_ns)

            # aggregate
            t0 = time.perf_counter_ns()
            agg_sig = AugSchemeMPL.aggregate(sigs)
            agg_ns = time.perf_counter_ns() - t0
            agg_ns_list.append(agg_ns)

            # aggregate_verify
            t0 = time.perf_counter_ns()
            ok = AugSchemeMPL.aggregate_verify(sub_pks, msgs, agg_sig)
            verify_ns = time.perf_counter_ns() - t0
            verify_ns_list.append(verify_ns)

            total_ns_list.append(sign_ns + agg_ns + verify_ns)

        sign_p50 = ns_to_us(percentile(sign_ns_list, 50))
        agg_p50 = ns_to_us(percentile(agg_ns_list, 50))
        verify_p50 = ns_to_us(percentile(verify_ns_list, 50))
        total_p50 = sign_p50 + agg_p50 + verify_p50

        results.append({
            'n': n,
            'sign_us': round(sign_p50, 3),
            'aggregate_us': round(agg_p50, 3),
            'verify_us': round(verify_p50, 3),
            'total_us': round(total_p50, 3),
        })
        if n % 19 == 1 or n == max_n:
            print(f'  n={n:<3} sign={sign_p50:.2f}us agg={agg_p50:.2f}us '
                  f'verify={verify_p50:.2f}us total={total_p50:.2f}us')

    print('[BLS] 完成')
    return results


# ============================================================
# 交叉点查找
# ============================================================
def find_crossover(ecdsa_results, bls_results):
    """找到 BLS 聚合验证总成本首次低于 ECDSA 逐个验证总成本的 n

    Args:
        ecdsa_results: benchmark_ecdsa 返回的列表 (含 total_us)
        bls_results  : benchmark_bls_aggregate 返回的列表 (含 total_us)

    Returns:
        交叉点 n (int); 若任一结果为空或无交叉, 返回 None
    """
    if not ecdsa_results or not bls_results:
        return None

    ecdsa_map = {r['n']: r['total_us'] for r in ecdsa_results}
    bls_map = {r['n']: r['total_us'] for r in bls_results}
    common_ns = sorted(set(ecdsa_map) & set(bls_map))

    for n in common_ns:
        if bls_map[n] < ecdsa_map[n]:
            return n
    return None


# ============================================================
# 结果展示
# ============================================================
def print_comparison(ecdsa_results, bls_results):
    print('\n签名方案对比 (P50, 微秒):')
    print('-' * 70)
    print(f'{"n":>4}{"ECDSA sign":>14}{"ECDSA verify":>16}'
          f'{"ECDSA total":>14}{"BLS total":>14}')
    print('-' * 70)
    if not ecdsa_results:
        print('  (ECDSA 结果为空)')
        return
    e_map = {r['n']: r for r in ecdsa_results}
    b_map = {r['n']: r for r in bls_results} if bls_results else {}
    for r in ecdsa_results:
        n = r['n']
        bls_tot = b_map.get(n, {}).get('total_us', None)
        bls_str = f'{bls_tot:.2f}' if bls_tot is not None else 'N/A'
        print(f'{n:>4}{r["sign_us"]:>14.2f}{r["verify_us"]:>16.2f}'
              f'{r["total_us"]:>14.2f}{bls_str:>14}')
    print('-' * 70)


# ============================================================
# 主入口
# ============================================================
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print('=' * 70)
    print('  双模签名临界点验证 (ECDSA vs BLS Aggregate)')
    print('=' * 70)
    print(f'  配置 SWITCH_THRESHOLD = {SWITCH_THRESHOLD}')
    print(f'  n_range = {list(range(1, 101, 2))}')
    print(f'  n_runs  = 200')
    print('-' * 70)

    # 1. ECDSA 基准
    ecdsa_results = benchmark_ecdsa(
        n_range=range(1, 101, 2), n_runs=200)

    # 2. BLS 基准
    bls_results = benchmark_bls_aggregate(
        n_range=range(1, 101, 2), n_runs=200)

    # 3. 对比表
    if ecdsa_results:
        print_comparison(ecdsa_results, bls_results)

    # 4. 交叉点
    crossover = find_crossover(ecdsa_results, bls_results)

    print('\n' + '=' * 70)
    print('  结论')
    print('=' * 70)
    if ecdsa_results is None:
        print('  [!] ECDSA 基准未执行 (缺少 ecdsa 库)')
    if bls_results is None:
        print('  [!] BLS 基准未执行 (缺少 blspy 库)')

    if crossover is not None:
        print(f'  实测交叉点 n* = {crossover}')
        print(f'  配置 SWITCH_THRESHOLD = {SWITCH_THRESHOLD}')
        if crossover == SWITCH_THRESHOLD:
            print('  [OK] 实测交叉点与配置阈值一致')
        elif crossover < SWITCH_THRESHOLD:
            print(f'  [INFO] 实测交叉点 < 配置阈值, 配置偏保守 '
                  f'(可适当下调以更早启用 BLS)')
        else:
            print(f'  [WARN] 实测交叉点 > 配置阈值, 配置偏激进 '
                  f'(在 [{SWITCH_THRESHOLD}, {crossover}) 区间内 ECDSA 实际更优)')
    else:
        if ecdsa_results and bls_results:
            print('  [INFO] 在测试范围内未观测到交叉点 '
                  '(可能 BLS 始终更优或始终更劣)')
        print(f'  配置 SWITCH_THRESHOLD = {SWITCH_THRESHOLD} (参考值)')

    # 5. 保存结果
    summary = {
        'experiment': 'signature_benchmark',
        'config': {
            'n_range': list(range(1, 101, 2)),
            'n_runs': 200,
            'switch_threshold': SWITCH_THRESHOLD,
            'timer': 'time.perf_counter_ns',
        },
        'ecdsa': {
            'available': ecdsa_results is not None,
            'library': 'ecdsa (NIST256p)',
            'results': ecdsa_results,
        },
        'bls': {
            'available': bls_results is not None,
            'library': 'blspy (AugSchemeMPL)',
            'results': bls_results,
        },
        'crossover_n': crossover,
        'switch_threshold': SWITCH_THRESHOLD,
        'timestamp': time.time(),
    }
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f'\n结果已保存到: {os.path.abspath(RESULTS_FILE)}')
    print('=' * 70)
    return summary


if __name__ == '__main__':
    main()
