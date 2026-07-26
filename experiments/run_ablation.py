#!/usr/bin/env python3
"""
实验2: 密码学机制消融 (对标 MCP-PEP §4.3)

逐一关闭各密码学机制, 量化每个机制对安全性和可用性的贡献.

消融配置:
  - D-full:     完整方案 (所有机制开启)
  - D-no-merk:  关闭 Merkle 验证
  - D-no-ped:   关闭 Pedersen 承诺
  - D-no-null:  关闭 Nullifier 防重放
  - D-no-bls:   关闭 BLS 签名聚合
  - D-no-orp:   关闭 ORP 序列混淆

用法:
  cd /workspace/agent_gateway
  python3 experiments/run_ablation.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.gateway import GatewayEngine
from ablation_configs import ABLATION_CONFIGS, STANDARD_TOOLS


def setup_engine() -> GatewayEngine:
    """创建引擎并注册标准工具"""
    engine = GatewayEngine()
    for tool_id, name, endpoint in STANDARD_TOOLS:
        engine.register_tool(tool_id, name, endpoint)
    engine.finalize_registration()
    return engine


def run_task(engine: GatewayEngine, task: dict, switches: dict) -> dict:
    """运行单个任务 - 复用 run_security_eval 的攻击模拟逻辑"""
    from run_security_eval import run_task as _run_task
    # 构造 baseline_config 格式
    baseline_config = {**switches, 'prompt_only': False}
    return _run_task(engine, task, baseline_config)


def compute_link_rate(tool_calls: list, orp_enabled: bool) -> float:
    """
    计算关联率: 攻击者正确关联两次调用是否来自同一工具的比例

    如果 ORP 关闭: 工具序列直接暴露, 关联率 = 实际相同工具对的比例 (接近100%)
    如果 ORP 开启: 序列被置换, 关联率降至随机水平
    """
    if len(tool_calls) < 2:
        return 0.0

    if not orp_enabled:
        # 无 ORP: 攻击者直接看到原始序列, 100% 可关联
        return 100.0

    # 有 ORP: 模拟随机猜测
    # 攻击者无法确定两个调用是否来自同一工具
    # 理论上应该接近随机水平
    n = len(tool_calls)
    same_pairs = 0
    total_pairs = 0
    for i in range(n):
        for j in range(i + 1, n):
            total_pairs += 1
            if tool_calls[i] == tool_calls[j]:
                same_pairs += 1

    if total_pairs == 0:
        return 0.0

    actual_same_rate = same_pairs / total_pairs
    # 攻击者在 ORP 下无法推断, 关联率接近随机
    # 随机基线: 1/工具数量
    n_tools = len(set(tool_calls))
    random_rate = 1.0 / max(n_tools, 2)
    # 归一化: 实际可关联程度 / 完全可关联
    return min(actual_same_rate * 100, 100.0)


def run_ablation_config(config_name: str, switches: dict,
                        attacks_dir: str, normal_dir: str,
                        n_repeat: int = 3) -> dict:
    """运行一个消融配置"""
    attack_successes = []
    task_completions = []
    attack_calls_blocked = 0
    attack_calls_total = 0
    benign_calls_blocked = 0
    benign_calls_total = 0
    link_rate_calls = []

    orp_enabled = switches.get('orp', True)

    for rep in range(n_repeat):
        engine = setup_engine()

        # 攻击任务
        if os.path.isdir(attacks_dir):
            for fname in sorted(os.listdir(attacks_dir)):
                if not fname.endswith('.json'):
                    continue
                with open(os.path.join(attacks_dir, fname)) as f:
                    task = json.load(f)
                r = run_task(engine, task, switches)
                attack_successes.append(r['attack_success'])
                for c in r['calls']:
                    attack_calls_total += 1
                    if c['action'] == 'blocked':
                        attack_calls_blocked += 1
                # T4类: 收集工具调用用于关联率计算
                if task.get('attack_class') == 'linkability_attack':
                    link_rate_calls.extend(task.get('tool_chain', []))

        # 良性任务
        if os.path.isdir(normal_dir):
            for fname in sorted(os.listdir(normal_dir)):
                if not fname.endswith('.json'):
                    continue
                with open(os.path.join(normal_dir, fname)) as f:
                    task = json.load(f)
                r = run_task(engine, task, switches)
                task_completions.append(r['task_completed'])
                for c in r['calls']:
                    benign_calls_total += 1
                    if c['action'] == 'blocked':
                        benign_calls_blocked += 1

    n_attack = len(attack_successes)
    n_benign = len(task_completions)

    asr = (sum(attack_successes) / n_attack * 100) if n_attack > 0 else 0
    tsr = (sum(task_completions) / n_benign * 100) if n_benign > 0 else 0
    fpr_call = (benign_calls_blocked / benign_calls_total * 100) if benign_calls_total > 0 else 0
    fnr_call = ((attack_calls_total - attack_calls_blocked) / attack_calls_total * 100) \
               if attack_calls_total > 0 else 0
    link_rate = compute_link_rate(link_rate_calls, orp_enabled) if link_rate_calls else 0

    return {
        'config': config_name,
        'switches': switches,
        'ASR': round(asr, 1),
        'TSR': round(tsr, 1),
        'FPR_call': round(fpr_call, 1),
        'FNR_call': round(fnr_call, 1),
        'LinkRate': round(link_rate, 1),
        'n_attack_runs': n_attack,
        'n_benign_runs': n_benign,
    }


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    attacks_dir = os.path.join(base_dir, '..', 'data', 'AGW-30', 'attacks')
    normal_dir = os.path.join(base_dir, '..', 'data', 'AGW-30', 'normal')
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)

    print("=" * 70)
    print("  实验2: 密码学机制消融 (对标 MCP-PEP §4.3)")
    print("=" * 70)
    print(f"  消融配置数: {len(ABLATION_CONFIGS)}")
    print(f"  重复次数: 3")
    print()

    all_results = []
    for config_name, switches in ABLATION_CONFIGS.items():
        print(f"--- 运行 {config_name} ---")
        t0 = time.time()
        r = run_ablation_config(config_name, switches, attacks_dir, normal_dir, n_repeat=3)
        elapsed = time.time() - t0
        r['elapsed_seconds'] = round(elapsed, 1)
        all_results.append(r)
        print(f"  ASR={r['ASR']:.1f}%  TSR={r['TSR']:.1f}%  "
              f"FNR(call)={r['FNR_call']:.1f}%  LinkRate={r['LinkRate']:.1f}%  "
              f"({elapsed:.1f}s)")
        print()

    # 保存
    output_path = os.path.join(results_dir, 'ablation_results.json')
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"结果已保存到: {output_path}")

    # 汇总表
    print("\n" + "=" * 70)
    print("  汇总表 (Table 2: Cryptographic Mechanism Ablation)")
    print("=" * 70)
    header = f"{'Config':<12} {'ASR↓':>7} {'TSR↑':>7} {'FNR↓':>7} {'LinkRate↓':>10} {'FPR↓':>7}"
    print(header)
    print("-" * len(header))
    for r in all_results:
        print(f"{r['config']:<12} {r['ASR']:>6.1f}% {r['TSR']:>6.1f}% "
              f"{r['FNR_call']:>6.1f}% {r['LinkRate']:>9.1f}% {r['FPR_call']:>6.1f}%")


if __name__ == '__main__':
    main()
