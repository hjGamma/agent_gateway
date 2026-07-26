# Agent Gateway 实验框架

基于 MCP-PEP 论文 (Electronics 2026) 实验框架设计，对标其 §4.2-§4.9 实验结构。

## 目录结构

```
agent_gateway/
├── app/
│   ├── gateway.py          # 核心引擎 (已添加消融开关)
│   ├── crypto.py            # 密码学原语
│   ├── audit_logger.py      # SHA-256 哈希链审计日志
│   └── main.py              # FastAPI 服务
├── data/AGW-30/             # 实验数据集 (20攻击 + 10良性)
│   ├── attacks/             # T1-T4 四类攻击任务
│   └── normal/              # N001-N010 良性任务
├── experiments/             # 实验脚本
│   ├── ablation_configs.py  # 消融配置矩阵
│   ├── run_security_eval.py # 实验1: 安全有效性评估
│   ├── run_ablation.py      # 实验2: 密码学机制消融
│   ├── benchmark_latency.py # 实验3: 网关开销微基准
│   ├── test_audit_tampering.py  # 实验4: 审计链完整性
│   ├── test_scalability.py  # 实验5: 工具链可扩展性
│   ├── benchmark_signature.py   # 实验6: 双模签名临界点
│   ├── run_e2e_openclaw.py  # 实验7: 端到端OpenClaw评估
│   └── results/             # 实验结果输出
├── tools/
│   └── verify_chain.py      # 独立审计链验证器
└── scripts/
    └── mock_tool_server.py  # Mock工具服务器
```

## 快速开始

### 环境准备

```bash
cd /workspace/agent_gateway
pip install -r requirements.txt
```

### 按优先级运行实验

#### P0 实验 (核心，必须完成)

**实验3: 网关开销微基准** (最快, ~2分钟)
```bash
python3 experiments/benchmark_latency.py
```
输出: `results/latency_benchmark.json`

**实验1: 安全有效性评估** (~1分钟)
```bash
python3 experiments/run_security_eval.py
```
输出: `results/security_eval_results.json`

**实验2: 密码学机制消融** (~1分钟)
```bash
python3 experiments/run_ablation.py
```
输出: `results/ablation_results.json`

#### P1 实验 (重要，建议完成)

**实验4: 审计链完整性** (~1分钟)
```bash
python3 experiments/test_audit_tampering.py
```
输出: `results/audit_tampering.json`

**实验5: 工具链可扩展性** (~10分钟)
```bash
python3 experiments/test_scalability.py
```
输出: `results/scalability.json`

**实验6: 双模签名临界点** (~5分钟)
```bash
pip install ecdsa blspy  # 需要这两个库
python3 experiments/benchmark_signature.py
```
输出: `results/signature_benchmark.json`

#### P2 实验 (端到端，需要OpenClaw)

**实验7: 端到端OpenClaw评估**
```bash
# 步骤1: 启动网关服务
python3 -m app.main

# 步骤2: 启动mock工具服务器 (另一个终端)
python3 scripts/mock_tool_server.py

# 步骤3: 运行端到端测试 (另一个终端)
python3 experiments/run_e2e_openclaw.py
```
输出: `results/e2e_results.json`

## 实验说明

### 实验1: 安全有效性评估 (对标 MCP-PEP §4.2+§4.4)

| Baseline | 含义 | 预期ASR |
|----------|------|---------|
| A | 无防护 | ~100% |
| B | Prompt-only | ~100% |
| C | Merkle+Nullifier (消融) | ~60% |
| D | 完整系统 | **~0%** |

### 实验2: 密码学机制消融 (对标 MCP-PEP §4.3)

| 配置 | 关闭机制 | 预期ASR变化 |
|------|---------|------------|
| D-full | 无 | 0% |
| D-no-ped | Pedersen | +40% (T2通过) |
| D-no-null | Nullifier | +20% (T3通过) |
| D-no-bls | BLS | 0% (仅影响效率) |

### 实验3: 网关开销微基准 (对标 MCP-PEP §4.5)

| 组件 | 预期P50 |
|------|---------|
| Merkle验证 | ~0.6 μs |
| Pedersen承诺 | ~2.2 μs |
| Nullifier计算 | ~1.2 μs |
| 端到端(64B) | ~13 μs |

### 实验4: 审计链完整性 (对标 MCP-PEP §4.6)

| 篡改模式 | 预期检测 |
|---------|---------|
| 值修改 | 检出 |
| 哈希伪造 | 检出 |
| 中间删除 | 检出 |
| 事件重排 | 检出 |
| 尾部截断 | 未检出 (已知缺口) |

## 独立审计链验证器

```bash
# 验证单个文件
python3 tools/verify_chain.py results/audit_log.json

# 验证目录下所有文件
python3 tools/verify_chain.py results/audit_logs/
```

## 消融开关使用

`gateway.py` 的 `verify_and_record()` 方法支持消融开关:

```python
engine.verify_and_record(
    tool_id='web_search',
    input_data=b'query',
    switches={
        'merkle': True,    # Merkle存在性验证
        'pedersen': True,  # Pedersen承诺
        'nullifier': True, # Nullifier防重放
        'bls': True,       # BLS签名聚合
    }
)
```

不传 `switches` 参数则全部开启 (默认行为)。

## 数据集格式

每个任务为JSON文件:

```json
{
  "task_id": "T1-001",
  "type": "attack",
  "attack_class": "tool_forgery",
  "tool_chain": ["fake_tool_001"],
  "inputs": ["malicious_query"],
  "expected_result": "deny"
}
```

攻击类型:
- T1 (tool_forgery): 调用未注册的伪造工具
- T2 (parameter_tampering): 提交承诺后用篡改输入验证
- T3 (replay_attack): 重放已使用的nullifier
- T4 (linkability_attack): 多次调用检查是否可关联

## 论文图表映射

| 论文位置 | 图表内容 | 数据来源 |
|---------|---------|---------|
| Table 1 | 安全有效性主表 | 实验1 |
| Table 2 | 密码学机制消融表 | 实验2 |
| Table 3 | 网关开销微基准 | 实验3 |
| Table 4 | 审计链篡改检测 | 实验4 |
| Figure 1 | 工具数量vs延迟 | 实验5 |
| Figure 2 | ECDSA vs BLS交叉点 | 实验6 |
| Table 5 | 端到端OpenClaw结果 | 实验7 |
