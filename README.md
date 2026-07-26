# Agent Gateway - 智能体工具链隐私保护验证网关

Agent Gateway 是一个部署在智能体（Agent）与工具之间的验证网关。所有工具调用必须经过网关验证后才能到达实际工具，确保工具调用的**合法性**、**隐私性**和**不可重放性**。

## 核心能力

| 能力 | 说明 |
|------|------|
| **工具合法性验证** | 基于 Merkle Tree 验证工具是否在治理委员会注册的白名单中 |
| **输入参数隐私** | 使用 Pedersen Commitment 隐藏工具调用的输入参数 |
| **防重放攻击** | 每次调用生成唯一 Nullifier，重复提交被拒绝 |
| **批量签名聚合** | BLS 增量聚合签名，n≥33 时自动切换至聚合验证模式 |
| **状态持久化** | 网关重启后自动恢复工具注册表和审计日志 |

## 架构

```
┌──────────┐     HTTP      ┌──────────────┐     HTTP      ┌──────────────┐
│  Agent   │ ────────────> │ Agent Gateway │ ────────────> │ Actual Tools │
│ (OpenClaw)│ <─────────── │  (验证+转发)  │ <─────────── │  (后端服务)   │
└──────────┘   响应+证明    └──────────────┘    响应       └──────────────┘
                                  │
                          验证流程:
                          1. Merkle存在性检查
                          2. Pedersen承诺(隐藏输入)
                          3. Nullifier生成(防重放)
                          4. BLS增量聚合(签名)
```

## 快速开始

### 1. 安装依赖

```bash
cd agent_gateway
pip install -r requirements.txt
```

依赖清单（`requirements.txt`）：
```
fastapi>=0.104.0
uvicorn>=0.24.0
httpx>=0.25.0
pydantic>=2.5.0
ecdsa>=0.18.0
blspy>=2.0.0
```

### 2. 启动网关

```bash
# 方式一: 直接启动
python -m uvicorn app.main:app --host 0.0.0.0 --port 8400

# 方式二: 使用启动脚本
bash scripts/start.sh

# 方式三: Docker 启动 (见下方部署部分)
```

启动后访问：
- API 文档：`http://localhost:8400/docs`
- 健康检查：`http://localhost:8400/health`

### 3. 注册工具

治理委员会将 Agent 可用的工具注册到网关：

```python
from app.openclaw_adapter import OpenClawGatewayClient

client = OpenClawGatewayClient("http://localhost:8400")

# 注册工具 (tool_id, 名称, 实际后端地址)
client.register_tool("web_search", "Web搜索", "http://tool-backend:5001/search")
client.register_tool("code_exec", "代码执行", "http://tool-backend:5001/exec")

# 完成注册, 构建 Merkle 树
result = client.finalize_registration()
print(f"Merkle Root: {result['merkle_root']}")
```

### 4. Agent 通过网关调用工具

```python
# Agent 每次调用工具 -> 网关自动验证 -> 转发到实际工具
result = client.call_tool("web_search", "搜索AI安全漏洞")

print(result["status"])           # "verified"
print(result["nullifier"])        # 防重放标记
print(result["tool_response"])    # 实际工具的返回结果
```

### 5. 提交调用批次

```python
# Agent 完成一轮工具链后, 提交批次
batch = client.submit_batch()

print(batch["batch_size"])   # 调用次数
print(batch["mode"])          # "ecdsa" (n<33) 或 "bls_aggregate" (n≥33)
print(batch["merkle_root"])  # Merkle 根
```

## 部署方法

### 方法一：Docker 部署（推荐）

```bash
cd agent_gateway

# 构建并启动
docker-compose up -d

# 查看日志
docker logs -f agent-gateway

# 停止
docker-compose down
```

`docker-compose.yml` 配置了数据卷持久化、健康检查和自动重启。

### 方法二：手动部署

```bash
# 1. 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 创建数据目录 (状态持久化)
mkdir -p /data

# 4. 启动网关 (生产环境用 gunicorn + uvicorn worker)
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8400

# 或开发模式
uvicorn app.main:app --host 0.0.0.0 --port 8400 --reload
```

### 方法三：Systemd 服务部署

创建 `/etc/systemd/system/agent-gateway.service`：

```ini
[Unit]
Description=Agent Gateway - Tool Chain Verification
After=network.target

[Service]
Type=simple
User=agent
WorkingDirectory=/opt/agent_gateway
Environment=PATH=/opt/agent_gateway/.venv/bin
ExecStart=/opt/agent_gateway/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8400 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable agent-gateway
sudo systemctl start agent-gateway
```

## OpenClaw 集成方法

### 方式一：URL 重定向（推荐，无需修改 Agent 代码）

将 OpenClaw Agent 的工具调用地址从直接指向工具后端，改为指向网关：

```yaml
# OpenClaw 配置
agent:
  tool_execution:
    # 修改前: 直接调用工具
    # base_url: "http://tool-backend:5001"
    
    # 修改后: 通过网关调用
    base_url: "http://agent-gateway:8400"
    endpoint: "/v1/call"
```

Agent 发送的请求格式：

```json
POST http://agent-gateway:8400/v1/call
{
  "tool_id": "web_search",
  "input": "搜索内容",
  "forward": true
}
```

网关验证后自动转发到注册时配置的实际工具地址。

### 方式二：嵌入 GatewayClient

在 Agent 代码中直接使用适配器：

```python
from app.openclaw_adapter import OpenClawGatewayClient

gateway = OpenClawGatewayClient("http://agent-gateway:8400")

# 注册阶段 (治理委员会执行一次)
gateway.register_tool("web_search", "Web搜索", "http://tool-backend:5001/search")
gateway.finalize_registration()

# 运行时: Agent 每次调用工具
result = gateway.call_tool("web_search", "搜索内容")

# 工具链执行完毕后提交批次
batch = gateway.submit_batch()
```

完整示例见 `examples/openclaw_integration.py`。

## API 接口参考

### 工具注册

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/tools/register` | 注册单个工具 |
| POST | `/v1/tools/finalize` | 完成注册，构建 Merkle 树 |
| GET | `/v1/tools` | 列出所有已注册工具 |
| POST | `/v1/tools/{tool_id}/enable` | 启用/禁用工具 |

### 工具调用（核心）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/call` | 调用工具（网关验证后转发） |
| POST | `/v1/batch/submit` | 提交调用批次 |
| GET | `/v1/batch/pending` | 查看待提交批次数 |

### 验证查询

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v1/verify/merkle/{tool_id}` | 验证工具 Merkle 存在性 |
| GET | `/v1/verify/nullifier/{hex}` | 检查 Nullifier 是否已使用 |
| GET | `/v1/merkle/root` | 获取 Merkle 根和叶子数 |

### 状态与审计

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/v1/stats` | 网关统计信息 |
| GET | `/v1/audit` | 审计日志 |

### `/v1/call` 请求/响应示例

**请求：**
```json
{
  "tool_id": "web_search",
  "input": "搜索AI安全漏洞",
  "forward": true
}
```

**响应：**
```json
{
  "status": "verified",
  "tool_id": "web_search",
  "nullifier": "a1b2c3d4e5f6...",
  "input_commit": "123456789012...",
  "result_hash": "f0e1d2c3b4a5...",
  "timestamp": 1785036822.0,
  "pending_batch_size": 1,
  "tool_response": {
    "tool": "web_search",
    "query": "搜索AI安全漏洞",
    "results": ["result_0", "result_1", "result_2"]
  }
}
```

## 测试

### 端到端测试

```bash
# 1. 启动模拟工具服务器 (端口 9100)
python -m uvicorn scripts.mock_tool_server:app --port 9100 &

# 2. 启动网关 (端口 8400)
python -m uvicorn app.main:app --port 8400 &

# 3. 运行端到端测试
python tests/e2e_test.py
```

测试覆盖：
- 工具注册与 Merkle 树构建
- 工具 Merkle 存在性验证
- Agent 工具链调用（含转发）
- 批次提交（ECDSA 模式 n=3）
- 大批量提交（BLS 聚合模式 n=35）
- 审计日志查询

### OpenClaw 集成示例

```bash
python examples/openclaw_integration.py
```

## 配置说明

配置文件位于 `config/gateway.toml`：

```toml
[server]
host = "0.0.0.0"
port = 8400
workers = 4

[gateway]
state_file = "/data/gateway_state.json"
max_audit_logs = 10000

[crypto]
bls_enabled = true          # BLS签名开关 (blspy不可用时自动降级)
switch_threshold = 33       # BLS/ECDSA 切换临界点

[blockchain]
enabled = false             # 区块链配置 (稍后启用)
rpc_url = ""
contract_address = ""
private_key = ""
```

## 验证机制详解

### 1. Merkle Tree 存在性验证

工具注册时，每个工具的 `(tool_id, code_hash)` 作为叶子加入 Merkle 树。调用时验证该工具确实存在于树中，防止未授权工具被调用。

```
         Root
        /    \
      N1      N2
     / \     / \
   L0   L1  L2  L3
   |    |    |    |
 web  code  file  db
```

### 2. Pedersen Commitment（输入隐私）

调用工具时，输入参数通过 Pedersen 承诺隐藏：`C = m*G + r*H`。验证者只能确认输入未被篡改，但无法获知具体内容。争议时可打开承诺进行仲裁。

### 3. Nullifier（防重放）

每次调用生成唯一 Nullifier：`N = Hash(tool_id, nonce)`。相同 Nullifier 重复提交会被拒绝，防止重放攻击。

### 4. BLS 增量聚合签名

Agent 每调用一个工具，网关增量聚合其 BLS 签名。当批次大小 n≥33 时自动切换至 BLS 聚合验证模式，验证效率 O(1) 而非 O(n)。

## 项目结构

```
agent_gateway/
├── app/
│   ├── __init__.py
│   ├── crypto.py            # 密码学核心 (Merkle, Pedersen, BLS, Nullifier)
│   ├── gateway.py           # 网关引擎 (注册, 验证, 批次, 持久化)
│   ├── main.py              # FastAPI 服务入口 (REST API)
│   └── openclaw_adapter.py  # OpenClaw 客户端适配器
├── config/
│   └── gateway.toml         # 配置文件
├── scripts/
│   ├── mock_tool_server.py  # 模拟工具服务器 (测试用)
│   └── start.sh             # 启动脚本
├── tests/
│   └── e2e_test.py          # 端到端测试
├── examples/
│   └── openclaw_integration.py  # OpenClaw 集成示例
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 区块链集成（待配置）

当前网关以独立模式运行，所有验证在本地完成。区块链集成将在后续阶段配置：

1. 将 Merkle Root 提交到链上合约
2. 批次聚合签名在链上验证
3. Nullifier 在链上去重
4. ZK Proof 链上验证（Groth16）

配置项已预留于 `config/gateway.toml` 的 `[blockchain]` 段。
