"""
Agent Gateway - FastAPI 服务入口
提供REST API供OpenClaw Agent调用
"""
import time, json, asyncio, logging
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx

from .gateway import GatewayEngine
from .crypto import VerifyMode, CallRecord

# ============================================================
# Pydantic 模型
# ============================================================

class ToolRegisterRequest(BaseModel):
    tool_id: str = Field(..., description="工具唯一标识")
    name: str = Field("", description="工具名称")
    endpoint: str = Field(..., description="工具的实际HTTP地址, 如 http://localhost:8081/search")
    code_hash: Optional[str] = Field(None, description="工具代码哈希(hex), 留空则自动计算")

class ToolCallRequest(BaseModel):
    tool_id: str = Field(..., description="要调用的工具ID")
    input: str = Field(..., description="调用输入参数(字符串)")
    forward: bool = Field(True, description="是否将调用转发到实际工具端点")

class BatchSubmitRequest(BaseModel):
    pass

class ToolEnableRequest(BaseModel):
    enabled: bool

# ============================================================
# FastAPI 应用
# ============================================================

app = FastAPI(
    title="Agent Gateway",
    description="智能体工具链隐私保护可信验证网关 - 拦截并验证Agent的所有工具调用",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局网关引擎
engine = GatewayEngine()
logger = logging.getLogger("agent_gateway")


# ============================================================
# 生命周期: 启动/关闭
# ============================================================

@app.on_event("startup")
async def startup():
    state_file = "/data/gateway_state.json"
    engine.set_state_file(state_file)
    engine.load_state()
    logger.info(f"Gateway started. Tools: {len(engine.tools)}, Merkle root: {engine.get_merkle_root()[:16]}...")

@app.on_event("shutdown")
async def shutdown():
    engine.save_state()
    logger.info("Gateway state saved.")


# ============================================================
# 中间件: 请求日志
# ============================================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = (time.time() - start) * 1000
    logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({duration:.1f}ms)")
    return response


# ============================================================
# API 路由
# ============================================================

# --- 健康检查 ---

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}


# --- 网关状态 ---

@app.get("/v1/stats")
async def get_stats():
    return engine.get_stats()


@app.get("/v1/audit")
async def get_audit_log(limit: int = 50):
    return {"logs": engine.get_audit_log(limit)}


# --- 工具注册管理 ---

@app.post("/v1/tools/register")
async def register_tool(req: ToolRegisterRequest):
    """注册工具到网关 (治理委员会调用)"""
    try:
        code_hash = bytes.fromhex(req.code_hash) if req.code_hash else None
        reg = engine.register_tool(req.tool_id, req.name, req.endpoint, code_hash)
        engine.save_state()
        return {
            "status": "registered",
            "tool_id": reg.tool_id,
            "name": reg.name,
            "endpoint": reg.endpoint,
            "merkle_index": reg.merkle_index,
        }
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.post("/v1/tools/finalize")
async def finalize_registration():
    """完成注册, 构建Merkle树"""
    root = engine.finalize_registration()
    engine.save_state()
    return {"status": "finalized", "merkle_root": root.hex()}


@app.get("/v1/tools")
async def list_tools():
    return {"tools": engine.list_tools()}


@app.post("/v1/tools/{tool_id}/enable")
async def enable_tool(tool_id: str, req: ToolEnableRequest):
    try:
        engine.enable_tool(tool_id, req.enabled)
        engine.save_state()
        return {"status": "ok", "tool_id": tool_id, "enabled": req.enabled}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- 工具调用 (核心拦截) ---

@app.post("/v1/call")
async def call_tool(req: ToolCallRequest, background_tasks: BackgroundTasks):
    """
    Agent通过此端点调用工具
    网关执行: 验证 -> 记录 -> (可选)转发到实际工具
    """
    input_bytes = req.input.encode('utf-8')

    # Step 1: 验证并记录
    try:
        record = engine.verify_and_record(req.tool_id, input_bytes)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Step 2: 转发到实际工具 (如果forward=True)
    tool_response = None
    if req.forward:
        tool = engine.tools.get(req.tool_id)
        if tool and tool.endpoint:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        tool.endpoint,
                        json={"tool_id": req.tool_id, "input": req.input},
                        headers={"X-Gateway-Nullifier": record.nullifier.hex()},
                    )
                    tool_response = resp.json()
            except httpx.ConnectError:
                tool_response = {"error": "tool endpoint unreachable", "endpoint": tool.endpoint}
            except httpx.TimeoutException:
                tool_response = {"error": "tool endpoint timeout"}
            except Exception as e:
                tool_response = {"error": str(e)}

    return {
        "status": "verified",
        "tool_id": req.tool_id,
        "nullifier": record.nullifier.hex(),
        "input_commit": str(record.input_commit),
        "result_hash": record.result_hash.hex(),
        "timestamp": record.timestamp,
        "pending_batch_size": engine.get_pending_batch_size(),
        "tool_response": tool_response,
    }


# --- 批次提交 ---

@app.post("/v1/batch/submit")
async def submit_batch():
    """提交当前调用批次, 自动选择验证模式"""
    try:
        batch = engine.submit_batch()
        engine.save_state()
        return batch
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/v1/batch/pending")
async def get_pending():
    return {"pending_size": engine.get_pending_batch_size()}


# --- 验证查询 ---

@app.get("/v1/verify/merkle/{tool_id}")
async def verify_merkle(tool_id: str):
    """验证工具的Merkle存在性"""
    reg = engine.tools.get(tool_id)
    if not reg:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    ok = engine._verify_merkle(reg)
    return {"tool_id": tool_id, "exists": ok, "merkle_root": engine.get_merkle_root()}


@app.get("/v1/verify/nullifier/{nullifier_hex}")
async def check_nullifier(nullifier_hex: str):
    """检查Nullifier是否已使用"""
    try:
        nullifier = bytes.fromhex(nullifier_hex)
        used = engine.check_nullifier(nullifier)
        return {"nullifier": nullifier_hex, "used": used}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex")


# --- Merkle信息 ---

@app.get("/v1/merkle/root")
async def get_merkle_root():
    return {"merkle_root": engine.get_merkle_root(), "leaf_count": engine.tree.num_leaves}


# ============================================================
# 启动入口
# ============================================================

def main():
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8400,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
