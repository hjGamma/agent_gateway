#!/usr/bin/env python3
"""
Agent Gateway - 模拟工具服务器
用于测试: 模拟OpenClaw工具的实际后端服务
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import time, hashlib

app = FastAPI(title="Mock Tool Server", version="1.0")

@app.post("/search")
async def search(request: Request):
    body = await request.json()
    query = body.get("input", "")
    return {
        "tool": "web_search",
        "query": query,
        "results": [f"result_{i}" for i in range(3)],
        "timestamp": time.time()
    }

@app.post("/analyze")
async def analyze(request: Request):
    body = await request.json()
    data = body.get("input", "")
    return {
        "tool": "data_analysis",
        "analysis": f"Analyzed: {data[:50]}...",
        "score": 0.87,
        "timestamp": time.time()
    }

@app.post("/summarize")
async def summarize(request: Request):
    body = await request.json()
    text = body.get("input", "")
    return {
        "tool": "summarizer",
        "summary": f"Summary of: {text[:50]}...",
        "word_count": len(text.split()),
        "timestamp": time.time()
    }

@app.post("/execute")
async def execute(request: Request):
    body = await request.json()
    code = body.get("input", "")
    return {
        "tool": "code_executor",
        "output": f"Executed: {code[:50]}...",
        "exit_code": 0,
        "timestamp": time.time()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9100)
