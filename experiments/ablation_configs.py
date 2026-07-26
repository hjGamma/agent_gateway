"""
消融实验配置矩阵
定义各 baseline 和消融配置的密码学开关
"""

# ============================================================
# Baseline 配置 (对标 MCP-PEP A/B/C/D)
# ============================================================
BASELINE_CONFIGS = {
    'A': {'merkle': False, 'pedersen': False, 'nullifier': False,
          'bls': False},
    'B': {'merkle': False, 'pedersen': False, 'nullifier': False,
          'bls': False, 'prompt_only': True},
    'C': {'merkle': True,  'pedersen': False, 'nullifier': True,
          'bls': False},
    'D': {'merkle': True,  'pedersen': True,  'nullifier': True,
          'bls': True},
}

# ============================================================
# 消融配置矩阵 (对标 MCP-PEP §4.3)
# 逐一关闭各密码学机制, 量化贡献
# ============================================================
ABLATION_CONFIGS = {
    'D-full':    {'merkle': True,  'pedersen': True,  'nullifier': True,
                  'bls': True},
    'D-no-merk': {'merkle': False, 'pedersen': True,  'nullifier': True,
                  'bls': True},
    'D-no-ped':  {'merkle': True,  'pedersen': False, 'nullifier': True,
                  'bls': True},
    'D-no-null': {'merkle': True,  'pedersen': True,  'nullifier': False,
                  'bls': True},
    'D-no-bls':  {'merkle': True,  'pedersen': True,  'nullifier': True,
                  'bls': False},
}

# 标准测试工具
STANDARD_TOOLS = [
    ('web_search', 'Web Search', 'http://localhost:9100/search'),
    ('file_read',  'File Read',  'http://localhost:9100/read'),
    ('file_write', 'File Write', 'http://localhost:9100/write'),
    ('shell_exec', 'Shell Execute', 'http://localhost:9100/shell'),
    ('send_email', 'Send Email', 'http://localhost:9100/email'),
]
