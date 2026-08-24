"""hyqsast_mcp — 把 HyqSast 包装成 MCP server 的薄层。

纯静态、零内部 LLM 决策：只把 ``hyqsast.scan()`` 暴露成 LLM 可调用的工具。
个人用仍走老 CLI 流程，本模块只服务于「LLM 通过 MCP 调用」这一条路径。
"""
