# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from tools.tool_generator import generate_tools_from_openapi
from common.tool_filter import get_tools
from opensearch.client import set_profile
import logging

# --- Server setup ---
async def serve(mode: str = "single", profile: str = "") -> None:
    # Set the global profile if provided
    if profile:
        set_profile(profile)
        
    server = Server("opensearch-mcp-server")
    # Call tool generator
    await generate_tools_from_openapi()
    enabled_tools = get_tools(mode)
    logging.info(f"Enabled tools: {list(enabled_tools.keys())}")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for tool_name, tool_info in enabled_tools.items():
            tools.append(
                Tool(
                    name=tool_name,
                    description=tool_info["description"],
                    inputSchema=tool_info["input_schema"],
                )
            )
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        tool = enabled_tools.get(name)
        if not tool:
            raise ValueError(f"Unknown or disabled tool: {name}")
        parsed = tool["args_model"](**arguments)
        return await tool["function"](parsed)

    # Start stdio-based MCP server
    options = server.create_initialization_options()
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, options, raise_exceptions=True)
