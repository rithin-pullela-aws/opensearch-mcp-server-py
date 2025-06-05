# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""
OpenSearch MCP Server implementation supporting multiple streaming protocols.
This module provides a Starlette-based web server that implements the Model Context Protocol
using both Server-Sent Events (SSE) and HTTP Streaming.
The SSE implementation is maintained for backward compatibility but may be deprecated in future versions.
"""

# Standard library imports
import argparse
import asyncio
import contextlib
import logging
from typing import AsyncIterator

# Third-party imports
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.responses import Response
from starlette.types import Scope, Receive, Send

# MCP imports
from mcp.server.sse import SseServerTransport
from mcp.server import Server
from mcp.types import TextContent, Tool
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

# Local imports
from tools.tools import TOOL_REGISTRY

# Configure logging
logger = logging.getLogger(__name__)

# ------------------------- MCP Server Implementation -------------------------

def create_mcp_server() -> Server:
    """
    Creates and configures an MCP server instance with tool registration.
    
    Returns:
        Server: Configured MCP server instance
    """
    server = Server("opensearch-mcp-server")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """Lists all available tools in the registry."""
        tools = []
        for tool_name, tool_info in TOOL_REGISTRY.items():
            tools.append(Tool(
                name=tool_name,
                description=tool_info["description"],
                inputSchema=tool_info["input_schema"]
            ))
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        """Executes a registered tool with the given arguments."""
        tool = TOOL_REGISTRY[name]
        if not tool:
            raise ValueError(f"Unknown tool: {name}")
        parsed = tool["args_model"](**arguments)
        return await tool["function"](parsed)

    return server

# ------------------------- Starlette Application -------------------------

class MCPStarletteApp:
    """
    Starlette application wrapper for the MCP server.
    Handles SSE connections, health checks, and streamable HTTP requests.
    """
    
    def __init__(self, mcp_server: Server):
        """
        Initialize the Starlette application with MCP server integration.
        
        Args:
            mcp_server: Configured MCP server instance
        """
        self.mcp_server = mcp_server
        self.sse = SseServerTransport("/messages/")
        self.session_manager = StreamableHTTPSessionManager(
            app=self.mcp_server,
            event_store=None,
            json_response=False,
            stateless=True,
        )

    async def handle_sse(self, request: Request) -> None:
        """Handle SSE connection requests."""
        async with self.sse.connect_sse(
                request.scope,
                request.receive,
                request._send,
        ) as (read_stream, write_stream):
            await self.mcp_server.run(
                read_stream,
                write_stream,
                self.mcp_server.create_initialization_options(),
            )
        return Response()

    async def handle_health(self, request: Request) -> Response:
        """Handle health check requests."""
        return Response("OK", status_code=200)
    
    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        """
        Context manager for session manager lifecycle.
        Ensures proper startup and shutdown of the session manager.
        """
        async with self.session_manager.run():
            logger.info("Application started with StreamableHTTP session manager!")
            try:
                yield
            finally:
                logger.info("Application shutting down...")

    async def handle_streamable_http(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Handle streamable HTTP requests."""
        await self.session_manager.handle_request(scope, receive, send)

    def create_app(self) -> Starlette:
        """
        Create and configure the Starlette application with all routes.
        
        Returns:
            Starlette: Configured Starlette application
        """
        return Starlette(
            routes=[
                Route("/sse", endpoint=self.handle_sse, methods=["GET"]),
                Route("/health", endpoint=self.handle_health, methods=["GET"]),
                Mount("/messages/", app=self.sse.handle_post_message),
                Mount("/mcp", app=self.handle_streamable_http),
            ],
            lifespan=self.lifespan,
        )

# ------------------------- Server Entry Point -------------------------

async def serve(host: str = "0.0.0.0", port: int = 9900) -> None:
    """
    Start the MCP server with the specified host and port.
    
    Args:
        host: Host address to bind to
        port: Port number to listen on
    """
    mcp_server = create_mcp_server()
    app_handler = MCPStarletteApp(mcp_server)
    app = app_handler.create_app()
    
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
    )
    server = uvicorn.Server(config)
    await server.serve()
