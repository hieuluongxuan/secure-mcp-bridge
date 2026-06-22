import os
import sys
import json
import asyncio
from contextlib import AsyncExitStack

# Attempt to import the required MCP library components
try:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    import mcp.types as types
except ImportError:
    print("Error: Please install the mcp SDK by running: pip install mcp", file=sys.stderr)
    sys.exit(1)

# SSE Gateway Server URL configuration (VPS Oracle production by default)
GATEWAY_URL = os.environ.get("MCP_GATEWAY_URL", "https://himitrace.himitek.com")
SSE_ENDPOINT = f"{GATEWAY_URL}/mcp/sse"

# Local Credentials Storage File
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_DIR = os.path.join(SCRIPT_DIR, ".secrets")
TOKEN_FILE = os.path.join(SECRETS_DIR, "token.json")

# Ensure .secrets directory exists
os.makedirs(SECRETS_DIR, exist_ok=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Authentication Management (Mock OAuth2 Flow)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_auth_token() -> str:
    """
    Reads the access token from the local credentials storage.
    Automatically generates a default mock token if not found (for easy demo setup).
    """
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                data = json.load(f)
                return data.get("access_token", "")
        except Exception as e:
            print(f"[Auth] Error reading token file: {e}", file=sys.stderr)

    # Mock OAuth2 login: write a default valid token to storage
    mock_token = "token-vip-hieu"
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump({
                "access_token": mock_token,
                "token_type": "Bearer",
                "issued_at": "2026-06-19T14:00:00",
                "expires_in": 3600
            }, f, indent=2)
        print(f"[Auth] Initialized Mock Token at: {TOKEN_FILE}", file=sys.stderr)
        return mock_token
    except Exception as e:
        print(f"[Auth] Error generating Mock Token: {e}", file=sys.stderr)
        return ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Client Bridge Program (Stdio <-> SSE Proxy)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async def main():
    token = get_auth_token()
    if not token:
        print("[Error] Could not find or initialize authentication token.", file=sys.stderr)
        sys.exit(1)

    print(f"[Client] Establishing connection to Enterprise Gateway via SSE...", file=sys.stderr)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    async with AsyncExitStack() as stack:
        # 1. Establish SSE stream transport with the Gateway
        try:
            transport = await stack.enter_async_context(
                sse_client(SSE_ENDPOINT, headers=headers)
            )
            read_stream, write_stream = transport
        except Exception as e:
            print(f"[Error] Could not connect to MCP Gateway at {SSE_ENDPOINT}: {e}", file=sys.stderr)
            print("[Hint] Please verify if gateway.py is running and reachable.", file=sys.stderr)
            sys.exit(1)

        # 2. Establish Client Session with the Gateway
        client_session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await client_session.initialize()
        
        # 3. Synchronize list of tools from the Gateway
        remote_tools = await client_session.list_tools()
        print(f"[Client] Successfully synchronized {len(remote_tools.tools)} tools from Enterprise Gateway.", file=sys.stderr)

        # 4. Initialize Local Stdio Server for Cursor/Windsurf
        local_server = Server("SecureLocalBridge")

        # Dynamically register tools on the local server
        for remote_tool in remote_tools.tools:
            # Create a dynamic forwarding handler
            def create_tool_handler(tool_name):
                async def handler(*args, **kwargs):
                    # Forward tool call to the remote SSE Gateway
                    response = await client_session.call_tool(tool_name, arguments=kwargs)
                    return response
                return handler

            # Register on local server
            local_server.tool(
                name=remote_tool.name,
                description=remote_tool.description,
                input_schema=remote_tool.inputSchema
            )(create_tool_handler(remote_tool.name))

        # 5. Run stdio server loop for communication with the local AI Editor
        print("[Client] Ready to receive commands from AI Editor via Stdio...", file=sys.stderr)
        async with stdio_server() as (local_read, local_write):
            await local_server.run(
                local_read,
                local_write,
                local_server.create_initialization_options()
            )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[Client] Stopped Client Bridge.", file=sys.stderr)
    except Exception as e:
        print(f"[Client] Unexpected error: {e}", file=sys.stderr)
