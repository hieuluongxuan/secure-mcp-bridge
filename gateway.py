import os
import re
import json
import logging
import contextvars
from datetime import datetime
from typing import Sequence, Any

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse, Response
from mcp.server.sse import SseServerTransport
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ContextVar for managing request-scoped user identities across async tasks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
current_user = contextvars.ContextVar("current_user", default="anonymous")

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureMCPGateway")

# Audit log file location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_PATH = os.path.join(SCRIPT_DIR, "audit.log")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Mock Enterprise Databases
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CUSTOMERS_DB = {
    "CUST-001": {
        "name": "Nguyen Van Hung",
        "email": "hung.nguyen@company.vn",
        "phone": "0912345678",
        "tier": "VIP",
        "sales_rep": "hieuluongxuan"
    },
    "CUST-002": {
        "name": "Tran Thi Lan",
        "email": "lan.tran@gmail.com",
        "phone": "0987654321",
        "tier": "Standard",
        "sales_rep": "staff_01"
    }
}

INVENTORY_DB = {
    "SKU-COFFEE-01": {"name": "Dak Lak Coffee Premium", "qty": 150, "price": 250000},
    "SKU-SHRIMP-02": {"name": "Ca Mau Tiger Shrimp", "qty": 500, "price": 320000}
}

# OAuth2 Mock Access Tokens
VALID_TOKENS = {
    "token-vip-hieu": {"user_id": "hieuluongxuan", "role": "admin"},
    "token-staff-01": {"user_id": "staff_01", "role": "staff"},
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PII Redaction & Audit Logger Middleware
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class PIIRedactionMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        tool_name = context.message.name
        arguments = context.message.arguments
        user_info = current_user.get()

        # Execute the tool
        result = await call_next(context)

        # Apply PII Masking on tool output text
        raw_text = ""
        if hasattr(result, "content") and result.content:
            for item in result.content:
                if hasattr(item, "text") and isinstance(item.text, str):
                    raw_text += item.text
                    item.text = self.redact_text(item.text)

        # Log details to Audit Trail
        self.write_audit_log(user_info, tool_name, arguments, raw_text, result)

        return result

    def redact_text(self, text: str) -> str:
        # 1. Mask Email Addresses
        text = re.sub(r"[\w\.-]+@[\w\.-]+\.\w{2,4}", "[EMAIL_REDACTED]", text)
        # 2. Mask Vietnamese Phone Numbers (preventing sub-matching longer digits)
        text = re.sub(r"(?<!\d)(?:\+84|0)[1-9]\d{8}(?!\d)", "[PHONE_REDACTED]", text)
        # 3. Mask secrets, credentials & API keys
        text = re.sub(r"(sk-[a-zA-Z0-9]{32,48}|ghp_[a-zA-Z0-9]{36})", "[API_KEY_REDACTED]", text)
        # 4. Mask National ID numbers (9 to 12 digits, preventing phone overlaps)
        text = re.sub(r"(?<!\d)\d{9,12}(?!\d)", "[ID_REDACTED]", text)
        return text

    def write_audit_log(self, user: Any, tool_name: str, args: Any, raw: str, result: Any):
        redacted_text = ""
        if hasattr(result, "content") and result.content:
            for item in result.content:
                if hasattr(item, "text") and isinstance(item.text, str):
                    redacted_text += item.text

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "tool": tool_name,
            "arguments": args,
            "response_length_raw": len(raw),
            "response_length_redacted": len(redacted_text),
            "response_preview": redacted_text[:100] + "..." if len(redacted_text) > 100 else redacted_text
        }

        # Write log entry to file
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        logger.info(f"Audit Log written for tool: {tool_name}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FastMCP Server Initialization & Business-Logic-Aware Tools
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
mcp = FastMCP(
    name="EnterpriseSecureGateway",
    instructions="Secure enterprise Gateway with OAuth2 authentication and PII filtering."
)
mcp.add_middleware(PIIRedactionMiddleware())

@mcp.tool()
def search_product_inventory(sku: str) -> str:
    """
    Look up stock quantity and price of a product by its SKU.
    All authenticated staff have permission to call this tool.
    """
    user_info = current_user.get()
    logger.info(f"User '{user_info}' is checking inventory for SKU: {sku}")
    
    item = INVENTORY_DB.get(sku)
    if not item:
        return f"Product not found with SKU: {sku}"
    
    return json.dumps({
        "sku": sku,
        "product_name": item["name"],
        "stock": item["qty"],
        "price_vnd": item["price"]
    }, ensure_ascii=False, indent=2)

@mcp.tool()
def get_customer_details(customer_id: str) -> str:
    """
    Retrieve customer contact details including phone, email and membership tier.
    Requires admin privileges or matching sales_rep ownership on the customer record.
    """
    user_info = current_user.get()
    if user_info == "anonymous":
        return "Security Error: Please log in before accessing customer details."
        
    user_id = user_info.get("user_id")
    role = user_info.get("role")
    
    customer = CUSTOMERS_DB.get(customer_id)
    if not customer:
        return f"Customer not found: {customer_id}"
        
    # Check permissions: Admin can view all, Staff can only view owned records
    if role != "admin" and customer["sales_rep"] != user_id:
        return f"Authorization Error: User '{user_id}' does not have permission to view this customer."
        
    return json.dumps({
        "customer_id": customer_id,
        "name": customer["name"],
        "email": customer["email"],
        "phone": customer["phone"],
        "tier": customer["tier"],
        "sales_rep": customer["sales_rep"]
    }, ensure_ascii=False, indent=2)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Starlette Web App & SSE Transport with OAuth2 Interceptors
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
sse = SseServerTransport("/mcp/messages")
app = Starlette()

# 1. OAuth2 Mock Token Endpoint
async def oauth_token(request):
    try:
        body = await request.json()
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")
        
        # Validate client credentials (mock)
        if client_id == "hieuluongxuan" and client_secret == "himi_secure_pass":
            return JSONResponse({
                "access_token": "token-vip-hieu",
                "token_type": "Bearer",
                "expires_in": 3600
            })
        elif client_id == "staff_01" and client_secret == "staff_pass":
            return JSONResponse({
                "access_token": "token-staff-01",
                "token_type": "Bearer",
                "expires_in": 3600
            })
        else:
            return JSONResponse({"error": "invalid_credentials"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# 2. SSE Connection Handler (GET)
async def handle_sse(request):
    # Retrieve token from Authorization Header or query param
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        # Fallback to query param for debugging ease
        token = request.query_params.get("token")
        
    if not token or token not in VALID_TOKENS:
        return Response("Unauthorized: Missing or invalid token", status_code=401)
        
    user_data = VALID_TOKENS[token]
    
    # Store identity in ContextVar before connecting the stream
    ctx_token = current_user.set(user_data)
    try:
        logger.info(f"User logged in: {user_data['user_id']} via SSE")
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp._mcp_server.run(
                streams[0], 
                streams[1], 
                mcp._mcp_server.create_initialization_options()
            )
    finally:
        current_user.reset(ctx_token)
    return Response()

# 3. Intercept & Authenticate POST messages
async def authenticated_messages_app(scope, receive, send):
    headers = dict(scope.get("headers", []))
    auth_header = headers.get(b"authorization", b"").decode("utf-8")
    
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        # Check query string fallback in ASGI scope
        query_string = scope.get("query_string", b"").decode("utf-8")
        params = dict(re.findall(r"([^&=]+)=([^&=]+)", query_string))
        token = params.get("token")
        
    if not token or token not in VALID_TOKENS:
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({"type": "http.body", "body": b"Unauthorized: Missing or invalid token"})
        return
        
    user_data = VALID_TOKENS[token]
    
    # Set request identity context
    ctx_token = current_user.set(user_data)
    try:
        await sse.handle_post_message(scope, receive, send)
    finally:
        current_user.reset(ctx_token)

# Starlette Routes registration
app.routes.append(Route("/oauth/token", endpoint=oauth_token, methods=["POST"]))
app.routes.append(Route("/mcp/sse", endpoint=handle_sse, methods=["GET"]))
app.routes.append(Mount("/mcp/messages", app=authenticated_messages_app))

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Enterprise Secure MCP Gateway running on http://127.0.0.1:8000")
    print(f"📝 Audit Log path: {AUDIT_LOG_PATH}")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8000)
