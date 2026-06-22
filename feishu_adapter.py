import json
import logging
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
import uvicorn

# Import mcp instance from gateway to use security tools and middleware directly
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gateway import mcp, current_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FeishuAdapter")

# Initialize Starlette App for Adapter
app = Starlette()

# Verification token from Feishu (configured in Feishu Developer Console)
FEISHU_VERIFICATION_TOKEN = "feishu_mcp_verification_token_xyz"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENDPOINT: Receive Webhook from Feishu AI Assistant (Lark Custom Skill)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async def feishu_webhook(request):
    try:
        payload = await request.json()
        logger.info(f"Received Feishu Webhook payload: {json.dumps(payload, ensure_ascii=False)}")
        
        # 1. Verify packet source from Feishu
        token = payload.get("token")
        if token != FEISHU_VERIFICATION_TOKEN:
            logger.warning("Unauthorized request received: Token mismatch")
            return JSONResponse({"code": 401, "msg": "Unauthorized: Verification token mismatch"}, status_code=401)
            
        # 2. Handle URL Verification challenge from Feishu (for initial webhook setup)
        if payload.get("type") == "url_verification":
            challenge = payload.get("challenge")
            return JSONResponse({"challenge": challenge})
            
        # 3. Extract Action (tool name) and Params from Feishu AI
        # Feishu Custom Skill payload structure sent to Webhook
        header = payload.get("header", {})
        event = payload.get("event", {})
        
        # Get user details calling the bot on Feishu for authorization
        feishu_user_id = event.get("operator", {}).get("operator_id", {}).get("open_id", "feishu_anonymous")
        
        # Mock authorization based on Feishu Open ID
        # Production: Map Open ID to internal LDAP/Okta account
        user_role = "admin" if feishu_user_id == "ou_hieuluongxuan" else "staff"
        user_context = {"user_id": feishu_user_id, "role": user_role}
        
        # Set user identity in ContextVar
        token_ctx = current_user.set(user_context)
        
        try:
            # Extract Skill call details
            action_name = event.get("action_name")
            action_params = event.get("action_parameters", {})
            
            if not action_name:
                return JSONResponse({
                    "code": 400,
                    "msg": "Missing action_name in event payload."
                }, status_code=400)
                
            logger.info(f"Mapping Feishu Action: '{action_name}' for User: '{feishu_user_id}' ({user_role})")
            
            # 4. Invoke MCP Tool via FastMCP Engine
            # FastMCP automatically runs through PIIRedactionMiddleware filtering PII & writing Audit log
            try:
                mcp_result = await mcp.call_tool(action_name, arguments=action_params)
                
                # Extract text from MCP result
                response_text = ""
                if mcp_result.content:
                    response_text = "\n".join([item.text for item in mcp_result.content if hasattr(item, "text")])
            except Exception as e:
                logger.error(f"Error calling MCP Tool {action_name}: {e}")
                response_text = f"❌ Error executing tool {action_name}: {str(e)}"
                
            # 5. Format output into Feishu Interactive Card structure
            feishu_card = {
                "config": {
                    "wide_screen_mode": True
                },
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": f"📊 HimiTek MCP: {action_name.replace('_', ' ').title()}"
                    },
                    "template": "blue"
                },
                "elements": [
                    {
                        "tag": "markdown",
                        "content": f"**🤖 Secure Query Result (PII Masked):**\n\n```json\n{response_text}\n```"
                    },
                    {
                        "tag": "note",
                        "elements": [
                            {
                               "tag": "plain_text",
                               "content": f"Requested by OpenID: {feishu_user_id} | Secured by HimiTek Enterprise MCP Bridge"
                            }
                        ]
                    }
                ]
            }
            
            # Return response with structure expected by Feishu
            return JSONResponse({
                "code": 0,
                "msg": "success",
                "data": {
                    "card": feishu_card
                }
            })
            
        finally:
            current_user.reset(token_ctx)
            
    except Exception as e:
        logger.error(f"General adapter crash: {e}")
        return JSONResponse({"code": 500, "msg": f"Internal Server Error: {str(e)}"}, status_code=500)

app.routes.append(Route("/feishu/webhook", endpoint=feishu_webhook, methods=["POST"]))

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Feishu MCP Adapter running on http://127.0.0.1:8001")
    print("🔌 Webhook URL configuration in Feishu: http://<domain>/feishu/webhook")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8001)
