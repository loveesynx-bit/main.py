"""
╔══════════════════════════════════════════════════╗
║  🤖 IG Notifier — Python Backend (Fixed)        ║
║  Deploy on Render.com with Python 3.11           ║
╚══════════════════════════════════════════════════
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import logging
import os
import traceback
from datetime import datetime
from typing import Optional, List

# ── Safe instagrapi import ──
try:
    from instagrapi import Client as InstaClient
    from instagrapi.exceptions import (
        TwoFactorRequired, ChallengeRequired,
        BadPassword, LoginRequired,
        ConnectionException, SentryBlock,
        GenericRequestError, BadCredentials,
        PleaseWaitLoginPage, UserNotFound,
    )
    HAS_INSTAGRAPI = True
except ImportError:
    HAS_INSTAGRAPI = False
    print("❌ instagrapi not installed!")

# ══════════════════════════════════════════════════
#  📝 LOGGING
# ══════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════
#  🚀 FASTAPI APP
# ══════════════════════════════════════════════════
app = FastAPI(title="IG Notifier Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory client storage
clients = {}

# ══════════════════════════════════════════════════
#  📋 BAN KEYWORDS
# ══════════════════════════════════════════════════
BAN_KEYWORDS = [
    "disabled", "banned", "violated", "violation",
    "removed", "restricted", "suspended", "blocked",
    "community guidelines", "terms of use", "appeal",
    "warning", "strikes", "account status",
    "we removed", "we noticed", "unusual activity",
    "secure your account", "help us confirm",
    "your account", "account review", "action blocked",
    "try again later", "challenge required",
    "temporary lock", "unusual login", "verify your identity",
    "account disabled", "reactivate", "deactivated",
    "compromised", "phishing", "spam",
]


# ══════════════════════════════════════════════════
#  📦 REQUEST MODELS
# ══════════════════════════════════════════════════
class LoginRequest(BaseModel):
    username: str
    password: str
    session_id: str

class Verify2FARequest(BaseModel):
    code: str
    session_id: str

class SessionRequest(BaseModel):
    session_id: str


# ══════════════════════════════════════════════════
#  🔐 LOGIN ENDPOINT
# ══════════════════════════════════════════════════
@app.post("/login")
async def login(req: LoginRequest):
    """Login to Instagram"""
    if not HAS_INSTAGRAPI:
        return {"status": "error", "error": "instagrapi not installed on server"}

    try:
        cl = InstaClient()
        cl.set_locale("en_US")
        cl.set_timezone_offset(19800)

        session_file = f"session_{req.username}.json"

        # Try existing session
        if os.path.exists(session_file):
            try:
                cl.load_settings(session_file)
                cl.login(req.username, req.password)
                cl.get_timeline_feed()
                clients[req.session_id] = cl
                logger.info(f"✅ Session login: @{req.username}")
                return {
                    "status": "ok",
                    "session_id": req.session_id,
                    "message": "Login successful (session)"
                }
            except Exception as e:
                logger.info(f"Session expired: {e}")
                cl = InstaClient()
                cl.set_locale("en_US")
                cl.set_timezone_offset(19800)
                try:
                    os.remove(session_file)
                except Exception:
                    pass

        # Fresh login
        try:
            cl.login(req.username, req.password)
            cl.dump_settings(session_file)
            clients[req.session_id] = cl
            logger.info(f"✅ Fresh login: @{req.username}")
            return {
                "status": "ok",
                "session_id": req.session_id,
                "message": "Login successful"
            }

        except TwoFactorRequired as e:
            clients[req.session_id] = cl
            info = {}
            method = "unknown"
            try:
                last_json = getattr(cl, 'last_json', {}) or {}
                info = last_json.get("two_factor_info", {})
                if info.get("totp_two_factor_on"):
                    method = "totp"
                elif info.get("sms_two_factor_on"):
                    method = "sms"
            except Exception:
                pass

            logger.info(f"🔐 2FA required: @{req.username}")
            return {
                "status": "ok",
                "session_id": req.session_id,
                "needs_2fa": True,
                "two_factor_method": method,
                "obfuscated_phone": info.get("obfuscated_phone_number", ""),
                "message": "2FA verification required"
            }

        except ChallengeRequired as e:
            clients[req.session_id] = cl
            try:
                cl.challenge_resolve(cl.last_json)
                cl.dump_settings(session_file)
                logger.info(f"✅ Challenge auto-resolved: @{req.username}")
                return {
                    "status": "ok",
                    "session_id": req.session_id,
                    "message": "Login successful (challenge resolved)"
                }
            except Exception:
                pass

            return {
                "status": "ok",
                "session_id": req.session_id,
                "challenge_required": True,
                "message": "Challenge verification required"
            }

        except BadPassword:
            return {"status": "error", "error": "Wrong password!"}

        except BadCredentials:
            return {"status": "error", "error": "Invalid username or password!"}

        except UserNotFound:
            return {"status": "error", "error": "Username not found!"}

        except PleaseWaitLoginPage as e:
            return {"status": "error", "error": f"Rate limited. Please wait: {e}"}

        except SentryBlock:
            return {"status": "error", "error": "IP blocked by Instagram. Try proxy."}

        except ConnectionException:
            return {"status": "error", "error": "Cannot connect to Instagram."}

        except Exception as e:
            logger.error(f"❌ Login error: {e}\n{traceback.format_exc()}")
            return {"status": "error", "error": f"{type(e).__name__}: {str(e)}"}

    except Exception as e:
        logger.error(f"❌ Outer error: {e}")
        return {"status": "error", "error": str(e)}


# ══════════════════════════════════════════════════
#  🔐 VERIFY 2FA ENDPOINT
# ══════════════════════════════════════════════════
@app.post("/verify_2fa")
async def verify_2fa(req: Verify2FARequest):
    """Complete 2FA / challenge verification"""
    cl = clients.get(req.session_id)
    if not cl:
        return {"status": "error", "error": "No active session. Login first."}

    code = req.code.strip().replace(" ", "")

    # Method 1: two_factor_login
    try:
        cl.two_factor_login(code)
        username = getattr(cl, 'username', 'unknown') or 'unknown'
        cl.dump_settings(f"session_{username}.json")
        logger.info(f"✅ 2FA done (method 1): @{username}")
        return {"status": "ok", "message": "2FA verified"}
    except Exception as e:
        logger.debug(f"Method 1 failed: {e}")

    # Method 2: Re-login with verification_code
    try:
        last_json = getattr(cl, 'last_json', {}) or {}
        stored_username = ""
        # Try to find username from stored info
        for sid, c in clients.items():
            if c == cl:
                try:
                    stored_username = getattr(c, 'username', '') or ''
                except Exception:
                    pass
                break

        if stored_username:
            cl_new = InstaClient()
            cl_new.set_locale("en_US")
            cl_new.set_timezone_offset(19800)
            # We need password — but we don't store it
            # Skip this method if we can't get credentials
    except Exception as e:
        logger.debug(f"Method 2 failed: {e}")

    # Method 3: Direct API call
    try:
        last_json = getattr(cl, 'last_json', {}) or {}
        two_factor_info = last_json.get("two_factor_info", {})
        two_factor_id = two_factor_info.get("two_factor_identifier", "")

        if two_factor_id:
            result = cl.private_request(
                "accounts/two_factor_login/",
                data={
                    "verification_code": code,
                    "two_factor_identifier": two_factor_id,
                    "trust_this_device": "1",
                    "verification_method": "1",
                },
                with_signature=False,
            )
            if result:
                username = getattr(cl, 'username', 'unknown') or 'unknown'
                cl.dump_settings(f"session_{username}.json")
                logger.info(f"✅ 2FA done (direct API): @{username}")
                return {"status": "ok", "message": "2FA verified"}
    except Exception as e:
        logger.debug(f"Method 3 failed: {e}")

    # Method 4: Challenge code
    try:
        last_json = getattr(cl, 'last_json', {}) or {}
        api_path = last_json.get("challenge", {}).get("api_path", "")
        if api_path:
            result = cl.private_request(
                api_path.lstrip("/"),
                data={"security_code": code},
                with_signature=False,
            )
            if result:
                username = getattr(cl, 'username', 'unknown') or 'unknown'
                cl.dump_settings(f"session_{username}.json")
                logger.info(f"✅ Challenge resolved: @{username}")
                return {"status": "ok", "message": "Challenge verified"}
    except Exception as e:
        logger.debug(f"Method 4 failed: {e}")

    return {
        "status": "error",
        "error": "OTP verification failed. Try new code or /start again."
    }


# ══════════════════════════════════════════════════
#  📬 NOTIFICATIONS ENDPOINT
# ══════════════════════════════════════════════════
@app.post("/notifications")
async def notifications(req: SessionRequest):
    """Fetch Instagram notifications"""
    cl = clients.get(req.session_id)
    if not cl:
        return {"status": "error", "error": "Session expired. Login again."}

    all_notis = []
    seen_pk = set()

    def parse_item(item):
        try:
            noti_id = str(item.get("id", item.get("pk", "")))
            if not noti_id or noti_id in seen_pk:
                return None
            seen_pk.add(noti_id)

            text = item.get("text", "")
            if not text:
                args = item.get("args", {})
                if isinstance(args, dict):
                    text = args.get("text", args.get("description", args.get("headline", "")))
                    if isinstance(text, dict):
                        text = text.get("text", str(text))

            user = item.get("user", item.get("user_info", {}))
            username = user.get("username", "Unknown") if isinstance(user, dict) else "Unknown"

            ts = item.get("timestamp", item.get("created_at", ""))

            text_lower = str(text).lower()
            is_ban = any(kw in text_lower for kw in BAN_KEYWORDS)
            noti_type = str(item.get("type", "")).lower()
            if any(bt in noti_type for bt in ["ban", "block", "warning", "strike", "disabled"]):
                is_ban = True

            return {
                "id": noti_id,
                "type": item.get("type", "unknown"),
                "text": str(text),
                "timestamp": ts,
                "user": username,
                "is_ban_related": is_ban,
            }
        except Exception:
            return None

    # Endpoint 1
    try:
        result = cl.private_request("notifications/inbox/", params={"mark_as_seen": "false"})
        items = result.get("notifications", result.get("items", []))
        for item in items:
            if isinstance(item, dict):
                noti = parse_item(item)
                if noti: all_notis.append(noti)
    except Exception as e:
        logger.debug(f"notifications/inbox: {e}")

    # Endpoint 2
    try:
        result = cl.private_request("news/inbox/", params={"mark_as_seen": "false"})
        items = result.get("items", result.get("notifications", []))
        for item in items:
            if isinstance(item, dict):
                noti = parse_item(item)
                if noti: all_notis.append(noti)
    except Exception as e:
        logger.debug(f"news/inbox: {e}")

    # Endpoint 3
    try:
        result = cl.private_request("news/", params={"mark_as_seen": "false"})
        items = result.get("items", [])
        for item in items:
            if isinstance(item, dict):
                noti = parse_item(item)
                if noti: all_notis.append(noti)
    except Exception as e:
        logger.debug(f"news: {e}")

    logger.info(f"📬 {len(all_notis)} notis for {req.session_id[:8]}")
    return {"status": "ok", "notifications": all_notis}


# ══════════════════════════════════════════════════
#  📊 STATUS ENDPOINT
# ══════════════════════════════════════════════════
@app.post("/status")
async def status_check(req: SessionRequest):
    """Check if session is alive"""
    cl = clients.get(req.session_id)
    if not cl:
        return {"status": "ok", "alive": False, "error": "No session"}

    try:
        uid = cl.user_id
        if uid:
            cl.user_info(uid)
            return {"status": "ok", "alive": True, "user_id": str(uid)}
    except LoginRequired:
        return {"status": "ok", "alive": False, "error": "Expired"}
    except Exception as e:
        return {"status": "ok", "alive": True, "note": str(e)}

    return {"status": "ok", "alive": False}


# ══════════════════════════════════════════════════
#  🏥 HEALTH CHECK
# ══════════════════════════════════════════════════
@app.get("/")
async def health():
    return {
        "status": "ok",
        "service": "IG Notifier Backend",
        "active_sessions": len(clients),
        "instagrapi": HAS_INSTAGRAPI,
        "time": datetime.now().isoformat()
    }


# ══════════════════════════════════════════════════
#  🚀 RUN
# ══════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
