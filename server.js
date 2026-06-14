/*
╔══════════════════════════════════════════════════╗
║  🤖 IG Notifier — Node.js Backend               ║
║  100% JavaScript - No Python/Rust Errors!        ║
╚══════════════════════════════════════════════════
*/

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { IgApiClient, IgCheckpointError, IgLoginTwoFactorRequiredError } = require('instagram-private-api');

const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

// In-memory storage for Instagram clients
const clients = {};

// Ban keywords for detection
const BAN_KEYWORDS = [
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
    "compromised", "phishing", "spam"
];

// ─── HEALTH CHECK ────────────────────────────────
app.get('/', (req, res) => {
    res.json({ 
        status: "ok", 
        service: "IG Notifier Node.js Backend",
        active_sessions: Object.keys(clients).length 
    });
});

// ─── LOGIN ENDPOINT ──────────────────────────────
app.post('/login', async (req, res) => {
    const { username, password, session_id } = req.body;
    
    if (!username || !password || !session_id) {
        return res.status(400).json({ status: "error", error: "Missing fields" });
    }

    try {
        const ig = new IgApiClient();
        ig.state.generateDevice(username);
        
        // Try to load existing session
        const savedSession = loadSession(username);
        if (savedSession) {
            try {
                await ig.state.deserialize(savedSession);
                // Check if session is valid
                await ig.account.currentUser();
                clients[session_id] = ig;
                console.log(`✅ Session login: @${username}`);
                return res.json({
                    status: "ok",
                    session_id: session_id,
                    message: "Login successful (session)"
                });
            } catch (e) {
                console.log(`🔄 Session expired for @${username}, fresh login...`);
            }
        }

        // Fresh login
        try {
            await ig.simulate.preLoginFlow();
            const loggedInUser = await ig.account.login(username, password);
            ig.state.serialize();
            
            // Save session
            const sessionData = await ig.state.serialize();
            saveSession(username, sessionData);
            
            clients[session_id] = ig;
            console.log(`✅ Fresh login: @${username}`);
            
            return res.json({
                status: "ok",
                session_id: session_id,
                message: "Login successful"
            });

        } catch (e) {
            // 2FA Required
            if (e instanceof IgLoginTwoFactorRequiredError) {
                clients[session_id] = ig;
                const twoFactorInfo = e.response.body.two_factor_info;
                const method = twoFactorInfo.totp_two_factor_on ? "totp" : "sms";
                const phone = twoFactorInfo.obfuscated_phone_number || "";
                
                console.log(`🔐 2FA required: @${username}`);
                return res.json({
                    status: "ok",
                    session_id: session_id,
                    needs_2fa: true,
                    two_factor_method: method,
                    obfuscated_phone: phone,
                    message: "2FA verification required"
                });
            }
            
            // Challenge Required
            if (e instanceof IgCheckpointError) {
                clients[session_id] = ig;
                await ig.challenge.auto(true);
                console.log(`⚠️ Challenge required: @${username}`);
                return res.json({
                    status: "ok",
                    session_id: session_id,
                    challenge_required: true,
                    message: "Challenge verification required. Check email/SMS."
                });
            }

            // Bad Password / Other errors
            const errorMsg = e.response?.body?.message || e.message || "Unknown error";
            console.log(`❌ Login failed: @${username} - ${errorMsg}`);
            
            if (errorMsg.toLowerCase().includes("password")) {
                return res.json({ status: "error", error: "Wrong password!" });
            }
            if (errorMsg.toLowerCase().includes("user")) {
                return res.json({ status: "error", error: "Username not found!" });
            }
            
            return res.json({ status: "error", error: errorMsg });
        }

    } catch (error) {
        console.error("❌ Outer error:", error);
        return res.status(500).json({ status: "error", error: error.message });
    }
});

// ─── VERIFY 2FA ENDPOINT ────────────────────────
app.post('/verify_2fa', async (req, res) => {
    const { code, session_id } = req.body;
    const ig = clients[session_id];
    
    if (!ig) {
        return res.json({ status: "error", error: "No active session. Login first." });
    }

    try {
        // Method 1: Standard 2FA login
        try {
            await ig.account.twoFactorLogin({
                username: ig.state.cookieUserId ? String(ig.state.cookieUserId) : "",
                verificationCode: code,
                twoFactorIdentifier: ig.state.twoFactorIdentifier || "",
                trustThisDevice: "1",
                verificationMethod: "1"
            });
            
            const sessionData = await ig.state.serialize();
            const username = sessionData.cookiesMs?.match(/ds_user=([^;]+)/)?.[1] || "unknown";
            saveSession(username, sessionData);
            
            console.log(`✅ 2FA verified`);
            return res.json({ status: "ok", message: "2FA verified" });
        } catch (e1) {
            console.log("Method 1 failed:", e1.message);
        }

        // Method 2: Challenge code
        try {
            await ig.challenge.sendSecurityCode(code);
            const sessionData = await ig.state.serialize();
            const username = sessionData.cookiesMs?.match(/ds_user=([^;]+)/)?.[1] || "unknown";
            saveSession(username, sessionData);
            
            console.log(`✅ Challenge verified`);
            return res.json({ status: "ok", message: "Challenge verified" });
        } catch (e2) {
            console.log("Method 2 failed:", e2.message);
        }

        return res.json({ status: "error", error: "OTP verification failed. Try new code." });

    } catch (error) {
        console.error("❌ 2FA error:", error);
        return res.json({ status: "error", error: error.message });
    }
});

// ─── NOTIFICATIONS ENDPOINT ──────────────────────
app.post('/notifications', async (req, res) => {
    const { session_id } = req.body;
    const ig = clients[session_id];
    
    if (!ig) {
        return res.json({ status: "error", error: "Session expired. Login again." });
    }

    try {
        const feed = ig.feed.notifications();
        const items = await feed.items();
        
        const notifications = items.map(item => {
            const text = item.text || item.args?.text || item.args?.headline || "";
            const user = item.user?.username || "Unknown";
            const notiType = item.type || "unknown";
            
            // Ban check
            const textLower = text.toLowerCase();
            const typeLower = notiType.toLowerCase();
            const isBan = BAN_KEYWORDS.some(kw => textLower.includes(kw)) || 
                          ["ban", "block", "warning", "strike", "disabled"].some(bt => typeLower.includes(bt));

            return {
                id: String(item.id || item.pk || ""),
                type: notiType,
                text: text,
                timestamp: item.timestamp || item.created_at || "",
                user: user,
                is_ban_related: isBan
            };
        });

        console.log(`📬 Fetched ${notifications.length} notifications`);
        return res.json({ status: "ok", notifications: notifications });

    } catch (error) {
        console.error("❌ Noti error:", error.message);
        if (error.message.includes("login") || error.message.includes("auth")) {
            return res.json({ status: "error", error: "Session expired" });
        }
        return res.json({ status: "error", error: error.message });
    }
});

// ─── STATUS ENDPOINT ─────────────────────────────
app.post('/status', async (req, res) => {
    const { session_id } = req.body;
    const ig = clients[session_id];
    
    if (!ig) {
        return res.json({ status: "ok", alive: False, error: "No session" });
    }

    try {
        await ig.account.currentUser();
        return res.json({ status: "ok", alive: true });
    } catch (e) {
        return res.json({ status: "ok", alive: false, error: "Session expired" });
    }
});

// ─── SESSION HELPERS (In-Memory / File) ──────────
function saveSession(username, data) {
    try {
        // On Render, file system is temporary, but works within same deploy
        const fs = require('fs');
        fs.writeFileSync(`session_${username}.json`, JSON.stringify(data));
    } catch (e) {
        console.error("Save session error:", e);
    }
}

function loadSession(username) {
    try {
        const fs = require('fs');
        if (fs.existsSync(`session_${username}.json`)) {
            const data = fs.readFileSync(`session_${username}.json`, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {}
    return null;
}

// ─── START SERVER ────────────────────────────────
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`🟢 IG Notifier Backend running on port ${PORT}`);
});
