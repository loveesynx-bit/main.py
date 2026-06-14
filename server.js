/*
╔══════════════════════════════════════════════════╗
║  🤖 IG Notifier — Node.js Backend (FIXED)       ║
║  All bugs fixed! No Python, No Rust, No Errors   ║
╚══════════════════════════════════════════════════
*/

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const { IgApiClient, IgCheckpointError, IgResponseError } = require('instagram-private-api');

const app = express();

// ── Middleware ──
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());

// ── In-memory storage ──
const clients = {};

// ── Ban Keywords ──
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

// ══════════════════════════════════════════════════
//  🏥 TEST ENDPOINT — Browser mein check karo
// ══════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({
    status: "ok",
    service: "IG Notifier Backend",
    active_sessions: Object.keys(clients).length,
    uptime: process.uptime(),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + "MB"
  });
});

app.get('/test', (req, res) => {
  res.json({ ok: true, message: "Backend is working!", time: new Date().toISOString() });
});

// ══════════════════════════════════════════════════
//  🔐 LOGIN ENDPOINT
// ══════════════════════════════════════════════════
app.post('/login', async (req, res) => {
  const { username, password, session_id } = req.body || {};

  // Validate input
  if (!username || !password || !session_id) {
    return res.json({ status: "error", error: "Missing username, password, or session_id" });
  }

  console.log(`🔐 Login attempt: @${username}`);

  try {
    const ig = new IgApiClient();
    ig.state.generateDevice(username);

    // ── Try existing session first ──
    const saved = loadSession(username);
    if (saved) {
      try {
        await ig.state.deserialize(saved);
        await ig.account.currentUser();
        clients[session_id] = { ig: ig, username: username, twoFactorInfo: null, password: password };
        console.log(`✅ Session login: @${username}`);
        return res.json({
          status: "ok",
          session_id: session_id,
          message: "Login successful (session)"
        });
      } catch (e) {
        console.log(`🔄 Session expired for @${username}`);
      }
    }

    // ── Fresh login ──
    try {
      // Pre-login flow (can fail, ignore errors)
      try { await ig.simulate.preLoginFlow(); } catch (e) { /* ignore */ }

      await ig.account.login(username, password);

      // Post-login flow (can fail, ignore errors)
      process.nextTick(async () => {
        try { await ig.simulate.postLoginFlow(); } catch (e) { /* ignore */ }
      });

      // Save session
      try {
        const sessionData = await ig.state.serialize();
        saveSession(username, sessionData);
      } catch (e) { /* ignore */ }

      clients[session_id] = { ig: ig, username: username, twoFactorInfo: null, password: password };
      console.log(`✅ Fresh login: @${username}`);

      return res.json({
        status: "ok",
        session_id: session_id,
        message: "Login successful"
      });

    } catch (e) {
      console.log(`❌ Login error type: ${e.name}`);

      // ── 2FA Required ──
      if (e.name === 'IgLoginTwoFactorRequiredError' || (e.response && e.response.body && e.response.body.two_factor_info)) {
        const body = e.response.body || {};
        const info = body.two_factor_info || {};
        const method = info.totp_two_factor_on ? "totp" : "sms";
        const phone = info.obfuscated_phone_number || "";
        const twoFactorId = info.two_factor_identifier || "";

        console.log(`🔐 2FA required: @${username}, method=${method}`);

        clients[session_id] = {
          ig: ig,
          username: username,
          password: password,
          twoFactorInfo: {
            two_factor_identifier: twoFactorId,
            username: username,
            method: method
          }
        };

        return res.json({
          status: "ok",
          session_id: session_id,
          needs_2fa: true,
          two_factor_method: method,
          obfuscated_phone: phone,
          message: "2FA verification required"
        });
      }

      // ── Challenge Required ──
      if (e instanceof IgCheckpointError || (e.response && e.response.body && e.response.body.challenge)) {
        console.log(`⚠️ Challenge required: @${username}`);

        clients[session_id] = {
          ig: ig,
          username: username,
          password: password,
          twoFactorInfo: null,
          challengeNeeded: true
        };

        // Try to auto-resolve challenge
        try {
          await ig.challenge.auto(true);
          console.log(`📧 Challenge code sent to email/phone`);
        } catch (chErr) {
          console.log(`⚠️ Challenge auto failed: ${chErr.message}`);
        }

        return res.json({
          status: "ok",
          session_id: session_id,
          challenge_required: true,
          message: "Challenge verification required. Check email/SMS for code."
        });
      }

      // ── Bad Password ──
      if (e.name === 'IgUserHasLoggedOutError' || (e.response && e.response.statusCode === 400)) {
        const body = e.response ? e.response.body : {};
        if (body.error_type === 'bad_password' || (body.message && body.message.toLowerCase().includes('password'))) {
          return res.json({ status: "error", error: "Wrong password!" });
        }
      }

      // ── Rate limit / other errors ──
      const errorMsg = (e.response && e.response.body && e.response.body.message) || e.message || "Login failed";
      console.log(`❌ Login failed: @${username} - ${errorMsg}`);

      return res.json({ status: "error", error: String(errorMsg).substring(0, 200) });
    }

  } catch (outerError) {
    console.error("❌ Outer login error:", outerError);
    return res.json({ status: "error", error: String(outerError.message).substring(0, 200) });
  }
});

// ══════════════════════════════════════════════════
//  🔐 VERIFY 2FA ENDPOINT
// ══════════════════════════════════════════════════
app.post('/verify_2fa', async (req, res) => {
  const { code, session_id } = req.body || {};
  const data = clients[session_id];

  if (!data) {
    return res.json({ status: "error", error: "No active session. Send /start to login again." });
  }

  if (!code) {
    return res.json({ status: "error", error: "No OTP code provided." });
  }

  const { ig, username, twoFactorInfo, challengeNeeded } = data;

  console.log(`🔐 2FA verify attempt: @${username}, code=${code}`);

  // ── Method 1: 2FA Login ──
  if (twoFactorInfo && twoFactorInfo.two_factor_identifier) {
    try {
      await ig.account.twoFactorLogin({
        username: twoFactorInfo.username || username,
        verificationCode: String(code).replace(/\s/g, ""),
        twoFactorIdentifier: twoFactorInfo.two_factor_identifier,
        trustThisDevice: "1",
        verificationMethod: "1"
      });

      // Save session
      try {
        const sessionData = await ig.state.serialize();
        saveSession(username, sessionData);
      } catch (e) { /* ignore */ }

      clients[session_id] = { ig: ig, username: username, twoFactorInfo: null, password: data.password };
      console.log(`✅ 2FA verified: @${username}`);

      return res.json({ status: "ok", message: "2FA verified successfully" });
    } catch (e) {
      console.log(`2FA method 1 failed: ${e.message}`);
    }
  }

  // ── Method 2: Challenge Security Code ──
  if (challengeNeeded) {
    try {
      await ig.challenge.sendSecurityCode(String(code).replace(/\s/g, ""));

      try {
        const sessionData = await ig.state.serialize();
        saveSession(username, sessionData);
      } catch (e) { /* ignore */ }

      clients[session_id] = { ig: ig, username: username, twoFactorInfo: null, password: data.password };
      console.log(`✅ Challenge verified: @${username}`);

      return res.json({ status: "ok", message: "Challenge verified successfully" });
    } catch (e) {
      console.log(`Challenge method failed: ${e.message}`);
    }
  }

  // ── Method 3: Re-login with verification code ──
  try {
    const ig2 = new IgApiClient();
    ig2.state.generateDevice(username);
    try { await ig2.simulate.preLoginFlow(); } catch (e) { /* ignore */ }
    await ig2.account.login(username, data.password, String(code).replace(/\s/g, ""));

    try {
      const sessionData = await ig2.state.serialize();
      saveSession(username, sessionData);
    } catch (e) { /* ignore */ }

    clients[session_id] = { ig: ig2, username: username, twoFactorInfo: null, password: data.password };
    console.log(`✅ Re-login with code: @${username}`);

    return res.json({ status: "ok", message: "2FA verified successfully" });
  } catch (e) {
    console.log(`Re-login method failed: ${e.message}`);
  }

  return res.json({ status: "error", error: "OTP verification failed. Try a new code or /start again." });
});

// ══════════════════════════════════════════════════
//  📬 NOTIFICATIONS ENDPOINT
// ══════════════════════════════════════════════════
app.post('/notifications', async (req, res) => {
  const { session_id } = req.body || {};
  const data = clients[session_id];

  if (!data) {
    return res.json({ status: "error", error: "Session expired. Login again." });
  }

  const { ig } = data;

  try {
    // Use newsInbox feed
    const inboxFeed = ig.feed.newsInbox();
    const items = await inboxFeed.items();

    const notifications = [];
    const seenPk = new Set();

    for (const item of items) {
      try {
        const pk = String(item.id || item.pk || "");
        if (!pk || seenPk.has(pk)) continue;
        seenPk.add(pk);

        // Extract text
        let text = item.text || "";
        if (!text && item.args) {
          if (typeof item.args.text === 'string') text = item.args.text;
          else if (typeof item.args.headline === 'string') text = item.args.headline;
          else if (typeof item.args.description === 'string') text = item.args.description;
        }

        // Extract user
        const user = (item.user && item.user.username) ? item.user.username : "Unknown";

        // Extract type
        const notiType = item.type || "unknown";

        // Ban check
        const textLower = String(text).toLowerCase();
        const typeLower = String(notiType).toLowerCase();
        const isBan = BAN_KEYWORDS.some(kw => textLower.includes(kw)) ||
                      ["ban", "block", "warning", "strike", "disabled"].some(bt => typeLower.includes(bt));

        notifications.push({
          id: pk,
          type: notiType,
          text: String(text),
          timestamp: item.timestamp || "",
          user: user,
          is_ban_related: isBan
        });
      } catch (parseErr) {
        // Skip malformed items
      }
    }

    console.log(`📬 ${notifications.length} notifications for @${data.username}`);
    return res.json({ status: "ok", notifications: notifications });

  } catch (error) {
    console.error(`❌ Noti error: ${error.message}`);

    if (error.message && (error.message.includes("login") || error.message.includes("auth") || error.message.includes("session"))) {
      return res.json({ status: "error", error: "Session expired. Login again." });
    }

    return res.json({ status: "error", error: String(error.message).substring(0, 200) });
  }
});

// ══════════════════════════════════════════════════
//  📊 STATUS ENDPOINT
// ══════════════════════════════════════════════════
app.post('/status', async (req, res) => {
  const { session_id } = req.body || {};
  const data = clients[session_id];

  if (!data) {
    return res.json({ status: "ok", alive: false, error: "No session" });
  }

  try {
    await data.ig.account.currentUser();
    return res.json({ status: "ok", alive: true, username: data.username });
  } catch (e) {
    return res.json({ status: "ok", alive: false, error: "Session expired" });
  }
});

// ══════════════════════════════════════════════════
//  💾 SESSION HELPERS
// ══════════════════════════════════════════════════
function saveSession(username, data) {
  try {
    fs.writeFileSync(`/tmp/session_${username}.json`, JSON.stringify(data));
    console.log(`💾 Session saved: @${username}`);
  } catch (e) {
    console.log(`⚠️ Save failed: ${e.message}`);
  }
}

function loadSession(username) {
  try {
    const path = `/tmp/session_${username}.json`;
    if (fs.existsSync(path)) {
      const data = JSON.parse(fs.readFileSync(path, 'utf8'));
      console.log(`📂 Session loaded: @${username}`);
      return data;
    }
  } catch (e) {
    console.log(`⚠️ Load failed: ${e.message}`);
  }
  return null;
}

// ══════════════════════════════════════════════════
//  🚀 START SERVER
// ══════════════════════════════════════════════════
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════╗');
  console.log('║  🟢 IG Notifier Backend Running!     ║');
  console.log(`║  Port: ${PORT}                          ║`);
  console.log('╚══════════════════════════════════════╝');
  console.log('');
});
