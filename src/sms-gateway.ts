#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════
//  SELF-HOSTED SMS GATEWAY
//  Sends real SMS via your Android phone's SIM card over WiFi.
//
//  SETUP (5 minutes, one-time):
//  ─────────────────────────────────────────────────────────────────
//  1. On your Android phone install from F-Droid (NOT Play Store):
//       • Termux          – https://f-droid.org/packages/com.termux/
//       • Termux:API      – https://f-droid.org/packages/com.termux.api/
//
//  2. Open Termux, run:
//       pkg update && pkg install termux-api
//
//  3. In Termux start this gateway:
//       GATEWAY_TOKEN=mysecret123 node src/sms-gateway.ts
//
//  4. In the admin app → Settings → SMS Gateway:
//       Provider    :  Android Phone Gateway
//       Gateway URL :  http://<PHONE_IP>:8082
//       Password    :  mysecret123
//       Save → Send Test
//
//  Your phone IP is shown in Termux:  curl ifconfig.me
//  Or in WiFi settings:  Settings → Network → your IP
// ═══════════════════════════════════════════════════════════════════

import http from "http";
import { exec } from "child_process";

const PORT       = parseInt(process.argv[2] || process.env.PORT || "8082", 10);
const TOKEN      = process.env.GATEWAY_TOKEN || "";
const LOG_PREFIX = "[sms-gateway]";

function log(...a: unknown[]) { console.log(LOG_PREFIX, new Date().toISOString().slice(11, 19), ...a); }

function sendSms(number: string, message: string): Promise<{ success: boolean }> {
  return new Promise((resolve, reject) => {
    // Strip spaces, ensure + prefix for international
    let num = String(number).replace(/[\s\-()]/g, "");
    if (/^\d{10}$/.test(num)) num = "+91" + num;          // Indian 10-digit → +91
    else if (!num.startsWith("+")) num = "+" + num;

    // Sanitize message for shell
    const safe = message.replace(/'/g, "'\\''");
    const cmd  = `termux-sms-send -n '${num}' '${safe}'`;

    log("Sending to", num, `(${message.length} chars)`);
    exec(cmd, { timeout: 15000 }, (err, _stdout, _stderr) => {
      if (err) {
        log("FAILED:", err.message);
        return reject(err);
      }
      log("Sent OK to", num);
      resolve({ success: true });
    });
  });
}

function readBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); }
      catch { reject(new Error("Invalid JSON")); }
    });
  });
}

function json(res: http.ServerResponse, code: number, obj: any) {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    return res.end();
  }

  // Health check
  if (req.method === "GET" && (req.url === "/" || req.url === "/health")) {
    return json(res, 200, { status: "ok", gateway: "sms-gateway", uptime: process.uptime() | 0 });
  }

  // All POST routes require auth
  if (req.method !== "POST") return json(res, 404, { error: "Not found" });

  if (TOKEN) {
    const auth = req.headers.authorization || "";
    let provided = "";
    if (auth.startsWith("Bearer ")) {
      provided = auth.slice(7).trim();
    } else if (auth.startsWith("Basic ")) {
      // Main app sends Basic auth with sms:<password> encoded
      try { provided = Buffer.from(auth.slice(6).trim(), "base64").toString().split(":")[1] || ""; } catch {}
    }
    if (provided !== TOKEN) return json(res, 401, { error: "Unauthorized" });
  }

  try {
    // Send single SMS
    if (req.url === "/api/send" || req.url === "/message/send") {
      const { number, phoneNumbers, message } = await readBody(req);
      const target = number || (Array.isArray(phoneNumbers) ? phoneNumbers[0] : "");
      if (!target || !message) return json(res, 400, { error: "Missing number or message" });
      await sendSms(target, message);
      return json(res, 200, { success: true });
    }

    // Batch send
    if (req.url === "/api/send-batch") {
      const { messages } = await readBody(req);
      if (!Array.isArray(messages) || messages.length === 0)
        return json(res, 400, { error: "Provide messages array" });
      let sent = 0, failed = 0;
      for (const { number, message } of messages) {
        try { await sendSms(number, message); sent++; }
        catch { failed++; }
      }
      return json(res, 200, { success: true, sent, failed });
    }

    return json(res, 404, { error: "Unknown endpoint" });
  } catch (e: any) {
    log("Error:", e.message);
    return json(res, 500, { error: e.message });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  log(`Listening on http://0.0.0.0:${PORT}`);
  log(TOKEN ? "Auth: enabled" : "Auth: DISABLED (set GATEWAY_TOKEN for security)");
});