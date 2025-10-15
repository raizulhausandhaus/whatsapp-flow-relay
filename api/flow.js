// api/flow.js
import crypto from "node:crypto";

/* ---------------- logging ---------------- */
const LOG_ON = process.env.LOG_REQUEST !== "0";
const log = (...a) => { if (LOG_ON) console.log(...a); };

/* --------------- helpers ---------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).end(JSON.stringify(obj));
};
const sendB64 = (res, b64) => {
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).end((b64 || "").trim());
};
async function readBody(req) {
  return await new Promise((resolve) => {
    let s = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (s += c));
    req.on("end", () => resolve(s || "{}"));
  });
}

/* --------------- crypto ------------------ */
const VALID_AES = new Set([16, 24, 32]); // bytes (128/192/256)
const TAG_LEN = 16;

const isHex = (s) => typeof s === "string" && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const fromB64 = (s) => { try { const b = Buffer.from(s, "base64"); return b.length ? b : null; } catch { return null; } };
const fromHex = (s) => (isHex(s) ? Buffer.from(s, "hex") : null);

function deriveAesKey(k, pem) {
  const wrapped = fromB64(k);
  if (wrapped && pem) {
    try {
      const d = crypto.privateDecrypt({ key: pem, oaepHash: "sha256" }, wrapped);
      if (VALID_AES.has(d.length)) return d;
    } catch {}
  }
  if (wrapped && VALID_AES.has(wrapped.length)) return wrapped;
  const hx = fromHex(k);
  if (hx && VALID_AES.has(hx.length)) return hx;
  if (typeof k === "string") {
    const raw = Buffer.from(k, "utf8");
    if (VALID_AES.has(raw.length)) return raw;
  }
  return null;
}
function decodeIv(iv) {
  const b64 = fromB64(iv); if (b64 && (b64.length === 12 || b64.length === 16)) return b64;
  const hx  = fromHex(iv); if (hx  && (hx.length  === 12 || hx.length  === 16)) return hx;
  if (typeof iv === "string") {
    const raw = Buffer.from(iv, "utf8");
    if (raw.length === 12 || raw.length === 16) return raw;
  }
  return null;
}
const invert = (buf) => { const o = Buffer.alloc(buf.length); for (let i=0;i<buf.length;i++) o[i]=buf[i]^0xff; return o; };

function gcmEncryptToB64(key, iv, payload) {
  const bits = key.length * 8;
  const c = crypto.createCipheriv(`aes-${bits}-gcm`, key, iv);
  const data = Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload), "utf8");
  const ct = Buffer.concat([c.update(data), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([ct, tag]).toString("base64");
}
function gcmDecryptJson(key, iv, b64) {
  const data = Buffer.from(b64, "base64");
  if (data.length <= TAG_LEN) throw new Error("cipher too short");
  const tag = data.subarray(data.length - TAG_LEN);
  const ct  = data.subarray(0, data.length - TAG_LEN);
  const bits = key.length * 8;
  const d = crypto.createDecipheriv(`aes-${bits}-gcm`, key, iv);
  d.setAuthTag(tag);
  const pt = Buffer.concat([d.update(ct), d.final()]);
  return JSON.parse(pt.toString("utf8"));
}

/* --------------- request materials --------------- */
function getMaterials(b) {
  const key =
    b?.encrypted_aes_key ??
    b?.encrypted_session_key ??
    b?.encrypted_key ??
    b?.aes_key ??
    b?.data?.encrypted_aes_key ??
    b?.data?.encrypted_session_key ??
    b?.data?.aes_key;

  const iv =
    b?.initial_vector ??
    b?.initial_iv ??
    b?.iv ??
    b?.data?.initial_vector ??
    b?.data?.iv;

  const flow =
    b?.encrypted_flow_data ??
    b?.data?.encrypted_flow_data;

  return { key, iv, flow };
}

/* --------------- flow logic --------------- */
const TERMINAL_SCREENS = new Set(["end_no", "end_positive", "end_discuss_yes"]);
const START_SCREEN_ID = "ask_nps"; // <- your start screen

function decideNextScreen(clean) {
  const scr = clean?.screen;
  const d = clean?.data || {};

  if (scr === "ask_nps") {
    const s = Number(d.score ?? d.nps_score ?? "-1");
    if (!Number.isNaN(s) && s >= 8) return "end_positive";
    return "discuss_invite";
  }
  if (scr === "discuss_invite") {
    if (d.discuss === "discuss_yes") return "end_discuss_yes";
    if (d.discuss === "discuss_no")  return "end_no";
  }
  return scr || START_SCREEN_ID;
}

/* ------------------- handler ------------------- */
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).end();

    const bodyStr = await readBody(req);
    let body = {};
    try { body = JSON.parse(bodyStr); } catch {}

    log("FLOW: recv", {
      method: req.method, url: req.url,
      contentType: req.headers["content-type"],
      contentLength: req.headers["content-length"]
    });
    log("FLOW: body keys", Object.keys(body || {}));

    // Plain ping from "Connect Meta app"
    if (body?.action === "ping" && !body?.encrypted_aes_key && !body?.encrypted_flow_data) {
      log("FLOW: plaintext ping -> 200");
      return res.status(200).end();
    }

    // Key-signing challenge
    if (typeof body.challenge === "string") {
      log("FLOW: challenge echo");
      return sendJSON(res, { challenge: body.challenge });
    }

    // Materials
    const { key, iv, flow } = getMaterials(body);
    const aesKey = key ? deriveAesKey(key, process.env.FLOW_PRIVATE_PEM) : null;
    const ivBuf  = iv  ? decodeIv(iv) : null;

    log("FLOW: materials", {
      hasEncryptedFlowData: !!flow, hasEncryptedKey: !!key, hasIV: !!iv,
      aesKeyLen: aesKey?.length || null, ivLen: ivBuf?.length || null
    });

    // Health check (no encrypted_flow_data) -> encrypted {"data":{"status":"active"}}
    const HC_OK = { data: { status: "active" } };
    if (!flow) {
      const reply = aesKey && ivBuf
        ? gcmEncryptToB64(aesKey, invert(ivBuf), HC_OK)
        : Buffer.from(JSON.stringify(HC_OK)).toString("base64");
      return sendB64(res, reply);
    }

    // Decrypt real request
    let clean = {};
    try {
      if (aesKey && ivBuf) {
        clean = gcmDecryptJson(aesKey, ivBuf, flow);
        log("FLOW: decrypted keys", Object.keys(clean || {}));
        try { log("FLOW: decrypted payload preview", JSON.stringify(clean).slice(0, 1500)); } catch {}
      } else {
        log("FLOW: cannot decrypt (missing materials)");
      }
    } catch (e) {
      log("FLOW: decrypt error", e?.message || e);
    }

    // --- RUNTIME START PING: no screen provided → navigate to first screen
    if (clean && clean.action === "ping" && !clean.screen) {
      const payload = {
        version: clean?.version || "3.0",
        screen: START_SCREEN_ID,
        data: {}
      };
      const reply = aesKey && ivBuf
        ? gcmEncryptToB64(aesKey, invert(ivBuf), payload)
        : Buffer.from(JSON.stringify(payload)).toString("base64");
      log("FLOW: START → navigate to", START_SCREEN_ID);
      return sendB64(res, reply);
    }

    // Encrypted health_check (explicit)
    if (clean && clean.action === "health_check") {
      const reply = aesKey && ivBuf
        ? gcmEncryptToB64(aesKey, invert(ivBuf), HC_OK)
        : Buffer.from(JSON.stringify(HC_OK)).toString("base64");
      log("FLOW: PROBE reply (HC) len", reply.length);
      return sendB64(res, reply);
    }

    // If the *request* came from a terminal screen (Finish button), close now
    if (TERMINAL_SCREENS.has(clean?.screen)) {
      const closePayload = {
        version: clean?.version || "3.0",
        data: { status: "success" },
        close_flow: true
      };
      const closeReply = aesKey && ivBuf
        ? gcmEncryptToB64(aesKey, invert(ivBuf), closePayload)
        : Buffer.from(JSON.stringify(closePayload)).toString("base64");
      log("FLOW: CLOSE reply (from terminal screen)", clean?.screen, "len", closeReply.length);
      return sendB64(res, closeReply);
    }

    // Otherwise compute next; if next is terminal, end immediately
    const next = decideNextScreen(clean);
    const nextIsTerminal = TERMINAL_SCREENS.has(next);

    const payload = nextIsTerminal
      ? { version: clean?.version || "3.0", data: { status: "success" }, close_flow: true }
      : { version: clean?.version || "3.0", screen: next, data: {} };

    const reply = aesKey && ivBuf
      ? gcmEncryptToB64(aesKey, invert(ivBuf), payload)
      : Buffer.from(JSON.stringify(payload)).toString("base64");

    log("FLOW:", nextIsTerminal ? `NAVIGATE → terminal close ${next}` : `NAVIGATE → ${next}`);

    // Optional forward to Power Automate (non-blocking)
    try {
      if (process.env.MAKE_WEBHOOK_URL) {
        fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean)
        }).catch(() => {});
      }
    } catch {}

    return sendB64(res, reply);
  } catch (e) {
    log("FLOW: handler error", e?.message || e);
    const fallback = Buffer.from(JSON.stringify({ data: { status: "success" } })).toString("base64");
    return sendB64(res, fallback);
  }
}
