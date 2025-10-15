// api/flow.js
import crypto from "node:crypto";

/* --------------------- logging --------------------- */
const LOG_ON = process.env.LOG_REQUEST !== "0";
const log = (...args) => { if (LOG_ON) console.log(...args); };

/* ---------------- responders ---------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).end(JSON.stringify(obj));
};
const sendB64 = (res, b64) => {
  const body = (b64 || "").trim();
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).end(body);
};

/* --------------- raw body reader --------------- */
async function readBody(req) {
  return await new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data || "{}"));
  });
}

/* --------------- crypto helpers --------------- */
const VALID_AES = new Set([16, 24, 32]); // bytes
const TAG_LEN = 16;

const isHex  = (s) => typeof s === "string" && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const fromB64 = (s) => { try { const b = Buffer.from(s, "base64"); return b.length ? b : null; } catch { return null; } };
const fromHex = (s) => (isHex(s) ? Buffer.from(s, "hex") : null);

function deriveAesKey(anyKey, privatePem) {
  // RSA-OAEP-SHA256?
  const wrapped = fromB64(anyKey);
  if (wrapped && privatePem) {
    try {
      const k = crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, wrapped);
      if (VALID_AES.has(k.length)) return k;
    } catch {}
  }
  // raw Base64?
  if (wrapped && VALID_AES.has(wrapped.length)) return wrapped;
  // hex?
  const hx = fromHex(anyKey);
  if (hx && VALID_AES.has(hx.length)) return hx;
  // raw utf8 (rare)
  if (typeof anyKey === "string") {
    const raw = Buffer.from(anyKey, "utf8");
    if (VALID_AES.has(raw.length)) return raw;
  }
  return null;
}

function decodeIv(anyIv) {
  const b64 = fromB64(anyIv); if (b64 && (b64.length === 12 || b64.length === 16)) return b64;
  const hx  = fromHex(anyIv); if (hx  && (hx.length  === 12 || hx.length  === 16)) return hx;
  if (typeof anyIv === "string") {
    const raw = Buffer.from(anyIv, "utf8");
    if (raw.length === 12 || raw.length === 16) return raw;
  }
  return null;
}

const invert = (buf) => { const o = Buffer.alloc(buf.length); for (let i=0;i<buf.length;i++) o[i]=buf[i]^0xff; return o; };

function gcmEncryptToB64(key, iv, payload) {
  const bits = key.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, key, iv);
  const data =
    typeof payload === "string"
      ? Buffer.from(payload, "utf8")
      : Buffer.from(JSON.stringify(payload), "utf8");
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, tag]).toString("base64"); // cipher||tag
}

function gcmDecryptJson(key, iv, cipherPlusTagB64) {
  const data = Buffer.from(cipherPlusTagB64, "base64");
  if (data.length <= TAG_LEN) throw new Error("cipher too short");
  const tag = data.subarray(data.length - TAG_LEN);
  const ct  = data.subarray(0, data.length - TAG_LEN);
  const bits = key.length * 8;
  const dec = crypto.createDecipheriv(`aes-${bits}-gcm`, key, iv);
  dec.setAuthTag(tag);
  const pt = Buffer.concat([dec.update(ct), dec.final()]);
  return JSON.parse(pt.toString("utf8"));
}

/* --------------- materials extractor --------------- */
function getMaterials(body) {
  const key =
    body?.encrypted_aes_key ??
    body?.encrypted_session_key ??
    body?.encrypted_key ??
    body?.aes_key ??
    body?.data?.encrypted_aes_key ??
    body?.data?.encrypted_session_key ??
    body?.data?.aes_key;

  const iv =
    body?.initial_vector ??
    body?.initial_iv ??
    body?.iv ??
    body?.data?.initial_vector ??
    body?.data?.iv;

  const flow =
    body?.encrypted_flow_data ??
    body?.data?.encrypted_flow_data;

  return { key, iv, flow };
}

/* --------------- navigation helper --------------- */
/** Return the next screen id (string) based on the decrypted payload */
function decideNextScreen(clean) {
  const screen = clean?.screen;
  const data = clean?.data || {};

  // Screen: ask_experience  -> Yes -> ask_nps,  No -> end_no
  if (screen === "ask_experience") {
    if (data.consent === "yes_experience") return "ask_nps";
    if (data.consent === "no_experience")  return "end_no";
  }

  // Screen: ask_nps -> score >= 8 -> end_positive ; else -> discuss_invite
  if (screen === "ask_nps") {
    const s = Number(data.score ?? data.nps_score ?? "-1");
    if (!Number.isNaN(s) && s >= 8) return "end_positive";
    return "discuss_invite";
  }

  // Screen: discuss_invite  -> discuss_yes -> end_discuss_yes ; discuss_no -> end_no
  if (screen === "discuss_invite") {
    if (data.discuss === "discuss_yes") return "end_discuss_yes";
    if (data.discuss === "discuss_no")  return "end_no";
  }

  // Fallback: stay on same screen to avoid client error
  return screen || "ask_experience";
}

/* -------------------------- main handler -------------------------- */
export default async function handler(req, res) {
  const t0 = Date.now();
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).end();

    const bodyStr = await readBody(req);
    let body = {};
    try { body = JSON.parse(bodyStr); } catch { body = {}; }

    log("FLOW: recv", {
      method: req.method, url: req.url,
      contentType: req.headers["content-type"],
      contentLength: req.headers["content-length"]
    });
    log("FLOW: body keys", Object.keys(body || {}));
    if (body?.data && typeof body.data === "object") {
      log("FLOW: body.data keys", Object.keys(body.data));
    }

    // Ignore plaintext Data API ping (Connect Meta app)
    if (body?.action === "ping" && !body?.encrypted_aes_key && !body?.encrypted_flow_data) {
      log("FLOW: plaintext ping -> 200");
      return res.status(200).end();
    }

    // Public-key signing challenge
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
      aesKeyLen: aesKey ? aesKey.length : null,
      ivLen: ivBuf ? ivBuf.length : null
    });

    // Health check (no encrypted_flow_data) → ENCRYPT {"data":{"status":"active"}}
    const HC_OK_OBJECT = { data: { status: "active" } };
    if (!flow) {
      const reply =
        aesKey && ivBuf
          ? gcmEncryptToB64(aesKey, invert(ivBuf), HC_OK_OBJECT)
          : Buffer.from(JSON.stringify(HC_OK_OBJECT)).toString("base64");
      log("FLOW: HC reply len", reply.length);
      log("FLOW: HC done in ms", Date.now() - t0);
      return sendB64(res, reply);
    }

    // encrypted_flow_data present → decrypt
    let clean = {};
    try {
      if (aesKey && ivBuf) {
        clean = gcmDecryptJson(aesKey, ivBuf, flow);
        log("FLOW: decrypted keys", Object.keys(clean || {}));
        try { log("FLOW: decrypted payload preview", JSON.stringify(clean).slice(0, 1500)); } catch {}
      } else {
        log("FLOW: cannot decrypt (missing materials)");
        clean = {};
      }
    } catch (e) {
      log("FLOW: decrypt error", e?.message || e);
      clean = {};
    }

    // Probe wrapped in crypto? (Return HC ok)
    if (clean && (clean.action === "ping" || clean.action === "health_check")) {
      const reply =
        aesKey && ivBuf
          ? gcmEncryptToB64(aesKey, invert(ivBuf), HC_OK_OBJECT)
          : Buffer.from(JSON.stringify(HC_OK_OBJECT)).toString("base64");
      log("FLOW: PROBE reply (encrypted) len", reply.length, "action", clean.action);
      return sendB64(res, reply);
    }

    /* ---------- DATA EXCHANGE: compute next screen & return navigate ---------- */
    const nextScreen = decideNextScreen(clean);
    const navigatePayload = {
      version: clean?.version || "3.0",
      screen: nextScreen,
      // You can pass data to next screen here if needed:
      data: {}
      // Optional flags supported by many tenants:
      // close_flow: false,
      // error_message: undefined
    };

    const reply =
      aesKey && ivBuf
        ? gcmEncryptToB64(aesKey, invert(ivBuf), navigatePayload)
        : Buffer.from(JSON.stringify(navigatePayload)).toString("base64");

    log("FLOW: NAVIGATE →", nextScreen, "replyLen", reply.length);

    // Fire-and-forget forward to Power Automate
    try {
      if (process.env.MAKE_WEBHOOK_URL) {
        fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean)
        }).catch(() => {});
      }
    } catch {/* ignore */}

    return sendB64(res, reply);
  } catch (e) {
    log("FLOW: handler error", e?.message || e);
    // Safety: keep client alive
    const fallback = Buffer.from(JSON.stringify({ data: { status: "success" } })).toString("base64");
    return sendB64(res, fallback);
  }
}
