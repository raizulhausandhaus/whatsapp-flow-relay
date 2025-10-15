// api/flow.js
import crypto from "node:crypto";

/* --------------------- config / logging --------------------- */
const LOG_ON = process.env.LOG_REQUEST !== "0";
const log = (...args) => { if (LOG_ON) console.log(...args); };

/* --------------------- tiny responders ---------------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).end(JSON.stringify(obj));
};
const sendB64 = (res, b64) => {
  const body = (b64 || "").trim();           // raw Base64 only (no quotes)
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).end(body);
};

/* ------------------ read raw body (no parsers) --------------- */
async function readBody(req) {
  return await new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data || "{}"));
  });
}

/* ------------------ decode helpers / crypto ------------------ */
const VALID_AES = new Set([16, 24, 32]); // 128/192/256 bytes
const TAG_LEN   = 16;

const isHex  = (s) => typeof s === "string" && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const fromB64 = (s) => { try { const b = Buffer.from(s, "base64"); return b.length ? b : null; } catch { return null; } };
const fromHex = (s) => (isHex(s) ? Buffer.from(s, "hex") : null);

function deriveAesKey(anyKey, privatePem) {
  // 1) Try RSA-OAEP(SHA-256) wrapped (base64)
  const wrapped = fromB64(anyKey);
  if (wrapped && privatePem) {
    try {
      const k = crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, wrapped);
      if (VALID_AES.has(k.length)) return k;
    } catch {}
  }
  // 2) raw base64
  if (wrapped && VALID_AES.has(wrapped.length)) return wrapped;
  // 3) hex
  const hx = fromHex(anyKey);
  if (hx && VALID_AES.has(hx.length)) return hx;
  // 4) raw utf8 (very rare)
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

function gcmEncryptToB64(key, iv, obj) {
  const bits = key.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, key, iv);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
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

/* -------- materials extractor (cover common name variants) --- */
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

/* -------------------------- main handler -------------------------- */
export default async function handler(req, res) {
  const t0 = Date.now();
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).end();

    // --- Raw body parse (no body-parser) ---
    let bodyStr = await readBody(req);
    let body = {};
    try { body = JSON.parse(bodyStr); } catch { body = {}; }

    // --- Logging (safe) ---
    log("FLOW: recv", {
      method: req.method,
      url: req.url,
      contentType: req.headers["content-type"],
      contentLength: req.headers["content-length"],
    });
    log("FLOW: body keys", Object.keys(body || {}));
    if (body?.data && typeof body.data === "object") {
      log("FLOW: body.data keys", Object.keys(body.data));
    }

    // 0) Ignore Data API "ping" messages (Connect Meta app step)
    if (body?.action === "ping") {
      log("FLOW: handled ping");
      return res.status(200).end();
    }

    // 1) Public-key signing challenge
    if (typeof body.challenge === "string") {
      log("FLOW: challenge echo");
      return sendJSON(res, { challenge: body.challenge });
    }

    // 2) Materials
    const { key, iv, flow } = getMaterials(body);
    const aesKey = key ? deriveAesKey(key, process.env.FLOW_PRIVATE_PEM) : null;
    const ivBuf  = iv  ? decodeIv(iv) : null;

    log("FLOW: materials", {
      hasEncryptedFlowData: !!flow,
      hasEncryptedKey: !!key,
      hasIV: !!iv,
      aesKeyLen: aesKey ? aesKey.length : null,
      ivLen: ivBuf ? ivBuf.length : null,
    });

    // 3) Health check (no encrypted_flow_data): encrypted Base64 response
    if (!flow) {
      if (aesKey && ivBuf) {
        const reply = gcmEncryptToB64(aesKey, invert(ivBuf), { ok: true });
        log("FLOW: HC ENCRYPTED reply length (base64 chars)", reply.length);
        const r = sendB64(res, reply);
        log("FLOW: HC encrypted completed in ms", Date.now() - t0);
        return r;
      }
      // Tenant didn’t send materials — still return Base64
      const fallback = Buffer.from("ok").toString("base64"); // b2s=
      log("FLOW: HC FALLBACK base64", fallback);
      const r = sendB64(res, fallback);
      log("FLOW: HC fallback completed in ms", Date.now() - t0);
      return r;
    }

    // 4) Live data: decrypt, forward (optional), ack
    let clean = body;
    try {
      if (aesKey && ivBuf) {
        clean = gcmDecryptJson(aesKey, ivBuf, flow);
        log("FLOW: data_exchange decrypted keys", Object.keys(clean || {}));
      } else {
        log("FLOW: data_exchange without materials (left body as-is)");
      }
    } catch (e) {
      log("FLOW: Decrypt error", e?.message || e);
    }

    try {
      if (process.env.MAKE_WEBHOOK_URL) {
        const resp = await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean),
        });
        log("FLOW: forwarded to Power Automate status", resp.status);
      }
    } catch (e) {
      log("FLOW: Forward failed", e?.message || e);
    }

    log("FLOW: data_exchange completed in ms", Date.now() - t0);
    return res.status(200).end();
  } catch (e) {
    log("FLOW: Handler error", e?.message || e);
    // Even on error, return Base64 to avoid “not Base64” complaint
    const fallback = Buffer.from("ok").toString("base64");
    return sendB64(res, fallback);
  }
}
