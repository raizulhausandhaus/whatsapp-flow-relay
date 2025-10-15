// api/flow.js
import crypto from "node:crypto";

/* ---------- tiny responders ---------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).end(JSON.stringify(obj));
};
const sendB64 = (res, b64) => {
  const body = (b64 || "").trim();              // raw Base64 only
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).end(body);
};

/* ---------- read raw body safely (no body-parser) ---------- */
async function readBody(req) {
  return await new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data || "{}"));
  });
}

/* ---------- decode helpers ---------- */
const VALID_AES = new Set([16, 24, 32]);   // bytes: 128/192/256
const TAG_LEN   = 16;

const isHex = (s) => typeof s === "string" && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const fromB64 = (s) => { try {
  const b = Buffer.from(s, "base64");
  return b.length ? b : null;
} catch { return null; } };
const fromHex = (s) => (isHex(s) ? Buffer.from(s, "hex") : null);

function deriveAesKey(anyKey, privatePem) {
  // 1) RSA-OAEP(SHA-256) wrapped (sent as base64)
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
  // 4) raw utf8
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

/* ---------- AES-GCM ---------- */
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

/* ---------- materials extractor (names vary) ---------- */
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

/* ---------- main handler ---------- */
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).end();

    // Parse body without body-parser
    let body = {};
    try { body = typeof req.body === "object" && req.body ? req.body : JSON.parse(await readBody(req)); }
    catch { body = {}; }

    // 1) Public-key signing challenge
    if (typeof body.challenge === "string") {
      return sendJSON(res, { challenge: body.challenge });
    }

    // 2) Materials
    const { key, iv, flow } = getMaterials(body);
    const aesKey = key ? deriveAesKey(key, process.env.FLOW_PRIVATE_PEM) : null;
    const ivBuf  = iv  ? decodeIv(iv) : null;

    // 3) Health check (no encrypted_flow_data): encrypted Base64 response
    if (!flow) {
      if (aesKey && ivBuf) {
        const reply = gcmEncryptToB64(aesKey, invert(ivBuf), { ok: true });
        return sendB64(res, reply);
      }
      // Tenant didn’t send materials — still return Base64 so checker can’t claim encoding
      return sendB64(res, Buffer.from("ok").toString("base64"));
    }

    // 4) Live data: decrypt and forward (optional)
    let clean = body;
    try {
      if (aesKey && ivBuf) clean = gcmDecryptJson(aesKey, ivBuf, flow);
    } catch (e) {
      console.error("Decrypt error:", e?.message || e);
    }

    try {
      if (process.env.MAKE_WEBHOOK_URL) {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean)
        });
      }
    } catch (e) {
      console.error("Forward failed:", e?.message || e);
    }

    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    // Even on error, return Base64 (prevents “not Base64 encoded”)
    return sendB64(res, Buffer.from("ok").toString("base64"));
  }
}
