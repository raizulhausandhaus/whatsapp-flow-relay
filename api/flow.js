import crypto from "node:crypto";

// utils
const sendJSON = (res, obj) => { res.setHeader("Content-Type","application/json"); return res.status(200).send(JSON.stringify(obj)); };
const sendText = (res, txt) => { res.setHeader("Content-Type","text/plain"); return res.status(200).send(txt); };
const b64 = (x) => Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

// --- AES/GCM helpers ---
const VALID_AES = new Set([16, 24, 32]); // AES-128/192/256

function rsaDecryptMaybe(encryptedKeyB64, privatePem) {
  try {
    const enc = Buffer.from(encryptedKeyB64, "base64");
    const key = crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, enc);
    return key; // Buffer
  } catch (e) {
    return null;
  }
}

function parseAesKey(encryptedKeyB64, privatePem) {
  // 1) Try RSA decrypt
  let k = null;
  if (privatePem) k = rsaDecryptMaybe(encryptedKeyB64, privatePem);
  if (k && VALID_AES.has(k.length)) return k;

  // 2) Fall back: treat input as base64 of raw AES key
  try {
    const direct = Buffer.from(encryptedKeyB64, "base64");
    if (VALID_AES.has(direct.length)) return direct;
  } catch (_) {}

  return null;
}

function invertIv(ivBuffer) {
  const out = Buffer.alloc(ivBuffer.length);
  for (let i = 0; i < ivBuffer.length; i++) out[i] = ivBuffer[i] ^ 0xff;
  return out;
}

function aesGcmDecrypt(keyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64");
  if (iv.length !== 12) throw new Error(`IV must be 12 bytes, got ${iv.length}`);
  const data = Buffer.from(cipherB64, "base64");
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);
  const decipher = crypto.createDecipheriv(`aes-${keyBuf.length*8}-gcm`, keyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

function aesGcmEncrypt(keyBuf, ivBuf, obj) {
  if (ivBuf.length !== 12) throw new Error(`IV must be 12 bytes, got ${ivBuf.length}`);
  const cipher = crypto.createCipheriv(`aes-${keyBuf.length*8}-gcm`, keyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]).toString("base64");
}

// read materials with common field names
function readMaterials(body) {
  const encryptedKey =
    body?.encrypted_aes_key ||
    body?.encrypted_session_key ||
    body?.encrypted_key ||
    body?.data?.encrypted_aes_key ||
    body?.data?.encrypted_session_key;

  const initialIv =
    body?.initial_vector ||
    body?.initial_iv ||
    body?.data?.initial_vector;

  const encryptedFlowData =
    body?.encrypted_flow_data ||
    body?.data?.encrypted_flow_data;

  return { encryptedKey, initialIv, encryptedFlowData };
}

export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // robust parse
    let body = (req.body && typeof req.body === "object") ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((r)=>{ let d=""; req.on("data",(c)=>d+=c); req.on("end",()=>r(d)); });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // challenge echo
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // materials
    const { encryptedKey, initialIv, encryptedFlowData } = readMaterials(body);
    const hasMaterials = Boolean(encryptedKey && initialIv);

    // HEALTH CHECK: encryptedKey + initialIv, no payload
    if (hasMaterials && !encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");
        console.log(`HealthCheck: AES key length=${aesKey.length} bytes, IV(b64) len=${Buffer.from(initialIv,"base64").length}`);

        const iv = Buffer.from(initialIv, "base64");
        const flipped = invertIv(iv);
        const respB64 = aesGcmEncrypt(aesKey, flipped, { ok: true });
        return sendText(res, respB64); // raw Base64
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        return sendText(res, b64("ok")); // fallback (may still fail, but always Base64)
      }
    }

    // NORMAL: decrypt then forward
    let clean = body;
    if (hasMaterials && encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");
        console.log(`Decrypt: AES key length=${aesKey.length} bytes, IV len=${Buffer.from(initialIv,"base64").length}`);
        clean = aesGcmDecrypt(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
      }
    }

    // forward to Power Automate
    if (process.env.MAKE_WEBHOOK_URL) {
      try {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean)
        });
      } catch (e) {
        console.error("Forward failed:", e?.message || e);
      }
    }

    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
}
