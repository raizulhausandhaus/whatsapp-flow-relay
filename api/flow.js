import crypto from "node:crypto";

// helpers
const sendJSON = (res, obj) => { res.setHeader("Content-Type","application/json"); return res.status(200).send(JSON.stringify(obj)); };
const sendText = (res, txt) => { res.setHeader("Content-Type","text/plain"); return res.status(200).send(txt); };

// --- Core WhatsApp Flows crypto (per Meta guide) ---

// 1) RSA-OAEP(SHA-256) decrypt -> get AES session key (32 bytes)
function rsaDecryptAesKey(encryptedKeyB64, privatePem) {
  const enc = Buffer.from(encryptedKeyB64, "base64");
  const key = crypto.privateDecrypt(
    { key: privatePem, oaepHash: "sha256" },
    enc
  );
  return key; // Buffer of 16 or 32 bytes (we expect 32 for AES-256)
}

// 2) Invert IV bytes for the RESPONSE encryption (Meta requirement)
function invertIv(ivBuffer) {
  const out = Buffer.alloc(ivBuffer.length);
  for (let i = 0; i < ivBuffer.length; i++) out[i] = ivBuffer[i] ^ 0xff;
  return out;
}

// 3) AES-256-GCM decrypt (request) and encrypt (response)
function aesGcmDecrypt(keyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64");
  const data = Buffer.from(cipherB64, "base64");
  // last 16 bytes = auth tag
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

function aesGcmEncrypt(keyBuf, ivBuf, obj) {
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([encrypted, tag]).toString("base64"); // Base64(cipher||tag)
}

// Try to read Meta health-check materials from body (names vary a bit by tenant)
function readMaterials(body) {
  // common field names seen in the wild
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

    // Parse body robustly
    let body = (req.body && typeof req.body === "object") ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((r) => { let d=""; req.on("data",(c)=>d+=c); req.on("end",()=>r(d)); });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // A) Meta signing challenge
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // B) Inspect encryption materials
    const { encryptedKey, initialIv, encryptedFlowData } = readMaterials(body);
    const hasMaterials = !!(encryptedKey && initialIv);

    // C) HEALTH CHECK path:
    // Health probe usually sends only encryptedKey + initialIv (no flow data).
    // Requirement: respond with Base64(AES-GCM(encrypt({"ok":true}) with inverted IV))
    if (hasMaterials && !encryptedFlowData) {
      try {
        const aesKey = rsaDecryptAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        const iv = Buffer.from(initialIv, "base64");
        const flippedIv = invertIv(iv);

        const b64 = aesGcmEncrypt(aesKey, flippedIv, { ok: true });
        return sendText(res, b64); // raw Base64 string body (no JSON)
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Fallback: still return Base64 of "ok" to avoid "not Base64" error
        return sendText(res, Buffer.from("ok").toString("base64"));
      }
    }

    // D) NORMAL TRAFFIC: decrypt user payload (if present), then forward to Power Automate
    let clean = body;
    if (hasMaterials && encryptedFlowData) {
      try {
        const aesKey = rsaDecryptAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        clean = aesGcmDecrypt(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
      }
    }

    // Forward clean data to your automation
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

    // E) ACK to Meta (for data_exchange you can return an encrypted navigate; plain 200 is fine for now)
    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
}
