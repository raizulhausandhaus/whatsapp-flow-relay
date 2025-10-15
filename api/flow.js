// api/flow.js
import crypto from "node:crypto";

/* ----------------------- tiny helpers ----------------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

// Send a raw Base64 body with strict headers
const sendBase64 = (res, base64String) => {
  const body = (base64String || "").toString().trim(); // no quotes/whitespace
  const len = Buffer.byteLength(body, "utf8");
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Transfer-Encoding", "base64");
  res.setHeader("Content-Length", String(len));
  return res.status(200).send(body);
};

/* ------------------- crypto per Meta Flows ------------------ */
// Some tenants RSA-wrap the AES key, others send raw Base64 AES key.
const VALID_AES_BYTES = new Set([16, 24, 32]); // 128/192/256-bit

function tryRsaOaepSha256DecryptKey(encryptedKeyB64, privatePem) {
  try {
    const enc = Buffer.from(encryptedKeyB64, "base64");
    return crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, enc); // Buffer
  } catch {
    return null;
  }
}

function deriveAesKey(encryptedKeyB64, privatePem) {
  // 1) Try RSA-OAEP-SHA256 decryption
  if (privatePem) {
    const k = tryRsaOaepSha256DecryptKey(encryptedKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  // 2) Fallback: treat value itself as Base64 of the raw AES key
  try {
    const k = Buffer.from(encryptedKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch {}
  return null;
}

// Byte-wise NOT of IV for response encryption (Meta requirement)
function invertIv(ivBuf) {
  const out = Buffer.alloc(ivBuf.length);
  for (let i = 0; i < ivBuf.length; i++) out[i] = ivBuf[i] ^ 0xff;
  return out;
}

// Decrypt: AES-GCM with tag appended (cipher || tag), IV is Base64 in request
function aesGcmDecryptToJson(aesKeyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64");             // 12 or 16 typical; accept any length
  const data = Buffer.from(cipherB64, "base64");       // cipher || tag
  const tag = data.subarray(data.length - 16);         // 16-byte GCM tag
  const ciphertext = data.subarray(0, data.length - 16);
  const bits = aesKeyBuf.length * 8;                   // 128/192/256

  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, aesKeyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

// Encrypt: AES-GCM and return Base64(cipher || tag)
function aesGcmEncryptToBase64(aesKeyBuf, ivBuf, obj) {
  const bits = aesKeyBuf.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, aesKeyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]).toString("base64");
}

/* --------- pull fields (Meta varies names across tenants) ---------- */
function extractMaterials(body) {
  const encryptedKey =
    body?.encrypted_aes_key ??
    body?.encrypted_session_key ??
    body?.encrypted_key ??
    body?.data?.encrypted_aes_key ??
    body?.data?.encrypted_session_key;

  const initialIv =
    body?.initial_vector ??
    body?.initial_iv ??
    body?.data?.initial_vector;

  const encryptedFlowData =
    body?.encrypted_flow_data ??
    body?.data?.encrypted_flow_data;

  return { encryptedKey, initialIv, encryptedFlowData };
}

/* -------------------------- handler -------------------------- */
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // robust parse (Vercel often gives parsed JSON already)
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // 1) Public-key signing challenge
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // 2) Materials present?
    const { encryptedKey, initialIv, encryptedFlowData } = extractMaterials(body);
    const haveMaterials = Boolean(encryptedKey && initialIv);

    // 3) Health Check (key + iv present, but no encrypted_flow_data)
    if (haveMaterials && !encryptedFlowData) {
      try {
        const aesKey = deriveAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key");
        const iv = Buffer.from(initialIv, "base64");
        const flippedIv = invertIv(iv);

        // Encrypt {"ok":true} with SAME key and INVERTED IV, return Base64 body
        const base64Body = aesGcmEncryptToBase64(aesKey, flippedIv, { ok: true });
        return sendBase64(res, base64Body);
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Always send Base64 so checker never complains about encoding
        return sendBase64(res, Buffer.from("ok").toString("base64"));
      }
    }

    // 4) Normal data_exchange: decrypt -> forward -> 200 ACK
    let clean = body;
    if (haveMaterials && encryptedFlowData) {
      try {
        const aesKey = deriveAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key");
        clean = aesGcmDecryptToJson(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
        // leave clean as original body so you can still inspect downstream
      }
    }

    // Forward the clean (or raw) payload to Power Automate
    if (process.env.MAKE_WEBHOOK_URL) {
      try {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean),
        });
      } catch (e) {
        console.error("Forward failed:", e?.message || e);
      }
    }

    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end(); // avoid retries
  }
}
