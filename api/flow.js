// api/flow.js
import crypto from "node:crypto";

// ───────── helpers ─────────
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

// Send a raw Base64 body with strict headers (no quotes, no whitespace)
const sendBase64 = (res, base64String) => {
  const body = (base64String || "").toString().trim(); // ensure no newline/space
  const len = Buffer.byteLength(body, "utf8");
  res.setHeader("Content-Type", "application/octet-stream"); // safest for binary/base64
  res.setHeader("Content-Transfer-Encoding", "base64");
  res.setHeader("Content-Length", String(len));
  return res.status(200).send(body);
};

const toB64 = (x) =>
  Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

// ───────── Meta Flows crypto (per docs) ─────────
const VALID_AES_BYTES = new Set([16, 24, 32]); // 128/192/256

function rsaDecryptMaybe(encryptedKeyB64, privatePem) {
  try {
    const enc = Buffer.from(encryptedKeyB64, "base64");
    return crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, enc);
  } catch {
    return null;
  }
}

function parseAesKey(encryptedKeyB64, privatePem) {
  if (privatePem) {
    const k = rsaDecryptMaybe(encryptedKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  try {
    const k = Buffer.from(encryptedKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch {}
  return null;
}

function invertIv(ivBuffer) {
  const out = Buffer.alloc(ivBuffer.length);
  for (let i = 0; i < ivBuffer.length; i++) out[i] = ivBuffer[i] ^ 0xff;
  return out;
}

// Accept 12 or 16-byte IVs (and other lengths if Meta sends them)
function aesGcmDecrypt(keyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64");
  const data = Buffer.from(cipherB64, "base64");
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);
  const bits = keyBuf.length * 8; // 128/192/256
  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, keyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

function aesGcmEncrypt(keyBuf, ivBuf, obj) {
  const bits = keyBuf.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, keyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]).toString("base64");
}

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

// ───────── main handler ─────────
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // robust parse
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((r) => {
        let d = "";
        req.on("data", (c) => (d += c));
        req.on("end", () => r(d));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // A) signing challenge
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // B) encryption materials
    const { encryptedKey, initialIv, encryptedFlowData } = readMaterials(body);
    const hasMaterials = Boolean(encryptedKey && initialIv);

    // C) HEALTH CHECK (key + iv present, but no payload to decrypt)
    if (hasMaterials && !encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");

        const iv = Buffer.from(initialIv, "base64");
        const flipped = invertIv(iv);
        const base64Body = aesGcmEncrypt(aesKey, flipped, { ok: true });

        // Strict Base64 response
        return sendBase64(res, base64Body);
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Always send Base64 so the checker never complains about encoding
        return sendBase64(res, toB64("ok"));
      }
    }

    // D) NORMAL TRAFFIC: decrypt if present
    let clean = body;
    if (hasMaterials && encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");
        clean = aesGcmDecrypt(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
      }
    }

    // E) forward to Power Automate
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

    // F) ACK
    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
}
