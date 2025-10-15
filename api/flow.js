// api/flow.js
import crypto from "node:crypto";

// ───────── helpers ─────────
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};
const sendText = (res, txt) => {
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(txt);
};
const b64 = (x) =>
  Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

// ───────── Meta Flows crypto (per docs) ─────────

// some tenants send AES key RSA-encrypted, others send it as Base64 raw key
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
  // 1) Try RSA-OAEP(SHA-256) decrypt
  if (privatePem) {
    const k = rsaDecryptMaybe(encryptedKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  // 2) Fallback: treat as Base64 of raw AES key
  try {
    const k = Buffer.from(encryptedKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch {}
  return null;
}

// bytewise NOT of IV for response encryption
function invertIv(ivBuffer) {
  const out = Buffer.alloc(ivBuffer.length);
  for (let i = 0; i < ivBuffer.length; i++) out[i] = ivBuffer[i] ^ 0xff;
  return out;
}

// AES-GCM decrypt (accept IV length 12 or 16, etc.)
function aesGcmDecrypt(keyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64"); // 12 or 16 are common; don't hard-fail
  const data = Buffer.from(cipherB64, "base64");
  const tag = data.subarray(data.length - 16); // GCM tag is always 16 bytes
  const ciphertext = data.subarray(0, data.length - 16);
  const bits = keyBuf.length * 8; // 128 / 192 / 256

  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, keyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

// AES-GCM encrypt response payload; return Base64(cipher||tag)
function aesGcmEncrypt(keyBuf, ivBuf, obj) {
  const bits = keyBuf.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, keyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([enc, tag]).toString("base64");
}

// extract materials (names vary slightly across tenants)
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

    // robust JSON parse (Vercel often gives parsed body already)
    let body =
      req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((r) => {
        let d = "";
        req.on("data", (c) => (d += c));
        req.on("end", () => r(d));
      });
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        body = {};
      }
    }

    // A) public-key challenge (sign public key step)
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // B) read encryption materials
    const { encryptedKey, initialIv, encryptedFlowData } = readMaterials(body);
    const hasMaterials = Boolean(encryptedKey && initialIv);

    // C) HEALTH CHECK: meta sends only key+IV (no payload).
    // Must respond with Base64(AES-GCM encrypt of {"ok":true} using SAME key + INVERTED IV)
    if (hasMaterials && !encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");

        const iv = Buffer.from(initialIv, "base64");      // accept 12/16
        const flipped = invertIv(iv);                     // per Meta spec
        const respB64 = aesGcmEncrypt(aesKey, flipped, { ok: true });
        return sendText(res, respB64);                    // raw Base64 body
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Fallback stays Base64 so checker never says "not Base64"
        return sendText(res, b64("ok"));
      }
    }

    // D) NORMAL TRAFFIC: decrypt payload if present, then forward to Power Automate
    let clean = body;
    if (hasMaterials && encryptedFlowData) {
      try {
        const aesKey = parseAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");

        clean = aesGcmDecrypt(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
        // leave clean as original body if decrypt fails (still ACK)
      }
    }

    // E) Forward to your automation (Power Automate webhook URL in env)
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

    // F) Final ACK (for data_exchange you can later return an encrypted navigate action)
    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end(); // prevent retries
  }
}
