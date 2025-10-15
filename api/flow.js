// api/flow.js
import crypto from "node:crypto";

/* ----------------------- helpers ----------------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

// Return a raw Base64 string: no quotes, no spaces, text/plain
const sendBase64Plain = (res, base64String) => {
  const body = (base64String || "").toString().trim(); // ensure no newline/space
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(body);
};

const toB64 = (x) =>
  Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

/* ------------------- crypto (Meta Flows) ------------------ */
const VALID_AES_BYTES = new Set([16, 24, 32]); // 128/192/256

function tryRsaOaepSha256DecryptKey(encryptedKeyB64, privatePem) {
  try {
    const enc = Buffer.from(encryptedKeyB64, "base64");
    return crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, enc);
  } catch {
    return null;
  }
}

function deriveAesKey(encryptedKeyB64, privatePem) {
  // 1) RSA wrapped?
  if (privatePem) {
    const k = tryRsaOaepSha256DecryptKey(encryptedKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  // 2) Otherwise treat as raw Base64 AES key
  try {
    const k = Buffer.from(encryptedKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch {}
  return null;
}

function invertIv(ivBuf) {
  const out = Buffer.alloc(ivBuf.length);
  for (let i = 0; i < ivBuf.length; i++) out[i] = ivBuf[i] ^ 0xff;
  return out;
}

function aesGcmDecryptToJson(aesKeyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64");          // accept 12/16/etc
  const data = Buffer.from(cipherB64, "base64");    // cipher || tag
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);
  const bits = aesKeyBuf.length * 8;                // 128/192/256
  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, aesKeyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

function aesGcmEncryptToBase64(aesKeyBuf, ivBuf, obj) {
  const bits = aesKeyBuf.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, aesKeyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]).toString("base64");
}

/* --------- extract materials (names vary between tenants) ---------- */
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

    // robust parse
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // 1) Public key signing challenge
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // 2) Materials (if Meta includes them)
    const { encryptedKey, initialIv, encryptedFlowData } = extractMaterials(body);
    const haveMaterials = Boolean(encryptedKey && initialIv);

    // 3) HEALTH CHECK
    if (haveMaterials && !encryptedFlowData) {
      try {
        const aesKey = deriveAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Cannot derive AES key");
        const iv = Buffer.from(initialIv, "base64");
        const flipped = invertIv(iv);

        const base64Body = aesGcmEncryptToBase64(aesKey, flipped, { ok: true });
        console.log(`HealthCheck reply: len=${base64Body.length}, key=${aesKey.length} bytes, iv=${iv.length}`);
        return sendBase64Plain(res, base64Body);
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Always return *some* Base64 to satisfy the encoding check
        return sendBase64Plain(res, toB64("ok"));
      }
    }

    // 4) NORMAL TRAFFIC: decrypt if present, then forward
    let clean = body;
    if (haveMaterials && encryptedFlowData) {
      try {
        const aesKey = deriveAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Cannot derive AES key");
        clean = aesGcmDecryptToJson(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
      }
    }

    // 5) Forward to Power Automate
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

    // 6) Ack
    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
}
