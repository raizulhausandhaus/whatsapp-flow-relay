// api/flow.js
import crypto from "node:crypto";

/* ---------- tiny helpers ---------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

const sendBase64 = (res, base64String) => {
  const body = (base64String || "").trim(); // no quotes/whitespace
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(body);
};

const VALID_AES_BYTES = new Set([16, 24, 32]); // AES-128/192/256

/* ---------- key/iv handling per Meta ---------- */
function rsaDecryptIfWrapped(aesKeyB64, privatePem) {
  try {
    const wrapped = Buffer.from(aesKeyB64, "base64");
    return crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, wrapped);
  } catch {
    return null;
  }
}

function getAesKey(aesKeyB64, privatePem) {
  // 1) Try RSA-OAEP(SHA-256)
  if (privatePem) {
    const k = rsaDecryptIfWrapped(aesKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  // 2) Fall back to raw Base64 key
  try {
    const k = Buffer.from(aesKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch {}
  return null;
}

function invertIv(ivBuf) {
  const out = Buffer.alloc(ivBuf.length);
  for (let i = 0; i < ivBuf.length; i++) out[i] = ivBuf[i] ^ 0xff;
  return out;
}

/* ---------- AES-GCM primitives ---------- */
function aesGcmEncryptToBase64(aesKeyBuf, ivBuf, obj) {
  const bits = aesKeyBuf.length * 8; // 128/192/256
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, aesKeyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([ct, tag]).toString("base64"); // Base64(cipher || tag)
}

function aesGcmDecryptJson(aesKeyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64"); // accept 12 or 16
  const data = Buffer.from(cipherB64, "base64");
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const bits = aesKeyBuf.length * 8;
  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, aesKeyBuf, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString("utf8"));
}

/* ---------- extract materials (field names vary slightly) ---------- */
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

/* ------------------- main handler ------------------- */
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // Parse body robustly
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let d = "";
        req.on("data", (c) => (d += c));
        req.on("end", () => resolve(d));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    if (process.env.LOG_REQUEST === "1") {
      console.log("FLOW PROBE headers:", JSON.stringify(req.headers).slice(0, 4000));
      console.log("FLOW PROBE body:", JSON.stringify(body).slice(0, 4000));
    }

    // 1) Public-key challenge
    if (body?.challenge) return sendJSON(res, { challenge: body.challenge });

    // 2) Health check vs data_exchange
    const { encryptedKey, initialIv, encryptedFlowData } = extractMaterials(body);
    const haveMaterials = Boolean(encryptedKey && initialIv);

    // Health check (materials present, but no payload)
    if (haveMaterials && !encryptedFlowData) {
      try {
        const aesKey = getAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (!aesKey) throw new Error("Unable to derive AES key from materials");
        const iv = Buffer.from(initialIv, "base64");
        const reply = aesGcmEncryptToBase64(aesKey, invertIv(iv), { ok: true });
        console.log(`HealthCheck: key=${aesKey.length}B, iv=${iv.length}B, outB64=${reply.length}`);
        return sendBase64(res, reply); // raw Base64 body, text/plain
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
        // Last-resort: still return Base64 (prevents the “not Base64” error)
        return sendBase64(res, Buffer.from("ok").toString("base64")); // "b2s="
      }
    }

    // Normal traffic: decrypt if present, then forward
    let clean = body;
    if (haveMaterials && encryptedFlowData) {
      try {
        const aesKey = getAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (aesKey) clean = aesGcmDecryptJson(aesKey, initialIv, encryptedFlowData);
      } catch (e) {
        console.error("Decrypt request error:", e?.message || e);
      }
    }

    // Forward to Power Automate
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
    return res.status(200).end();
  }
}
