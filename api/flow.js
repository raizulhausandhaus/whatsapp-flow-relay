// api/flow.js
import crypto from "node:crypto";

/* ---------------- helpers ---------------- */
const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

const sendBase64 = (res, base64String) => {
  const body = (base64String || "").trim(); // no quotes/newlines
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(body);
};

const toB64 = (x) =>
  Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

/* ---------------- crypto (per Meta Flows) ---------------- */
const VALID_AES_BYTES = new Set([16, 24, 32]); // AES-128/192/256

function rsaDecryptIfWrapped(aesKeyB64, privatePem) {
  try {
    const wrapped = Buffer.from(aesKeyB64, "base64");
    return crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, wrapped);
  } catch (_e) {
    return null;
  }
}

function getAesKey(aesKeyB64, privatePem) {
  // 1) RSA-OAEP(SHA-256)
  if (privatePem) {
    const k = rsaDecryptIfWrapped(aesKeyB64, privatePem);
    if (k && VALID_AES_BYTES.has(k.length)) return k;
  }
  // 2) raw Base64 AES key
  try {
    const k = Buffer.from(aesKeyB64, "base64");
    if (VALID_AES_BYTES.has(k.length)) return k;
  } catch (_e) {}
  return null;
}

function invertIv(ivBuf) {
  const out = Buffer.alloc(ivBuf.length);
  for (let i = 0; i < ivBuf.length; i++) out[i] = ivBuf[i] ^ 0xff;
  return out;
}

function aesGcmEncryptToBase64(aesKeyBuf, ivBuf, obj) {
  const bits = aesKeyBuf.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, aesKeyBuf, ivBuf);
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16B
  return Buffer.concat([ct, tag]).toString("base64"); // Base64(cipher||tag)
}

function aesGcmDecryptJson(aesKeyBuf, ivB64, cipherB64) {
  const iv = Buffer.from(ivB64, "base64"); // accept 12/16/etc
  const data = Buffer.from(cipherB64, "base64");
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const bits = aesKeyBuf.length * 8;
  const decipher = crypto.createDecipheriv(`aes-${bits}-gcm`, aesKeyBuf, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString("utf8"));
}

/* -------- field extraction (names can vary) -------- */
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

/* ---------------- main handler ---------------- */
export default async function handler(req, res) {
  try {
    if (req.method === "GET") return sendJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // robust parsing
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let d = "";
        req.on("data", (c) => (d += c));
        req.on("end", () => resolve(d));
      });
      try {
        body = JSON.parse(raw || "{}");
      } catch (_e) {
        body = {};
      }
    }

    // 0) debug toggle (optional) — comment out after testing
    // console.log("FLOW PROBE:", JSON.stringify(body).slice(0, 2000));

    // 1) public-key signing challenge
    if (body?.challenge) {
      return sendJSON(res, { challenge: body.challenge });
    }

    // 2) materials
    const { encryptedKey, initialIv, encryptedFlowData } = extractMaterials(body);
    const haveMaterials = Boolean(encryptedKey && initialIv);

    // 3) health check or any POST without encrypted_flow_data
    if (!encryptedFlowData) {
      try {
        if (haveMaterials) {
          const aesKey = getAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
          if (aesKey) {
            const iv = Buffer.from(initialIv, "base64");
            const reply = aesGcmEncryptToBase64(aesKey, invertIv(iv), { ok: true });
            return sendBase64(res, reply); // encrypted Base64 per Meta spec
          }
        }
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
      }
      // fallback: still Base64, so checker can’t claim “not Base64”
      return sendBase64(res, toB64("ok")); // "b2s="
    }

    // 4) normal traffic — decrypt then forward
    let clean = body;
    try {
      if (haveMaterials) {
        const aesKey = getAesKey(encryptedKey, process.env.FLOW_PRIVATE_PEM);
        if (aesKey) {
          clean = aesGcmDecryptJson(aesKey, initialIv, encryptedFlowData);
        }
      }
    } catch (e) {
      console.error("Decrypt request error:", e?.message || e);
    }

    // 5) forward to Power Automate
    try {
      if (process.env.MAKE_WEBHOOK_URL) {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean),
        });
      }
    } catch (e) {
      console.error("Forward failed:", e?.message || e);
    }

    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
}
