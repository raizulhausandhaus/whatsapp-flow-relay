import express from "express";
import bodyParser from "body-parser";
import serverless from "serverless-http";
import crypto from "node:crypto";

const app = express();
app.use(bodyParser.json({ type: "*/*" })); // Flow posts sometimes use generic content-types

// ——— helpers ———
const VALID_AES = new Set([16, 24, 32]); // AES-128/192/256
const TAG_LEN = 16;

const deriveAesKey = (maybeKey, privatePem) => {
  // 1) RSA-OAEP-SHA256 wrapped key (sent base64)
  try {
    const wrapped = Buffer.from(maybeKey, "base64");
    if (wrapped.length) {
      try {
        const k = crypto.privateDecrypt({ key: privatePem, oaepHash: "sha256" }, wrapped);
        if (VALID_AES.has(k.length)) return k;
      } catch {}
    }
  } catch {}
  // 2) raw base64 key
  try {
    const k = Buffer.from(maybeKey, "base64");
    if (VALID_AES.has(k.length)) return k;
  } catch {}
  // 3) hex key
  if (/^[0-9a-f]+$/i.test(maybeKey || "") && (maybeKey.length % 2 === 0)) {
    const k = Buffer.from(maybeKey, "hex");
    if (VALID_AES.has(k.length)) return k;
  }
  return null;
};

const decodeIv = (maybeIv) => {
  // base64
  try {
    const b = Buffer.from(maybeIv, "base64");
    if (b.length === 12 || b.length === 16) return b;
  } catch {}
  // hex
  if (/^[0-9a-f]+$/i.test(maybeIv || "") && (maybeIv.length % 2 === 0)) {
    const b = Buffer.from(maybeIv, "hex");
    if (b.length === 12 || b.length === 16) return b;
  }
  // raw
  if (typeof maybeIv === "string") {
    const b = Buffer.from(maybeIv, "utf8");
    if (b.length === 12 || b.length === 16) return b;
  }
  return null;
};

const invertIv = (iv) => {
  const out = Buffer.alloc(iv.length);
  for (let i = 0; i < iv.length; i++) out[i] = iv[i] ^ 0xff;
  return out;
};

const gcmEncryptToB64 = (key, iv, json) => {
  const bits = key.length * 8;
  const cipher = crypto.createCipheriv(`aes-${bits}-gcm`, key, iv);
  const payload = Buffer.from(JSON.stringify(json), "utf8");
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, tag]).toString("base64");
};

const gcmDecryptJson = (key, iv, cipherPlusTagB64) => {
  const data = Buffer.from(cipherPlusTagB64, "base64");
  if (data.length <= TAG_LEN) throw new Error("cipher too short");
  const tag = data.subarray(data.length - TAG_LEN);
  const ct = data.subarray(0, data.length - TAG_LEN);
  const bits = key.length * 8;
  const dec = crypto.createDecipheriv(`aes-${bits}-gcm`, key, iv);
  dec.setAuthTag(tag);
  const pt = Buffer.concat([dec.update(ct), dec.final()]);
  return JSON.parse(pt.toString("utf8"));
};

// ——— routes ———

// health / status (optional sanity check)
app.get("/api/flow", (_req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.status(200).send(JSON.stringify({ status: "ok" }));
});

// main POST handler (Flow will call this)
app.post("/api/flow", async (req, res) => {
  try {
    const body = req.body || {};

    // 1) Signing challenge
    if (typeof body.challenge === "string") {
      res.setHeader("Content-Type", "application/json");
      return res.status(200).send(JSON.stringify({ challenge: body.challenge }));
    }

    // 2) Extract materials (cover name variants)
    const keyField =
      body.encrypted_aes_key ??
      body.encrypted_session_key ??
      body.encrypted_key ??
      body.aes_key ??
      body?.data?.encrypted_aes_key ??
      body?.data?.encrypted_session_key ??
      body?.data?.aes_key;

    const ivField =
      body.initial_vector ??
      body.initial_iv ??
      body.iv ??
      body?.data?.initial_vector ??
      body?.data?.iv;

    const flowCipher =
      body.encrypted_flow_data ??
      body?.data?.encrypted_flow_data;

    // 3) Health check (no encrypted_flow_data) — MUST return encrypted Base64 of {"ok":true}
    if (!flowCipher) {
      const privatePem = process.env.FLOW_PRIVATE_PEM || "";
      const aesKey = keyField ? deriveAesKey(keyField, privatePem) : null;
      const ivBuf  = ivField ? decodeIv(ivField) : null;

      if (aesKey && ivBuf) {
        const b64 = gcmEncryptToB64(aesKey, invertIv(ivBuf), { ok: true });
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Cache-Control", "no-store");
        return res.status(200).send(b64); // body = raw Base64
      }

      // Fallback (some tenants don’t send materials during health-check)
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Cache-Control", "no-store");
      return res.status(200).send(Buffer.from("ok").toString("base64")); // "b2s="
    }

    // 4) Data exchange: decrypt → forward (optional) → ACK
    try {
      const privatePem = process.env.FLOW_PRIVATE_PEM || "";
      const aesKey = keyField ? deriveAesKey(keyField, privatePem) : null;
      const ivBuf  = ivField ? decodeIv(ivField) : null;

      let clean = body;
      if (aesKey && ivBuf) {
        clean = gcmDecryptJson(aesKey, ivBuf, flowCipher);
      }

      if (process.env.MAKE_WEBHOOK_URL) {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(clean)
        });
      }
    } catch (e) {
      console.error("Data decrypt/forward error:", e?.message || e);
    }

    return res.status(200).end();
  } catch (e) {
    console.error("Handler error:", e?.message || e);
    return res.status(200).end();
  }
});

export default serverless(app);
