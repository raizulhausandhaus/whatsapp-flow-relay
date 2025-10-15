import { createPrivateKey, createPublicKey } from "node:crypto";
import { compactDecrypt, CompactEncrypt, importSPKI } from "jose";

const toJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};
const toText = (res, text) => {
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(text);
};
const toBase64 = (bufOrStr) =>
  Buffer.isBuffer(bufOrStr)
    ? Buffer.from(bufOrStr).toString("base64")
    : Buffer.from(String(bufOrStr)).toString("base64");

/** Try to read Meta's public key for encrypting our response (Health check) */
async function extractMetaPublicKey(req, body) {
  // Common header variants seen in the wild:
  const h = req.headers || {};
  const headerCandidates = [
    "x-meta-public-key",
    "x-waba-public-key",
    "x-whatsapp-public-key",
    "x-meta-healthcheck-key"
  ];

  for (const k of headerCandidates) {
    const val = h[k];
    if (val && typeof val === "string" && val.includes("BEGIN PUBLIC KEY")) {
      try {
        return await importSPKI(val, "RSA-OAEP-256");
      } catch {}
    }
  }

  // Body variants (some tenants put it in the test payload):
  const bodyCandidates = [
    body?.meta_public_key_pem,
    body?.health_check?.public_key_pem,
    body?.public_key_pem
  ];
  for (const val of bodyCandidates) {
    if (val && typeof val === "string" && val.includes("BEGIN PUBLIC KEY")) {
      try {
        return await importSPKI(val, "RSA-OAEP-256");
      } catch {}
    }
  }

  // If key is base64-encoded PEM without headers:
  const headerB64Candidates = [
    "x-meta-public-key-b64",
    "x-waba-public-key-b64"
  ];
  for (const k of headerB64Candidates) {
    const val = h[k];
    if (val && typeof val === "string") {
      try {
        const pem = Buffer.from(val, "base64").toString("utf8");
        if (pem.includes("BEGIN PUBLIC KEY")) {
          return await importSPKI(pem, "RSA-OAEP-256");
        }
      } catch {}
    }
  }

  return null;
}

/** Encrypt an object to Meta using RSA-OAEP-256 + A256GCM, then Base64-encode the compact JWE */
async function encryptForMeta(metaPubKey, obj) {
  const payload = Buffer.from(JSON.stringify(obj));
  // jose CompactEncrypt defaults to A256GCM when you set enc to 'A256GCM'
  const jwe = await new CompactEncrypt(payload)
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(metaPubKey);
  // Health check expects the **HTTP body** to be Base64 of the compact JWE string
  return toBase64(jwe);
}

export default async function handler(req, res) {
  try {
    // Quick GET: show that the function is alive
    if (req.method === "GET") return toJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // Parse body safely (Vercel usually gives you JSON already)
    let body = (req.body && typeof req.body === "object") ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // 1) Signing challenge
    if (body.challenge) {
      return toJSON(res, { challenge: body.challenge });
    }

    // 2) Health check path
    const looksLikeHealth =
      req.headers["x-meta-health-check"] === "1" ||
      body?.type === "health_check" ||
      body?.health_check === true ||
      // many health checks have no business payload at all:
      (!body.encrypted_flow_data &&
        !body.encrypted_flow_data_v2 &&
        !body?.data?.encrypted_flow_data &&
        Object.keys(body).length <= 2); // very small test body

    if (looksLikeHealth) {
      try {
        const metaPubKey = await extractMetaPublicKey(req, body);
        if (metaPubKey) {
          const b64Jwe = await encryptForMeta(metaPubKey, { ok: true });
          return toText(res, b64Jwe);
        }
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
      }
      // Fallback: plain Base64 'ok' (older tenants)
      return toText(res, toBase64("ok"));
    }

    // 3) Normal Flow traffic — decrypt if JWE present
    const jweField =
      body.encrypted_flow_data ||
      body.encrypted_flow_data_v2 ||
      body?.data?.encrypted_flow_data ||
      null;

    let decrypted = null;
    if (jweField && process.env.FLOW_PRIVATE_PEM) {
      try {
        const privateKey = createPrivateKey(process.env.FLOW_PRIVATE_PEM);
        const { plaintext } = await compactDecrypt(jweField, privateKey);
        decrypted = JSON.parse(new TextDecoder().decode(plaintext));
      } catch (e) {
        console.error("Decryption error:", e?.message || e);
      }
    }

    // 4) Forward (clean or raw) to Power Automate
    const forwardBody = decrypted || body;
    if (process.env.MAKE_WEBHOOK_URL) {
      try {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(forwardBody)
        });
      } catch (e) {
        console.error("Forward failed:", e?.message || e);
      }
    }

    // 5) ACK; optional: you can return an encrypted navigate here too
    return res.status(200).end();
  } catch (err) {
    console.error("Handler error:", err?.message || err);
    return res.status(200).end(); // avoid retries
  }
}
