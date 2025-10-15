import { createPrivateKey } from "node:crypto";
import { compactDecrypt } from "jose";

/**
 * WhatsApp Flow relay (Vercel serverless)
 * - Handles Meta handshake (challenge)
 * - Answers Health Check with Base64 body (required by Flow Builder)
 * - Decrypts encrypted payloads (JWE) with your private key
 * - Forwards the clean JSON to Power Automate (MAKE_WEBHOOK_URL)
 */

const sendJSON = (res, obj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(obj));
};

const sendBase64 = (res, text) => {
  const b64 = Buffer.from(text).toString("base64");
  res.setHeader("Content-Type", "text/plain");
  return res.status(200).send(b64);
};

export default async function handler(req, res) {
  try {
    // Health pings / GET
    if (req.method === "GET") return sendJSON(res, { status: "ok" });

    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // Safe parse body (Vercel often parses JSON already)
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // 1) Public-key challenge (Meta shows "Sign public key")
    if (body && body.challenge) {
      return sendJSON(res, { challenge: body.challenge });
    }

    // 2) Health check: some tenants send a special probe and require a Base64 BODY
    // Heuristics: empty body OR explicit markers OR special header
    const isHealth =
      req.headers["x-meta-health-check"] === "1" ||
      body?.type === "health_check" ||
      body?.health_check === true ||
      Object.keys(body).length === 0;

    if (isHealth) {
      // Return Base64 of "ok"
      return sendBase64(res, "ok"); // "b2s="
    }

    // 3) Decrypt if JWE field is present. Field name can vary by tenant.
    const jwe =
      body.encrypted_flow_data ||
      body.encrypted_flow_data_v2 ||
      (body.data && body.data.encrypted_flow_data) ||
      null;

    let clean = null;
    if (jwe && process.env.FLOW_PRIVATE_PEM) {
      try {
        const privateKey = createPrivateKey(process.env.FLOW_PRIVATE_PEM);
        const { plaintext } = await compactDecrypt(jwe, privateKey);
        clean = JSON.parse(new TextDecoder().decode(plaintext));
      } catch (e) {
        console.error("Decryption error:", e?.message || e);
      }
    }

    // 4) Forward clean payload (or raw fallback) to Power Automate
    const forwardBody = clean || body;
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

    // 5) ACK to Meta (you can return a navigate action here if you want)
    return res.status(200).end();
  } catch (err) {
    console.error("Handler error:", err?.message || err);
    return res.status(200).end(); // ack to avoid retries
  }
}
