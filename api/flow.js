import { createPrivateKey } from "node:crypto";
import { compactDecrypt, CompactEncrypt, importSPKI } from "jose";

const toJSON = (res, obj) => { res.setHeader("Content-Type","application/json"); return res.status(200).send(JSON.stringify(obj)); };
const toText = (res, txt) => { res.setHeader("Content-Type","text/plain"); return res.status(200).send(txt); };
const b64 = (x) => Buffer.from(typeof x === "string" ? x : String(x)).toString("base64");

async function findMetaPubKey(req, body) {
  const H = req.headers || {};

  // Try common header names
  const headerNames = [
    "x-meta-public-key",
    "x-waba-public-key",
    "x-whatsapp-public-key",
    "x-meta-healthcheck-key",
    "x-wa-public-key",
  ];
  for (const name of headerNames) {
    const val = H[name];
    if (typeof val === "string" && val.includes("BEGIN PUBLIC KEY")) {
      try { return await importSPKI(val, "RSA-OAEP-256"); } catch {}
    }
  }

  // Try Base64-encoded PEM in headers
  const headerB64 = ["x-meta-public-key-b64","x-waba-public-key-b64","x-wa-public-key-b64"];
  for (const name of headerB64) {
    const v = H[name];
    if (typeof v === "string") {
      try {
        const pem = Buffer.from(v, "base64").toString("utf8");
        if (pem.includes("BEGIN PUBLIC KEY")) return await importSPKI(pem, "RSA-OAEP-256");
      } catch {}
    }
  }

  // Try body fields
  const bodyCandidates = [
    body?.meta_public_key_pem,
    body?.public_key_pem,
    body?.health_check?.public_key_pem,
  ];
  for (const v of bodyCandidates) {
    if (typeof v === "string" && v.includes("BEGIN PUBLIC KEY")) {
      try { return await importSPKI(v, "RSA-OAEP-256"); } catch {}
    }
  }

  return null;
}

async function encryptHealthAck(pubKey) {
  const payload = Buffer.from(JSON.stringify({ ok: true }));
  const jwe = await new CompactEncrypt(payload)
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(pubKey);
  return b64(jwe); // Health check expects Base64(JWE)
}

export default async function handler(req, res) {
  try {
    if (req.method === "GET") return toJSON(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // Robust parse
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((r)=>{ let d=""; req.on("data",(c)=>d+=c); req.on("end",()=>r(d)); });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // Challenge echo
    if (body?.challenge) return toJSON(res, { challenge: body.challenge });

    // Heuristic: health probe
    const isHealth =
      req.headers["x-meta-health-check"] === "1" ||
      body?.type === "health_check" ||
      body?.health_check === true ||
      (!body.encrypted_flow_data && !body.encrypted_flow_data_v2 && !body?.data?.encrypted_flow_data && Object.keys(body).length <= 2);

    if (isHealth) {
      // Optional debug: log headers/body to find the key field
      if (process.env.LOG_HEALTH_DEBUG === "1") {
        console.log("META HEALTH DEBUG: headers=", JSON.stringify(req.headers || {}, null, 2).slice(0, 6000));
        console.log("META HEALTH DEBUG: body=", JSON.stringify(body || {}, null, 2).slice(0, 4000));
      }

      try {
        const pub = await findMetaPubKey(req, body);
        if (pub) {
          const resp = await encryptHealthAck(pub);
          return toText(res, resp);
        }
      } catch (e) {
        console.error("Health encrypt error:", e?.message || e);
      }
      // Fallback for older tenants (will fail “decrypt response” but helps us iterate)
      return toText(res, b64("ok"));
    }

    // Normal traffic: decrypt if JWE present (ignore errors)
    const jwe =
      body.encrypted_flow_data ||
      body.encrypted_flow_data_v2 ||
      body?.data?.encrypted_flow_data ||
      null;

    if (jwe && process.env.FLOW_PRIVATE_PEM) {
      try {
        const { plaintext } = await compactDecrypt(jwe, createPrivateKey(process.env.FLOW_PRIVATE_PEM));
        body = JSON.parse(new TextDecoder().decode(plaintext));
      } catch (e) {
        console.error("Decryption error:", e?.message || e);
      }
    }

    // Forward to Power Automate
    if (process.env.MAKE_WEBHOOK_URL) {
      try {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
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
