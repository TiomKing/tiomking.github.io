// Contact backend for tiomking.com. Every request must carry a valid Turnstile token.
//   POST /          the contact form: emails the details to TO_ADDRESS through Email Routing
//   POST /whatsapp  returns the wa.me link, so WHATSAPP_NUMBER never appears in the page
import { EmailMessage } from "cloudflare:email";

// Longest accepted value per field, in characters
const LIMITS = { name: 100, role: 150, contact: 150, type: 60, message: 4000 };

// Prefilled first message of the WhatsApp chat, by page language
const WHATSAPP_TEXT = {
  he: "שלום גלעד, אשמח לתאם פגישה אישית לאבטחת סייבר.",
  en: "Hi Gilad, I'd like to set up a private cybersecurity session.",
};

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
    const originOk = allowed.includes(origin);
    const cors = originOk ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : { Vary: "Origin" };

    const reply = (status, body) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      });

    if (request.method === "OPTIONS") {
      if (!originOk) return new Response(null, { status: 403, headers: cors });
      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    if (request.method !== "POST") return reply(405, { ok: false, error: "method" });
    if (!originOk) return reply(403, { ok: false, error: "origin" });

    let data;
    try {
      data = await request.json();
    } catch {
      return reply(400, { ok: false, error: "json" });
    }
    if (!data || typeof data !== "object") return reply(400, { ok: false, error: "json" });

    const path = new URL(request.url).pathname.replace(/\/+$/, "") || "/";
    const ip = request.headers.get("CF-Connecting-IP");
    const token = typeof data.turnstileToken === "string" ? data.turnstileToken : "";

    if (path === "/whatsapp") {
      const number = (env.WHATSAPP_NUMBER || "").replace(/\D/g, "");
      if (!number) return reply(503, { ok: false, error: "unavailable" });
      if (!(await verifyTurnstile(token, env.TURNSTILE_SECRET, ip))) {
        return reply(403, { ok: false, error: "captcha" });
      }
      const text = data.lang === "en" ? WHATSAPP_TEXT.en : WHATSAPP_TEXT.he;
      return reply(200, { ok: true, url: "https://wa.me/" + number + "?text=" + encodeURIComponent(text) });
    }

    if (path !== "/") return reply(404, { ok: false, error: "path" });

    // Honeypot filled in: a bot. Pretend it worked so it doesn't retry.
    if (data._gotcha) return reply(200, { ok: true });

    const f = {};
    for (const key of Object.keys(LIMITS)) {
      f[key] = clean(data[key], LIMITS[key], key === "message");
    }
    if (!f.name || !f.contact) return reply(400, { ok: false, error: "missing" });

    if (!(await verifyTurnstile(token, env.TURNSTILE_SECRET, ip))) {
      return reply(403, { ok: false, error: "captcha" });
    }

    try {
      const raw = buildEmail(f, env.FROM_ADDRESS, env.TO_ADDRESS);
      await env.MAILER.send(new EmailMessage(env.FROM_ADDRESS, env.TO_ADDRESS, raw));
    } catch (err) {
      console.error("Sending failed:", err && err.message);
      return reply(502, { ok: false, error: "send" });
    }

    return reply(200, { ok: true });
  },
};

// Plain text, length-limited, no control characters.
// Only the message keeps its line breaks.
function clean(value, max, multiline) {
  let s = typeof value === "string" ? value : "";
  s = s.replace(/\r\n?/g, "\n");
  s = multiline ? s.replace(/[^\S\n]+/g, " ") : s.replace(/\s+/g, " ");
  s = s.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, "");
  return s.trim().slice(0, max);
}

async function verifyTurnstile(token, secret, ip) {
  if (!token || !secret) return false;
  const body = new FormData();
  body.append("secret", secret);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
    });
    const result = await res.json();
    return result.success === true;
  } catch (err) {
    console.error("Turnstile check failed:", err && err.message);
    return false;
  }
}

const EMAIL_RE = /^[^\s@<>()",;:\\]+@[^\s@<>()",;:\\]+\.[^\s@<>()",;:\\]+$/;

function buildEmail(f, from, to) {
  const domain = from.split("@")[1];
  const body = [
    "Name: " + f.name,
    "Role and organization: " + (f.role || "-"),
    "Contact: " + f.contact,
    "Reaching out as: " + (f.type || "-"),
    "",
    "Message:",
    f.message || "-",
  ].join("\n");

  const headers = [
    "From: tiomking.com contact form <" + from + ">",
    "To: <" + to + ">",
    "Subject: " + encodeWord("פנייה מהאתר / Website inquiry: " + f.name),
    "Date: " + new Date().toUTCString(),
    "Message-ID: <" + crypto.randomUUID() + "@" + domain + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
  ];
  // Lets you press "Reply" and answer the visitor directly
  if (EMAIL_RE.test(f.contact)) headers.push("Reply-To: <" + f.contact + ">");

  return headers.join("\r\n") + "\r\n\r\n" + base64(body).replace(/.{1,76}/g, "$&\r\n");
}

// RFC 2047 encoded-word, so Hebrew survives in the subject line
function encodeWord(s) {
  return "=?UTF-8?B?" + base64(s) + "?=";
}

function base64(s) {
  let bin = "";
  for (const byte of new TextEncoder().encode(s)) bin += String.fromCharCode(byte);
  return btoa(bin);
}
