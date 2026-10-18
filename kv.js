// Общие функции сервера: доступ к Upstash Redis (через REST), подпись токенов, чтение тела запроса.
const crypto = require("crypto");

const kvUrl = () => process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const kvToken = () => process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

// Выполняет список команд Redis одним запросом. Пример: redis([["GET","key"],["INCR","n"]])
async function redis(cmds) {
  const url = kvUrl(), token = kvToken();
  if (!url || !token) throw new Error("Хранилище не подключено (нет KV_REST_API_URL / KV_REST_API_TOKEN)");
  const r = await fetch(url.replace(/\/$/, "") + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new Error("Redis: HTTP " + r.status);
  const out = await r.json();
  return out.map((x) => { if (x.error) throw new Error(x.error); return x.result; });
}

const secret = () => process.env.AUTH_SECRET || "istoki:" + (process.env.ADMIN_PASSWORD || "");
const sign = (payload) => crypto.createHmac("sha256", secret()).update(payload).digest("base64url");

function makeToken(hours = 12) {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + hours * 3600 * 1000 })).toString("base64url");
  return p + "." + sign(p);
}

function checkToken(t) {
  if (!t || typeof t !== "string") return false;
  const [p, s] = t.split(".");
  if (!p || !s) return false;
  const e = sign(p);
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return false;
  try { return JSON.parse(Buffer.from(p, "base64url").toString()).exp > Date.now(); } catch (e2) { return false; }
}

// Сравнение паролей за одинаковое время
function safeEq(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function send(res, status, obj, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const k of Object.keys(headers)) res.setHeader(k, headers[k]);
  res.end(JSON.stringify(obj));
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let raw = typeof req.body === "string" ? req.body : "";
  if (!raw && typeof req.on === "function") {
    raw = await new Promise((resolve) => {
      let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => resolve(d)); req.on("error", () => resolve(""));
    });
  }
  try { return raw ? JSON.parse(raw) : {}; } catch (e) { return {}; }
}

const clientIp = (req) => String((req.headers && req.headers["x-forwarded-for"]) || "").split(",")[0].trim() || (req.socket && req.socket.remoteAddress) || "unknown";

module.exports = { redis, makeToken, checkToken, safeEq, send, readBody, clientIp };
