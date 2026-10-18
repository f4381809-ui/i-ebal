// POST /api/login  { "password": "..." }  ->  { "token": "..." }
// Пароль проверяется на сервере и берётся из переменной окружения ADMIN_PASSWORD.
const { redis, makeToken, safeEq, send, readBody, clientIp } = require("../lib/kv");

module.exports = async (req, res) => {
  if (req.method !== "POST") return send(res, 405, { error: "method" });
  if (!process.env.ADMIN_PASSWORD) return send(res, 500, { error: "ADMIN_PASSWORD не задан" });
  try {
    const key = "istoki:fail:" + clientIp(req);
    const [n] = await redis([["INCR", key]]);
    if (n === 1) await redis([["EXPIRE", key, 900]]);
    if (n > 10) return send(res, 429, { error: "too many attempts" }, { "Retry-After": "900" });
    const body = await readBody(req);
    if (typeof body.password !== "string" || !safeEq(body.password, process.env.ADMIN_PASSWORD)) {
      return send(res, 401, { error: "bad password" });
    }
    await redis([["DEL", key]]);
    return send(res, 200, { token: makeToken(12) });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e) });
  }
};
