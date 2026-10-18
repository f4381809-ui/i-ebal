// GET /api/state  -> { rev, t, data }       (читают все посетители)
// PUT /api/state  { data }  -> { rev }      (только администратор: заголовок Authorization: Bearer <token>)
const { redis, checkToken, send, readBody } = require("../lib/kv");

const KEY = "istoki:state";
const KEYS = ["CST", "UZ", "CATS", "OV", "CFG", "PLAYERS"];
const LIMITS = { CST: 5000, UZ: 3000, CATS: 200, PLAYERS: 500 };
const MAX_BYTES = 900000;

function validate(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return "data должно быть объектом";
  for (const k of Object.keys(d)) if (!KEYS.includes(k)) return "неизвестное поле " + k;
  for (const k of Object.keys(LIMITS)) if (d[k] !== undefined && (!Array.isArray(d[k]) || d[k].length > LIMITS[k])) return "поле " + k + " неверно";
  for (const k of ["OV", "CFG"]) if (d[k] != null && (typeof d[k] !== "object" || Array.isArray(d[k]))) return "поле " + k + " неверно";
  return null;
}

module.exports = async (req, res) => {
  try {
    if (req.method === "GET") {
      const [raw] = await redis([["GET", KEY]]);
      const st = raw ? JSON.parse(raw) : { rev: 0, t: 0, data: null };
      return send(res, 200, st, { "Cache-Control": "public, s-maxage=3, stale-while-revalidate=10" });
    }
    if (req.method === "PUT") {
      const auth = String((req.headers && (req.headers.authorization || req.headers.Authorization)) || "");
      if (!checkToken(auth.replace(/^Bearer\s+/i, ""))) return send(res, 401, { error: "нужен вход администратора" });
      const body = await readBody(req);
      const bad = validate(body.data);
      if (bad) return send(res, 400, { error: bad });
      const text = JSON.stringify(body.data);
      if (text.length > MAX_BYTES) return send(res, 413, { error: "слишком большие данные" });
      const [cur] = await redis([["GET", KEY]]);
      const rev = (cur ? JSON.parse(cur).rev || 0 : 0) + 1;
      await redis([["SET", KEY, JSON.stringify({ rev, t: Date.now(), data: body.data })]]);
      return send(res, 200, { rev });
    }
    return send(res, 405, { error: "method" });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e) });
  }
};
