const { checkCode, COOKIE } = require('./_codes');
module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  const body = typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body) } catch (e) { return {} } })() : (req.body || {});
  const r = checkCode(body.code);
  if (!r.ok) return res.status(r.reason === 'notset' ? 503 : 401).json(r);
  const code = String(body.code).toUpperCase().replace(/\s+/g, '');
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(code)}; Path=/; Max-Age=${r.secondsLeft}; HttpOnly; Secure; SameSite=Lax`);
  return res.status(200).json({ ok: true });
};
