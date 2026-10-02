const { makeCode, samePassword, secret } = require('./_codes');
module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  const body = typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body) } catch (e) { return {} } })() : (req.body || {});
  if (!secret() || !process.env.MAVIS_ADMIN_PASSWORD) return res.status(503).json({ ok: false, reason: 'notset' });
  if (!samePassword(body.password)) return res.status(401).json({ ok: false, reason: 'password' });
  return res.status(200).json({ ok: true, ...makeCode(body.name, body.hours) });
};
