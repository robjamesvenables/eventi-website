const { checkCode, readCookie } = require('./_codes');
const L = require('./_claims');
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'private, no-store');
  const code = readCookie(req);
  const r = checkCode(code);
  if (!r.ok) return res.status(r.reason === 'notset' ? 503 : 401).json(r);
  if (L.lockEnabled()) {
    let state;
    try { state = await L.check(code.toUpperCase().replace(/\s+/g, ''), L.readDevice(req)); }
    catch (e) { return res.status(503).json({ ok: false, reason: 'busy' }); }
    if (state !== 'ok') return res.status(401).json({ ok: false, reason: 'claimed' });
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(require('./_tourhtml'));
};
