const { checkCode, COOKIE } = require('./_codes');
const L = require('./_claims');
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  const body = typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body) } catch (e) { return {} } })() : (req.body || {});
  const r = checkCode(body.code);
  if (!r.ok) return res.status(r.reason === 'notset' ? 503 : 401).json(r);
  const code = String(body.code).toUpperCase().replace(/\s+/g, '');
  const cookies = [`${COOKIE}=${encodeURIComponent(code)}; Path=/; Max-Age=${r.secondsLeft}; HttpOnly; Secure; SameSite=Lax`];
  if (L.lockEnabled()) {
    let dev = L.readDevice(req);
    if (!dev) dev = L.newDevice();
    cookies.push(L.deviceCookie(dev));
    let state;
    try { state = await L.claimOrCheck(code, dev); }
    catch (e) { return res.status(503).json({ ok: false, reason: 'busy' }); }
    if (state !== 'ok') { res.setHeader('Set-Cookie', [L.deviceCookie(dev)]); return res.status(401).json({ ok: false, reason: 'claimed' }); }
  }
  res.setHeader('Set-Cookie', cookies);
  return res.status(200).json({ ok: true });
};
