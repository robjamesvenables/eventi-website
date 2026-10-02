const { checkCode, readCookie } = require('./_codes');
module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'private, no-store');
  const r = checkCode(readCookie(req));
  if (!r.ok) return res.status(r.reason === 'notset' ? 503 : 401).json(r);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(require('./_tourhtml'));
};
