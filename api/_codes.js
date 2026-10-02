// Mavis private-preview access codes.
// A code looks like SAMSUNG-K7Q4XM2P: the client name, then 3 characters holding the
// expiry time and 5 characters of signature made with a secret only the server knows
// (MAVIS_CODE_SECRET). Nothing is stored: the server re-computes the signature to check
// a code is genuine, and reads the expiry straight out of the code.
// Emergency switch: change MAVIS_CODE_SECRET in Vercel and every existing code stops working.
const crypto = require('crypto');

const BASE_MS = Date.UTC(2026, 0, 1);            // expiry counted in hours from 1 Jan 2026
const B32 = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';    // no 0/1/I/L/O so codes are easy to read
const COOKIE = 'mv_tour';

function secret(){ return process.env.MAVIS_CODE_SECRET || ''; }

function cleanName(name){
  const n = String(name || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
  return n || 'GUEST';
}

function sign(name, expStr){
  const h = crypto.createHmac('sha256', secret()).update(name + '|' + expStr).digest();
  let out = '';
  for (let i = 0; i < 5; i++) out += B32[h[i] % B32.length];
  return out;
}

function makeCode(name, hours){
  const n = cleanName(name);
  const nowH = Math.ceil((Date.now() - BASE_MS) / 3600000);
  const exp = nowH + Math.max(1, Math.min(24 * 30, Math.round(Number(hours) || 24)));
  const expStr = exp.toString(36).toUpperCase().padStart(3, '0');
  return { code: n + '-' + expStr + sign(n, expStr), expiresAt: new Date(BASE_MS + exp * 3600000).toISOString() };
}

// returns {ok:true, secondsLeft} or {ok:false, reason:'invalid'|'expired'|'notset'}
function checkCode(raw){
  if (!secret()) return { ok: false, reason: 'notset' };
  const s = String(raw || '').toUpperCase().replace(/\s+/g, '');
  const i = s.lastIndexOf('-');
  if (i < 1) return { ok: false, reason: 'invalid' };
  const name = s.slice(0, i), tail = s.slice(i + 1);
  if (tail.length !== 8 || cleanName(name) !== name) return { ok: false, reason: 'invalid' };
  const expStr = tail.slice(0, 3), sig = tail.slice(3);
  const good = sign(name, expStr);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return { ok: false, reason: 'invalid' };
  const exp = parseInt(expStr, 36);
  if (!Number.isFinite(exp)) return { ok: false, reason: 'invalid' };
  const left = Math.floor((BASE_MS + exp * 3600000 - Date.now()) / 1000);
  if (left <= 0) return { ok: false, reason: 'expired' };
  return { ok: true, secondsLeft: left };
}

function readCookie(req){
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)mv_tour=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

function samePassword(given){
  const real = process.env.MAVIS_ADMIN_PASSWORD || '';
  if (!real) return false;
  const a = crypto.createHash('sha256').update(String(given || '')).digest();
  const b = crypto.createHash('sha256').update(real).digest();
  return crypto.timingSafeEqual(a, b);
}

module.exports = { makeCode, checkCode, readCookie, samePassword, COOKIE, secret };
