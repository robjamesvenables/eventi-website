// One-phone lock for preview codes.
// The first device that unlocks with a code "claims" it: we store sha256(device key) for that
// code in Supabase (table public.tour_code_claims, RLS on, no policies - only the service key
// can touch it). The device key itself lives only in that browser's HttpOnly cookie (mv_dev).
// Any other device presenting the same code is refused.
// If the Supabase settings aren't in Vercel yet, the lock is simply off (old behaviour).
const crypto = require('crypto');
const URL_ = (process.env.MAVIS_SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = process.env.MAVIS_SUPABASE_SERVICE_KEY || '';
const DEV_COOKIE = 'mv_dev';

function lockEnabled(){ return !!(URL_ && KEY); }
function hash(s){ return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function readDevice(req){
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)mv_dev=([a-f0-9]{64})/);
  return m ? m[1] : '';
}
function newDevice(){ return crypto.randomBytes(32).toString('hex'); }
function deviceCookie(dev){ return `${DEV_COOKIE}=${dev}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`; }

async function sb(path, opts){
  const r = await fetch(URL_ + '/rest/v1/' + path, Object.assign({}, opts, { headers: Object.assign({
    apikey: KEY, Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' }, (opts && opts.headers) || {}) }));
  return r;
}
async function getClaim(code){
  const r = await sb('tour_code_claims?select=device_hash&code=eq.' + encodeURIComponent(code), { method: 'GET' });
  if (!r.ok) throw new Error('lookup ' + r.status);
  const rows = await r.json();
  return rows[0] ? rows[0].device_hash : null;
}

// returns 'ok' | 'claimed' ; throws on database trouble
async function claimOrCheck(code, dev){
  const h = hash(dev);
  const existing = await getClaim(code);
  if (existing) return existing === h ? 'ok' : 'claimed';
  const r = await sb('tour_code_claims', { method: 'POST', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ code, device_hash: h }) });
  if (r.ok) return 'ok';
  if (r.status === 409) { const again = await getClaim(code); return again === h ? 'ok' : 'claimed'; }
  throw new Error('insert ' + r.status);
}
async function check(code, dev){
  if (!dev) return 'claimed';
  const existing = await getClaim(code);
  return existing && existing === hash(dev) ? 'ok' : 'claimed';
}
module.exports = { lockEnabled, readDevice, newDevice, deviceCookie, claimOrCheck, check };
