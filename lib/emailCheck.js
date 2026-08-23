const dns = require('dns').promises;

const EMAIL_RE = /^[^\s@]+@([^\s@]+\.[^\s@]{2,})$/;

const DISPOSABLE = new Set([
    'mailinator.com', 'tempmail.com', 'temp-mail.org', '10minutemail.com',
    'guerrillamail.com', 'yopmail.com', 'trashmail.com', 'throwawaymail.com',
    'getnada.com', 'dispostable.com', 'fakeinbox.com', 'sharklasers.com'
  ]);

async function domainAcceptsMail(domain) {
    try {
          const mx = await dns.resolveMx(domain);
          if (mx && mx.length) return true;
    } catch (e) { }
    try {
          const a = await dns.resolve(domain);
          return !!(a && a.length);
    } catch (e) {
          try {
                  const aaaa = await dns.resolve6(domain);
                  return !!(aaaa && aaaa.length);
          } catch (e2) {
                  return false;
          }
    }
}

async function checkEmail(raw) {
    const email = String(raw || '').trim().toLowerCase();
    const m = EMAIL_RE.exec(email);
    if (!m) return { valid: false, reason: 'formato' };

  const domain = m[1];
    if (DISPOSABLE.has(domain)) return { valid: false, reason: 'descartavel' };

  const ok = await domainAcceptsMail(domain);
    if (!ok) return { valid: false, reason: 'dominio' };

  return { valid: true };
}

module.exports = { checkEmail, EMAIL_RE };
