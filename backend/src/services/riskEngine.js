const pool = require('../config/db');
const axios = require('axios');
const tls = require('tls');
const { getRootDomain, getHostname } = require('../utils/domainUtils');
const { similarityPercent } = require('../utils/levenshtein');

const rdapCache = new Map(); // key -> { expiresAt, createdAt }

async function getTrustedBrands() {
  const [rows] = await pool.query('SELECT * FROM TrustedBrands');
  return rows;
}

function daysBetween(date) {
  const ms = Date.now() - date.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

async function getDomainCreatedAtRdap(rootDomain) {
  const cached = rdapCache.get(rootDomain);
  if (cached && cached.expiresAt > Date.now()) return cached.createdAt;

  const url = `https://rdap.org/domain/${encodeURIComponent(rootDomain)}`;
  const resp = await axios.get(url, { timeout: 5000, validateStatus: () => true });
  if (resp.status < 200 || resp.status >= 300) return null;

  const events = Array.isArray(resp.data?.events) ? resp.data.events : [];
  const createdEvent =
    events.find((e) => String(e?.eventAction || '').toLowerCase() === 'registration') ||
    events.find((e) => String(e?.eventAction || '').toLowerCase() === 'created') ||
    events.find((e) => String(e?.eventAction || '').toLowerCase() === 'registered');

  const createdAt = createdEvent?.eventDate ? new Date(createdEvent.eventDate) : null;
  if (!createdAt || Number.isNaN(createdAt.getTime())) return null;

  rdapCache.set(rootDomain, { createdAt, expiresAt: Date.now() + 6 * 60 * 60 * 1000 }); // 6h
  return createdAt;
}

async function checkDomainAge(url, reasons) {
  let score = 0;
  const rootDomain = getRootDomain(url);
  if (!rootDomain) return { score, reasons };

  try {
    const createdAt = await getDomainCreatedAtRdap(rootDomain);
    if (!createdAt) return { score, reasons };

    const ageDays = daysBetween(createdAt);
    if (ageDays < 14) {
      score += 15;
      reasons.push(`New domain (${ageDays} days old)`);
    } else if (ageDays < 90) {
      score += 10;
      reasons.push(`Recently created domain (${ageDays} days old)`);
    }
  } catch {
    // ignore rdap errors
  }

  return { score, reasons };
}

function certLooksValidForHost(cert, hostname) {
  const host = String(hostname || '').toLowerCase();
  if (!host) return true;

  const san = String(cert?.subjectaltname || '').toLowerCase();
  const cn = String(cert?.subject?.CN || cert?.subject?.commonName || '').toLowerCase();

  // Very simple match: SAN contains host, or CN matches host or a wildcard for its suffix.
  if (san.includes(host)) return true;
  if (cn === host) return true;
  if (cn.startsWith('*.')) {
    const suffix = cn.slice(1); // ".example.com"
    if (host.endsWith(suffix)) return true;
  }
  return false;
}

async function checkTlsCertificate(url, reasons) {
  let score = 0;
  if (!url.startsWith('https://')) return { score, reasons };

  const hostname = getHostname(url);
  if (!hostname) return { score, reasons };

  await new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: 2500
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (!cert || !cert.valid_to) return;

          const validTo = new Date(cert.valid_to);
          if (!Number.isNaN(validTo.getTime()) && validTo.getTime() < Date.now()) {
            score += 10;
            reasons.push('TLS certificate expired');
          }

          if (!certLooksValidForHost(cert, hostname)) {
            score += 8;
            reasons.push('TLS certificate hostname mismatch');
          }
        } catch {
          // ignore
        }
      }
    );

    socket.on('error', () => resolve());
    socket.on('timeout', () => {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve();
    });
    socket.on('secureConnect', () => {
      try {
        socket.end();
      } catch {
        // ignore
      }
      resolve();
    });
  });

  return { score, reasons };
}

async function checkBrandAuthenticity(url, reasons) {
  let score = 0;
  const hostname = getHostname(url);
  const rootDomain = getRootDomain(url);
  if (!hostname || !rootDomain) return { score, reasons };

  const brands = await getTrustedBrands();

  for (const brand of brands) {
    const brandName = brand.brand_name.toLowerCase();
    const officialDomain = brand.official_domain.toLowerCase();

    if (!hostname.toLowerCase().includes(brandName)) continue;

    if (rootDomain === officialDomain) {
      continue; // exact match
    }

    const sim = similarityPercent(rootDomain, officialDomain);
    if (sim > 80 && rootDomain !== officialDomain) {
      score += 12;
      reasons.push(`Brand impersonation risk for ${brandName} (similar domain)`);
    }

    if (!rootDomain.endsWith(officialDomain) && hostname.includes(brandName)) {
      score += 8;
      reasons.push(`Brand only in subdomain for ${brandName}`);
    }
  }

  return { score, reasons };
}

async function checkRedirects(url, reasons) {
  let score = 0;
  try {
    const response = await axios.get(url, {
      maxRedirects: 10,
      validateStatus: () => true
    });

    const redirects = response.request._redirectable._redirectCount || 0;
    if (redirects > 2) {
      score += 6;
      reasons.push(`Redirect chain length: ${redirects}`);
    }
  } catch {
    reasons.push('Error while checking redirects');
  }
  return { score, reasons };
}

async function checkThreatAPIs(url, reasons) {
  let score = 0;
  // To keep it simple: we skip real API until later
  return { score, reasons };
}

function checkStaticSignals(url, reasons) {
  let score = 0;

  let hostname = null;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return { score, reasons };
  }

  if (!url.startsWith('https://')) {
    score += 5;
    reasons.push('No HTTPS detected');
  }

  const suspiciousWords = ['login-secure', 'verification', 'update-account', 'confirm', 'free-gift'];
  const lowerUrl = url.toLowerCase();
  if (suspiciousWords.some(w => lowerUrl.includes(w))) {
    score += 6;
    reasons.push('Suspicious keywords in URL');
  }

  // Unofficial / unknown / ad-redirect style signals (free heuristics)
  const suspiciousTlds = new Set([
    'xyz',
    'top',
    'click',
    'live',
    'loan',
    'work',
    'support',
    'monster',
    'gq',
    'tk',
    'site',
    'fun',
    'online',
    'vip',
    'bet'
  ]);

  const hostLower = hostname.toLowerCase();
  const hostParts = hostLower.split('.').filter(Boolean);
  const tld = hostParts.length ? hostParts[hostParts.length - 1] : '';

  const isIpHost = /^[0-9.]+$/.test(hostLower) || /^\[[0-9a-f:]+\]$/i.test(hostLower);
  if (isIpHost) {
    score += 12;
    reasons.push('Hostname is an IP address (common in phishing)');
  }

  if (hostLower.startsWith('xn--') || hostLower.includes('.xn--')) {
    score += 10;
    reasons.push('Punycode domain detected (possible lookalike)');
  }

  if (suspiciousTlds.has(tld)) {
    score += 8;
    reasons.push(`Suspicious TLD detected (.${tld})`);
  }

  const hyphenCount = (hostLower.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 4;
    reasons.push('Many hyphens in hostname');
  }

  const digitCount = (hostLower.match(/[0-9]/g) || []).length;
  if (digitCount >= 5) {
    score += 4;
    reasons.push('Many digits in hostname');
  } else if (/[0-9]{3,}/.test(hostLower)) {
    score += 3;
    reasons.push('Suspicious digit pattern in hostname');
  }

  if (hostLower.length >= 35) {
    score += 4;
    reasons.push('Very long hostname');
  }

  if (hostParts.length >= 4) {
    score += 4;
    reasons.push('Deep subdomain chain');
  }

  // URL shorteners / ad intermediaries (often used in redirect chains)
  const redirectIntermediaries = new Set([
    'bit.ly',
    't.co',
    'tinyurl.com',
    'rb.gy',
    'cutt.ly',
    'goo.gl',
    'lnkd.in',
    'fb.me'
  ]);
  const root2 = hostParts.slice(-2).join('.');
  if (redirectIntermediaries.has(hostLower) || redirectIntermediaries.has(root2)) {
    score += 10;
    reasons.push('Known redirect/shortener domain');
  }

  // If it looks like an ad click/affiliate jump (not always malicious, but riskier when redirected)
  const adParams = ['gclid=', 'fbclid=', 'utm_source=', 'utm_medium=', 'utm_campaign=', 'ref=', 'aff=', 'affiliate='];
  if (adParams.some(p => lowerUrl.includes(p))) {
    score += 2;
    reasons.push('Ad/affiliate tracking parameters');
  }

  return { score, reasons };
}

function classifyScore(totalScore) {
  if (totalScore <= 5) return 'safe';
  if (totalScore <= 15) return 'suspicious';
  return 'dangerous';
}

function scoreToPercent(totalScore) {
  // Simple normalization so UI can use 0–100% thresholds (free, deterministic).
  // Tune MAX_SCORE as you add more signals.
  const MAX_SCORE = 40;
  const pct = Math.round((Math.max(0, totalScore) / MAX_SCORE) * 100);
  return Math.max(0, Math.min(100, pct));
}

async function logResult({ userId, url, totalScore, status, reasons }) {
  const [res] = await pool.query(
    'INSERT INTO URLLogs (user_id, url, risk_score, status) VALUES (?, ?, ?, ?)',
    [userId || null, url, totalScore, status]
  );
  const urlId = res.insertId;
  for (const r of reasons) {
    await pool.query(
      'INSERT INTO ThreatReasons (url_id, reason, score_added) VALUES (?, ?, ?)',
      [urlId, r, 0]
    );
  }
  return urlId;
}

async function evaluateUrl(url, userId = null, context = {}) {
  let reasons = [];
  let totalScore = 0;

  const brandRes = await checkBrandAuthenticity(url, reasons);
  totalScore += brandRes.score;
  reasons = brandRes.reasons;

  // If browser navigation indicates redirect, add risk (fast client-side signal).
  if (context && context.redirected) {
    totalScore += 6;
    reasons.push('Browser navigation shows redirect');
  }
  if (context && context.externalLikely) {
    totalScore += 4;
    reasons.push('Likely opened from external app (no referrer)');
  }
  if (context && context.popupSpam) {
    totalScore += 8;
    reasons.push('Popup/new-tab spam behavior detected');
  }

  const redirRes = await checkRedirects(url, reasons);
  totalScore += redirRes.score;
  reasons = redirRes.reasons;

  const apiRes = await checkThreatAPIs(url, reasons);
  totalScore += apiRes.score;
  reasons = apiRes.reasons;

  const ageRes = await checkDomainAge(url, reasons);
  totalScore += ageRes.score;
  reasons = ageRes.reasons;

  const tlsRes = await checkTlsCertificate(url, reasons);
  totalScore += tlsRes.score;
  reasons = tlsRes.reasons;

  const staticRes = checkStaticSignals(url, reasons);
  totalScore += staticRes.score;
  reasons = staticRes.reasons;

  const status = classifyScore(totalScore);
  const riskPercent = scoreToPercent(totalScore);
  const safetyPercent = Math.max(0, Math.min(100, 100 - riskPercent));
  const urlId = await logResult({ userId, url, totalScore, status, reasons });

  return { urlId, totalScore, riskPercent, safetyPercent, status, reasons };
}

module.exports = { evaluateUrl };