const axios = require('axios');
const fs = require('fs');
const dns = require('dns').promises;
const puppeteer = require('puppeteer');

let sharedBrowser = null;

async function getBrowser() {
  if (!sharedBrowser) {
    sharedBrowser = await puppeteer.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  }
  return sharedBrowser;
}

// Subdomains where B2B startups typically host their product, billing or auth
const SUBDOMAINS = ['www', 'app', 'dashboard', 'portal', 'billing', 'account', 'my', 'admin', 'login', 'checkout', 'pay', 'console', 'panel', 'secure', 'members', 'client', 'platform', 'store', 'shop'];

// Everything that proves Stripe runs on a page, from strongest to weakest
const STRIPE_HTML_PATTERNS = [
  'pk_live_', 'pk_test_',                       // Stripe publishable API keys
  'stripe.elements', 'stripejs',                // Stripe Elements / JS SDK
  'stripeenvironment',                          // API params like ?stripeEnvironment=...
  'js.stripe.com', 'checkout.stripe.com',       // Checkout / Elements hosts
  'buy.stripe.com', 'pay.stripe.com',           // Stripe Payment Links / hosted payment pages
  'stripe-verification',                        // Stripe custom domain verification
  'stripe.com',                                 // Generic link/reference
  'stripe('                                     // window.Stripe() init calls
];

function hasStripeInHtml(html) {
  const lower = (html || '').toLowerCase();
  return STRIPE_HTML_PATTERNS.some(pattern => lower.includes(pattern));
}

function hasStripeCookie(cookieString) {
  const lower = (cookieString || '').toLowerCase();
  return lower.includes('__stripe') || lower.includes('stripe');
}

/**
 * Fast HTTP check (no JS execution). Looks for cookies, HTML references and CSP headers.
 */
async function checkUrlWaterfall(url) {
  try {
    const response = await axios.get(url, {
      timeout: 7000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
      }
    });

    const html = response.data || '';
    const headers = response.headers || {};

    // STEP 1: Stripe fraud-prevention cookies (__stripe_mid, __stripe_sid, ...)
    const rawCookies = headers['set-cookie'] || [];
    if (hasStripeCookie(rawCookies.join(' '))) {
      return { found: true, method: 'Stripe Cookies Detected' };
    }

    // STEP 2: Stripe references in HTML (keys, SDKs, payment links, hosts)
    if (hasStripeInHtml(html)) {
      return { found: true, method: 'Stripe References Found in HTML' };
    }

    // STEP 3: Content Security Policy header whitelisting Stripe
    const csp = headers['content-security-policy'] || '';
    if (csp.toLowerCase().includes('stripe')) {
      return { found: true, method: 'Stripe Whitelisted in CSP Headers' };
    }

    return { found: false, method: 'No signals found' };

  } catch (error) {
    // Subdomain likely doesn't exist (DNS error) or is bot-blocked; let the orchestrator move on
    return { found: false, method: `Connection failed (${error.message})` };
  }
}

/**
 * Full browser check: executes JS, watches all network requests and reads real cookies.
 * Catches Stripe loaded dynamically, after consent banners, or behind login walls.
 */
async function checkUrlWithBrowser(url) {
  try {
    const browser = await getBrowser();
    const page = await browser.newPage();
    let stripeHit = false;

    page.on('request', req => {
      if (req.url().toLowerCase().includes('stripe')) stripeHit = true;
    });

    const response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });

    // CSP from the final (post-redirect) response
    const csp = (response && response.headers()['content-security-policy']) || '';
    if (csp.toLowerCase().includes('stripe')) {
      await page.close();
      return { found: true, method: 'Stripe Whitelisted in CSP Headers (browser)' };
    }

    // Give consent banners / lazy-loaded scripts time to fire
    await new Promise(resolve => setTimeout(resolve, 2000));

    const cookies = await page.cookies();
    const html = await page.content();
    await page.close();

    if (cookies.some(c => hasStripeCookie(c.name))) {
      return { found: true, method: 'Stripe Cookies Detected (via browser JS)' };
    }
    if (stripeHit) {
      return { found: true, method: 'Stripe Network Request Detected (via browser JS)' };
    }
    if (hasStripeInHtml(html)) {
      return { found: true, method: 'Stripe References in Rendered HTML (via browser JS)' };
    }

    return { found: false, method: 'No signals in browser' };

  } catch (error) {
    return { found: false, method: `Browser check failed (${error.message})` };
  }
}

/**
 * DNS TXT record check: Stripe writes a stripe-verification TXT record on the
 * apex domain when verifying custom domains / branded payment links.
 */
async function checkDnsStripeTxt(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    return records.some(parts => parts.join('').toLowerCase().includes('stripe'));
  } catch (error) {
    return false;
  }
}

/**
 * Lead orchestrator: DNS check -> fast HTTP checks on apex + all subdomains ->
 * browser (JS) checks on the most likely product/billing spots.
 */
async function qualifyLead(domain) {
  const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '');

  // PHASE 0: DNS TXT verification record
  if (await checkDnsStripeTxt(cleanDomain)) {
    return { domain: cleanDomain, status: 'YES', trace: 'Stripe DNS Verification Record Found' };
  }

  // PHASE 1: Fast HTTP checks on apex + every known subdomain
  const urls = [`https://${cleanDomain}`, ...SUBDOMAINS.map(s => `https://${s}.${cleanDomain}`)];
  console.log(`[Phase 1 - HTTP checks] ${urls.length} URLs for ${cleanDomain}...`);

  for (const url of urls) {
    const result = await checkUrlWaterfall(url);
    if (result.found) {
      return { domain: cleanDomain, status: 'YES', trace: `${result.method} (${url})` };
    }
  }

  // PHASE 2: Browser (JS execution) checks on the spots where the product actually lives
  const browserUrls = [
    `https://${cleanDomain}`,
    `https://app.${cleanDomain}`,
    `https://dashboard.${cleanDomain}`,
    `https://portal.${cleanDomain}`,
    `https://billing.${cleanDomain}`,
    `https://account.${cleanDomain}`,
    `https://my.${cleanDomain}`,
    `https://admin.${cleanDomain}`
  ];
  console.log(`[Phase 2 - Browser checks] ${browserUrls.length} URLs for ${cleanDomain}...`);

  for (const url of browserUrls) {
    const result = await checkUrlWithBrowser(url);
    if (result.found) {
      return { domain: cleanDomain, status: 'YES', trace: `${result.method} (${url})` };
    }
  }

  return { domain: cleanDomain, status: 'NO', trace: 'No Stripe signals across DNS, HTTP and browser checks.' };
}

// ==========================================
// CLI
// ==========================================
async function runScanner() {
  const args = process.argv.slice(2);
  const batchArgIndex = args.findIndex(a => a === '--batch' || a === '-b');
  const concurrency = batchArgIndex >= 0 ? parseInt(args[batchArgIndex + 1], 10) || 1 : 1;
  const inputFile = batchArgIndex >= 0
    ? args.filter((a, i) => i !== batchArgIndex && i !== batchArgIndex + 1 && !a.startsWith('-'))[0]
    : args.filter(a => !a.startsWith('-'))[0];

  const targets = inputFile
    ? fs.readFileSync(inputFile, 'utf8').split(/\r?\n/).map(t => t.trim()).filter(Boolean)
    : ['slack.com', 'shopify.com', 'wikipedia.org'];

  console.log(`Starting Stripe Qualification scan for ${targets.length} targets (batch: ${concurrency})...\n`);

  const results = [];
  let index = 0;

  async function worker() {
    while (index < targets.length) {
      const current = index++;
      const assessment = await qualifyLead(targets[current]);
      results[current] = assessment;
      console.log(`${assessment.domain} -> ${assessment.status} | ${assessment.trace}`);
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));

  console.log('\nFINAL RESULTS');
  console.log('---------------------------------------------------------------------------------------------------');
  for (const assessment of results) {
    console.log(`${assessment.domain} | ${assessment.status} | ${assessment.trace}`);
    console.log('---------------------------------------------------------------------------------------------------');
  }

  if (sharedBrowser) await sharedBrowser.close();
}

runScanner();