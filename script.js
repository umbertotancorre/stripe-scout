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

// Strong signals only: each one means a live Stripe integration, not just a mention of Stripe
const STRIPE_HTML_PATTERNS = [
  'pk_live_',                                   // Stripe live publishable API key
  'stripe.elements', 'stripejs',                // Stripe Elements / JS SDK
  'stripeenvironment',                          // API params like ?stripeEnvironment=...
  'js.stripe.com', 'checkout.stripe.com',       // Checkout / Elements hosts
  'buy.stripe.com', 'pay.stripe.com',           // Stripe Payment Links / hosted payment pages
  'billing.stripe.com', 'invoice.stripe.com',   // Customer portal / hosted invoices
  'stripe-verification'                         // Stripe custom domain verification
];

// Hosts Stripe serves its SDK, API and fraud checks from
const STRIPE_HOST = /(^|\.)stripe\.(com|network)$/;

function hasStripeInHtml(html) {
  const lower = (html || '').toLowerCase();
  return STRIPE_HTML_PATTERNS.some(pattern => lower.includes(pattern));
}

// Stripe.js sets __stripe_mid and __stripe_sid; other names containing "stripe" are not proof
function hasStripeCookie(cookieString) {
  return (cookieString || '').toLowerCase().includes('__stripe_');
}

// A CSP counts only when it allows a Stripe host, not when "stripe" appears elsewhere in it
function cspAllowsStripe(csp) {
  return /\bstripe\.(com|network)\b/i.test(csp || '');
}

// Stripe object IDs (price_1..., prod_..., cus_..., sub_..., in_...) in a site's own API responses
const STRIPE_OBJECT_ID = /"(price_1[A-Za-z0-9]{20,}|prod_[A-Za-z0-9]{14}|(cus|sub|in)_[A-Za-z0-9]{14,})"/;

// A call to Stripe's own hosts, or to the site's API with Stripe parameters (?stripeEnvironment=...)
function isStripeRequest(url) {
  try {
    const parsed = new URL(url);
    return STRIPE_HOST.test(parsed.hostname.toLowerCase()) || parsed.search.toLowerCase().includes('stripeenvironment');
  } catch {
    return false;
  }
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
    if (cspAllowsStripe(headers['content-security-policy'])) {
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
      if (isStripeRequest(req.url())) stripeHit = true;
    });

    // Catches apps that call Stripe from their backend and pass its IDs to the page
    let stripeIdHit = false;
    page.on('response', async res => {
      if (stripeIdHit || !(res.headers()['content-type'] || '').includes('json')) return;
      try {
        if (STRIPE_OBJECT_ID.test(await res.text())) stripeIdHit = true;
      } catch {
        // Body unavailable (redirect, aborted or closed page)
      }
    });

    // A slow page that never goes quiet still counts: keep the requests seen before the timeout
    let response = null;
    try {
      response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
    } catch (error) {
      if (error.name !== 'TimeoutError') throw error;
    }

    // CSP from the final (post-redirect) response
    const csp = (response && response.headers()['content-security-policy']) || '';
    if (cspAllowsStripe(csp)) {
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
    if (stripeIdHit) {
      return { found: true, method: 'Stripe Object IDs in API Response (via browser JS)' };
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
    return records.some(parts => parts.join('').toLowerCase().startsWith('stripe-verification='));
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

  let targets;
  if (!inputFile) {
    targets = ['slack.com', 'shopify.com', 'wikipedia.org'];
  } else if (inputFile.includes('.') && !inputFile.includes('/') && !inputFile.includes('\\')) {
    targets = [inputFile];
  } else {
    targets = fs.readFileSync(inputFile, 'utf8').split(/\r?\n/).map(t => t.trim()).filter(Boolean);
  }

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