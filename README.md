# stripe-scout

A Node.js tool that detects whether a domain uses Stripe for payments.

## How it works

The scanner runs in 3 phases:

1. **DNS TXT check**: looks for Stripe verification records on the apex domain
2. **HTTP checks**: scans apex + 19 common subdomains for Stripe cookies, HTML patterns (API keys, SDK refs, payment links), and CSP headers
3. **Browser checks**: uses Puppeteer to execute JS and watch for Stripe network requests

Only strong signals count: a live publishable key, Stripe's SDK or hosted pages, `__stripe_` cookies, requests to Stripe's own hosts, Stripe product or price IDs in the site's own API responses, or a `stripe-verification=` record. A plain link to stripe.com or a Stripe logo on a page is not proof of an integration.

## Install

```bash
npm install
```

## Usage

```bash
node script.js                        # scan default targets (slack.com, shopify.com, wikipedia.org)
node script.js example.com            # scan single domain
node script.js targets.txt            # scan from file (one domain per line)
node script.js targets.txt -b 4       # batch with 4 concurrent workers
```

## Output

Each domain is classified as:

- **YES:** Stripe integration detected (with method and URL)
- **NO:** no Stripe signals found across DNS, HTTP and browser checks
