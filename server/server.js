const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// Defense-in-depth: an uncaught error anywhere in a single request (a
// decryption failure on a stale credential, a malformed response from a
// broker, anything unforeseen) must never be able to take the whole
// process down for every connected user. Individual endpoints should
// still have their own try/catch for a clean, specific error response,
// this is the backstop for whatever one of them misses, not a substitute
// for fixing the actual gap when one is found (as happened twice already
// with decryptSecret() calls sitting outside their try block).
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION (process kept alive):', err.message, err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION (process kept alive):', reason);
});

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

// =========================================================================
// STRIPE BILLING
// =========================================================================
// Pragmatic choice: Stripe Checkout (hosted), not a custom payment form, so
// this app never touches card data or PCI compliance directly. Raw fetch
// calls against Stripe's REST API (Bearer auth, form-encoded bodies), same
// pattern as the Alpaca/eToro adapters, rather than the stripe npm SDK, to
// avoid a dependency this app doesn't otherwise need. Needs real Stripe
// keys to go live (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, and one Price
// ID per paid tier), with none of these set, the endpoints below fail
// gracefully with a clear "billing is not configured" message rather than
// silently pretending to work.
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || null;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || null;
const STRIPE_API_BASE = process.env.STRIPE_API_BASE || 'https://api.stripe.com';
const STRIPE_PRICE_IDS = { starter: process.env.STRIPE_PRICE_ID_STARTER || null, pro: process.env.STRIPE_PRICE_ID_PRO || null };
const APP_BASE_URL = process.env.APP_BASE_URL || '';

// Stripe expects application/x-www-form-urlencoded, with nested objects
// flattened into bracket notation (e.g. line_items[0][price]=xxx), not JSON.
function toStripeForm(obj, prefix) {
  const pairs = [];
  for (const key in obj) {
    if (obj[key] === undefined || obj[key] === null) continue;
    const name = prefix ? `${prefix}[${key}]` : key;
    const val = obj[key];
    if (typeof val === 'object' && !Array.isArray(val)) pairs.push(toStripeForm(val, name));
    else if (Array.isArray(val)) val.forEach((v, i) => pairs.push(typeof v === 'object' ? toStripeForm(v, `${name}[${i}]`) : `${encodeURIComponent(`${name}[${i}]`)}=${encodeURIComponent(v)}`));
    else pairs.push(`${encodeURIComponent(name)}=${encodeURIComponent(val)}`);
  }
  return pairs.join('&');
}
async function stripeRequest(method, urlPath, params) {
  const res = await fetch(STRIPE_API_BASE + urlPath, {
    method,
    headers: { 'Authorization': 'Bearer ' + STRIPE_SECRET_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params ? toStripeForm(params) : undefined,
  });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}
// Verifies Stripe's webhook signature header ("t=...,v1=...") by recomputing
// the HMAC-SHA256 of "timestamp.rawBody" with the webhook signing secret,
// without this, anyone who finds the webhook URL could fake a "payment
// succeeded" event and grant themselves a paid tier for free.
function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
  if (!parts.t || !parts.v1) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${parts.t}.${rawBody}`).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1)); } catch (e) { return false; }
}

// Registered before express.json() below: Stripe's signature check needs
// the exact raw bytes Stripe sent, and JSON-parsing then re-serializing the
// body is not guaranteed to reproduce them byte-for-byte, which would break
// verification.
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) return res.status(503).send('Billing is not configured on this deployment.');
  const sig = req.headers['stripe-signature'];
  const rawBody = req.body.toString('utf8');
  if (!verifyStripeSignature(rawBody, sig, STRIPE_WEBHOOK_SECRET)) return res.status(400).send('Invalid signature.');
  let event;
  try { event = JSON.parse(rawBody); } catch (e) { return res.status(400).send('Invalid payload.'); }
  try {
    const obj = event.data && event.data.object;
    if (event.type === 'checkout.session.completed' && obj.client_reference_id) {
      const tier = (obj.metadata && obj.metadata.tier) || 'starter';
      await pool.query('UPDATE users SET plan_tier=$1, stripe_customer_id=$2, stripe_subscription_id=$3, subscription_status=$4 WHERE username=$5',
        [tier, obj.customer, obj.subscription, 'active', obj.client_reference_id]);
    } else if (event.type === 'customer.subscription.updated') {
      const status = obj.status === 'active' || obj.status === 'trialing' ? 'active' : obj.status;
      await pool.query('UPDATE users SET subscription_status=$1 WHERE stripe_subscription_id=$2', [status, obj.id]);
      if (status !== 'active') await pool.query("UPDATE users SET plan_tier='free' WHERE stripe_subscription_id=$1", [obj.id]);
    } else if (event.type === 'customer.subscription.deleted') {
      await pool.query("UPDATE users SET plan_tier='free', subscription_status='canceled' WHERE stripe_subscription_id=$1", [obj.id]);
    }
    res.json({ received: true });
  } catch (e) {
    console.error('stripe webhook processing error:', e.message);
    res.status(500).send('Webhook processing error.');
  }
});

app.use(express.json({ limit: '2mb' })); // registered first, routes below depend on req.body being parsed

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL environment variable is not set.');
  process.exit(1);
}

const ENCRYPTION_KEY_RAW = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY_RAW) {
  console.error('FATAL: ENCRYPTION_KEY environment variable is not set (used to encrypt stored broker API secrets).');
  process.exit(1);
}
const ENC_KEY = crypto.createHash('sha256').update(ENCRYPTION_KEY_RAW).digest(); // always 32 bytes for AES-256

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}
function decryptSecret(encoded) {
  const buf = Buffer.from(encoded, 'base64');
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

const ALPACA_BASE_URL_DEFAULT = process.env.ALPACA_BASE_URL || 'https://paper-api.alpaca.markets';
const ETORO_BASE_URL_DEFAULT = process.env.ETORO_BASE_URL || 'https://public-api.etoro.com';
async function etoroRequest(baseUrl, apiKey, userKey, urlPath, options = {}) {
  return fetch(baseUrl + urlPath, {
    ...options,
    headers: Object.assign({
      'x-api-key': apiKey,
      'x-user-key': userKey,
      'x-request-id': crypto.randomUUID(),
      'Content-Type': 'application/json',
    }, options.headers || {}),
  });
}
async function alpacaRequest(baseUrl, apiKeyId, apiSecretKey, urlPath, options = {}) {
  return fetch(baseUrl + urlPath, {
    ...options,
    headers: Object.assign({
      'APCA-API-KEY-ID': apiKeyId,
      'APCA-API-SECRET-KEY': apiSecretKey,
      'Content-Type': 'application/json',
    }, options.headers || {}),
  });
}


// =========================================================================
// REAL LIVE EXECUTION ENGINE
// =========================================================================
// Fixes the gap where "Go live" only changed a status label with no actual
// broker automation behind it, and "Live Positions" were a client-side
// random simulation (`rnd() < 0.6`) with zero connection to any real
// account. This section makes "live" genuinely mean: a server-side loop
// periodically pulls REAL recent price bars for the strategy's symbol from
// Alpaca's market-data API, evaluates the strategy's actual entry
// conditions against them using the exact same indicator math already
// verified in the frontend backtest engine (ported below, byte-identical,
// cross-checked against the same RSI reference values used to verify the
// original), and if a signal genuinely fires, places a REAL bracket order
// (entry + take-profit + stop-loss legs, so Alpaca's own system, not a
// hopeful polling loop, handles the exit) through the user's connected
// Alpaca paper account. This is real automated execution against paper
// money, not simulated money against a real position, an important
// distinction: no real capital is ever at risk, but the mechanism itself is
// genuine, not decorative.
//
// Scope, stated plainly: this only works for plain US equity/ETF tickers
// (what Alpaca actually supports) via the Alpaca connection specifically.
// GCC instruments, forex, commodities, crypto Alpaca doesn't list, and every
// other broker on the Broker Connections page (Sahm, eToro, IBKR, MT5,
// TradeStation) remain explicitly simulated, there is no real market data
// or execution path for them, and "Go live" is blocked for them rather than
// silently pretending to work.
const ALPACA_DATA_BASE_URL = process.env.ALPACA_DATA_BASE_URL || 'https://data.alpaca.markets';
const LIVE_TICK_INTERVAL_MS = parseInt(process.env.LIVE_TICK_INTERVAL_MS, 10) || 60000;

function isAlpacaTradable(symbol) {
  // Plain US equity/ETF tickers only, no slashes (forex/crypto pairs), no
  // dots (GCC and other international suffixes like .SR/.DU/.QA/.L/.HK).
  return /^[A-Z]{1,5}$/.test(symbol);
}

function tfToAlpaca(tf) {
  return { '1m': '1Min', '5m': '5Min', '15m': '15Min', '30m': '30Min', '1H': '1Hour', '4H': '1Hour', '1D': '1Day' }[tf] || '15Min';
}

async function alpacaGetBars(baseUrl, apiKeyId, apiSecretKey, symbol, timeframe, limit) {
  const tf = tfToAlpaca(timeframe);
  const url = `${ALPACA_DATA_BASE_URL}/v2/stocks/${encodeURIComponent(symbol)}/bars?timeframe=${tf}&limit=${limit}`;
  const res = await fetch(url, { headers: { 'APCA-API-KEY-ID': apiKeyId, 'APCA-API-SECRET-KEY': apiSecretKey } });
  if (!res.ok) { const body = await res.text().catch(() => ''); throw new Error(`Alpaca bars request failed (${res.status}): ${body.slice(0, 200)}`); }
  const data = await res.json();
  const raw = data.bars || [];
  return raw.map(b => ({ open: b.o, high: b.h, low: b.l, close: b.c, volume: b.v }));
}

function computeSMA(values, period) {
  const out = new Array(values.length).fill(null);
  let sum = 0;
  for (let i = 0; i < values.length; i++) {
    sum += values[i];
    if (i >= period) sum -= values[i - period];
    if (i >= period - 1) out[i] = sum / period;
  }
  return out;
}

function computeEMA(values, period) {
  const out = new Array(values.length).fill(null);
  const k = 2 / (period + 1);
  let ema = null;
  for (let i = 0; i < values.length; i++) {
    if (ema === null) {
      if (i === period - 1) {
        // seed with SMA of the first `period` values
        let sum = 0;
        for (let j = 0; j <= i; j++) sum += values[j];
        ema = sum / period;
        out[i] = ema;
      }
    } else {
      ema = values[i] * k + ema * (1 - k);
      out[i] = ema;
    }
  }
  return out;
}

function computeRSI(closes, period) {
  const out = new Array(closes.length).fill(null);
  if (closes.length < period + 1) return out;
  let avgGain = 0, avgLoss = 0;
  for (let i = 1; i <= period; i++) {
    const change = closes[i] - closes[i - 1];
    if (change > 0) avgGain += change; else avgLoss += -change;
  }
  avgGain /= period; avgLoss /= period;
  out[period] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  for (let i = period + 1; i < closes.length; i++) {
    const change = closes[i] - closes[i - 1];
    const gain = change > 0 ? change : 0;
    const loss = change < 0 ? -change : 0;
    avgGain = (avgGain * (period - 1) + gain) / period;
    avgLoss = (avgLoss * (period - 1) + loss) / period;
    out[i] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  }
  return out;
}

function computeMACD(closes) {
  const ema12 = computeEMA(closes, 12);
  const ema26 = computeEMA(closes, 26);
  const macdLine = closes.map((_, i) => (ema12[i] !== null && ema26[i] !== null) ? ema12[i] - ema26[i] : null);
  const macdValuesOnly = macdLine.filter(v => v !== null);
  const signalRaw = computeEMA(macdValuesOnly, 9);
  const signalLine = new Array(closes.length).fill(null);
  let si = 0;
  for (let i = 0; i < closes.length; i++) {
    if (macdLine[i] !== null) { signalLine[i] = signalRaw[si] !== undefined ? signalRaw[si] : null; si++; }
  }
  const histogram = closes.map((_, i) => (macdLine[i] !== null && signalLine[i] !== null) ? macdLine[i] - signalLine[i] : null);
  return { macdLine, signalLine, histogram };
}

function computeBollingerBands(closes, period, mult) {
  const sma = computeSMA(closes, period);
  const upper = new Array(closes.length).fill(null);
  const lower = new Array(closes.length).fill(null);
  for (let i = period - 1; i < closes.length; i++) {
    let sumSq = 0;
    for (let j = i - period + 1; j <= i; j++) sumSq += Math.pow(closes[j] - sma[i], 2);
    const stdDev = Math.sqrt(sumSq / period);
    upper[i] = sma[i] + mult * stdDev;
    lower[i] = sma[i] - mult * stdDev;
  }
  return { upper, middle: sma, lower };
}

function computeRollingVWAP(bars, period) {
  const out = new Array(bars.length).fill(null);
  for (let i = 0; i < bars.length; i++) {
    if (i < period - 1) continue;
    let pvSum = 0, vSum = 0;
    for (let j = i - period + 1; j <= i; j++) {
      const typicalPrice = (bars[j].high + bars[j].low + bars[j].close) / 3;
      pvSum += typicalPrice * bars[j].volume;
      vSum += bars[j].volume;
    }
    out[i] = vSum > 0 ? pvSum / vSum : null;
  }
  return out;
}

// Stochastic Oscillator: %K measures where the close sits within the
// recent high/low range (0-100), %D is a 3-period SMA of %K used as a
// signal line for crossovers. Standard 14-period %K, 3-period %D.
function computeStochastic(bars, period) {
  const rawK = new Array(bars.length).fill(null);
  for (let i = period - 1; i < bars.length; i++) {
    let hh = -Infinity, ll = Infinity;
    for (let j = i - period + 1; j <= i; j++) { hh = Math.max(hh, bars[j].high); ll = Math.min(ll, bars[j].low); }
    rawK[i] = hh === ll ? 50 : 100 * (bars[i].close - ll) / (hh - ll);
  }
  const kValuesOnly = rawK.filter(v => v !== null);
  const dRaw = computeSMA(kValuesOnly, 3);
  const d = new Array(bars.length).fill(null);
  let di = 0;
  for (let i = 0; i < bars.length; i++) { if (rawK[i] !== null) { d[i] = dRaw[di] !== undefined ? dRaw[di] : null; di++; } }
  return { k: rawK, d };
}

// Average True Range, Wilder's smoothing (the same recursive method RSI
// uses), the textbook standard rather than a plain SMA of true range.
function computeATR(bars, period) {
  const tr = new Array(bars.length).fill(null);
  for (let i = 1; i < bars.length; i++) {
    tr[i] = Math.max(bars[i].high - bars[i].low, Math.abs(bars[i].high - bars[i - 1].close), Math.abs(bars[i].low - bars[i - 1].close));
  }
  const out = new Array(bars.length).fill(null);
  if (bars.length <= period) return out;
  let sum = 0;
  for (let i = 1; i <= period; i++) sum += tr[i];
  let atr = sum / period;
  out[period] = atr;
  for (let i = period + 1; i < bars.length; i++) {
    atr = (atr * (period - 1) + tr[i]) / period;
    out[i] = atr;
  }
  return out;
}

// Average Directional Index: measures trend strength (not direction).
// +DM/-DM capture directional movement, smoothed the same Wilder way as
// ATR, DX is the normalized difference between +DI and -DI, and ADX is
// DX smoothed again. Standard 14-period.
function computeADX(bars, period) {
  const n = bars.length;
  const plusDM = new Array(n).fill(0), minusDM = new Array(n).fill(0), tr = new Array(n).fill(0);
  for (let i = 1; i < n; i++) {
    const upMove = bars[i].high - bars[i - 1].high;
    const downMove = bars[i - 1].low - bars[i].low;
    plusDM[i] = (upMove > downMove && upMove > 0) ? upMove : 0;
    minusDM[i] = (downMove > upMove && downMove > 0) ? downMove : 0;
    tr[i] = Math.max(bars[i].high - bars[i].low, Math.abs(bars[i].high - bars[i - 1].close), Math.abs(bars[i].low - bars[i - 1].close));
  }
  const out = new Array(n).fill(null);
  if (n <= period * 2) return out;
  let smoothTR = 0, smoothPlusDM = 0, smoothMinusDM = 0;
  for (let i = 1; i <= period; i++) { smoothTR += tr[i]; smoothPlusDM += plusDM[i]; smoothMinusDM += minusDM[i]; }
  const dxSeries = [];
  const pushDX = () => {
    const plusDI = smoothTR === 0 ? 0 : 100 * smoothPlusDM / smoothTR;
    const minusDI = smoothTR === 0 ? 0 : 100 * smoothMinusDM / smoothTR;
    const dx = (plusDI + minusDI) === 0 ? 0 : 100 * Math.abs(plusDI - minusDI) / (plusDI + minusDI);
    dxSeries.push(dx);
  };
  pushDX();
  for (let i = period + 1; i < n; i++) {
    smoothTR = smoothTR - (smoothTR / period) + tr[i];
    smoothPlusDM = smoothPlusDM - (smoothPlusDM / period) + plusDM[i];
    smoothMinusDM = smoothMinusDM - (smoothMinusDM / period) + minusDM[i];
    pushDX();
  }
  // ADX is Wilder-smoothed DX, seeded by a simple average of the first
  // `period` DX values, then recursively smoothed like ATR/RSI above.
  if (dxSeries.length < period) return out;
  let adx = dxSeries.slice(0, period).reduce((a, b) => a + b, 0) / period;
  const firstAdxIdx = period + period;
  out[firstAdxIdx] = adx;
  for (let k = period; k < dxSeries.length; k++) {
    adx = (adx * (period - 1) + dxSeries[k]) / period;
    const barIdx = period + k + 1;
    if (barIdx < n) out[barIdx] = adx;
  }
  return out;
}

// Commodity Channel Index: how far the typical price has strayed from
// its moving average, scaled by mean absolute deviation. The 0.015
// constant is Lambert's original scaling so ~70-80% of values fall
// within +/-100, the textbook standard.
function computeCCI(bars, period) {
  const n = bars.length;
  const tp = bars.map(b => (b.high + b.low + b.close) / 3);
  const smaTP = computeSMA(tp, period);
  const out = new Array(n).fill(null);
  for (let i = period - 1; i < n; i++) {
    if (smaTP[i] === null) continue;
    let meanDev = 0;
    for (let j = i - period + 1; j <= i; j++) meanDev += Math.abs(tp[j] - smaTP[i]);
    meanDev /= period;
    out[i] = meanDev === 0 ? 0 : (tp[i] - smaTP[i]) / (0.015 * meanDev);
  }
  return out;
}

// Williams %R: an inverse-scaled stochastic, 0 to -100, where readings
// near 0 mean closing near the recent high and near -100 mean closing
// near the recent low. Standard 14-period.
function computeWilliamsR(bars, period) {
  const out = new Array(bars.length).fill(null);
  for (let i = period - 1; i < bars.length; i++) {
    let hh = -Infinity, ll = Infinity;
    for (let j = i - period + 1; j <= i; j++) { hh = Math.max(hh, bars[j].high); ll = Math.min(ll, bars[j].low); }
    out[i] = hh === ll ? -50 : -100 * (hh - bars[i].close) / (hh - ll);
  }
  return out;
}

// Rate of Change: simple percentage change over `period` bars.
function computeROC(closes, period) {
  const out = new Array(closes.length).fill(null);
  for (let i = period; i < closes.length; i++) {
    out[i] = closes[i - period] === 0 ? null : 100 * (closes[i] - closes[i - period]) / closes[i - period];
  }
  return out;
}

// Money Flow Index: a volume-weighted RSI. Typical price times volume
// gives "money flow"; days are bucketed as positive or negative by
// whether typical price rose or fell, then ratio'd the same way RSI
// ratios average gain to average loss. Standard 14-period.
function computeMFI(bars, period) {
  const n = bars.length;
  const tp = bars.map(b => (b.high + b.low + b.close) / 3);
  const out = new Array(n).fill(null);
  for (let i = period; i < n; i++) {
    let posFlow = 0, negFlow = 0;
    for (let j = i - period + 1; j <= i; j++) {
      const rawFlow = tp[j] * bars[j].volume;
      if (tp[j] > tp[j - 1]) posFlow += rawFlow;
      else if (tp[j] < tp[j - 1]) negFlow += rawFlow;
    }
    if (negFlow === 0) { out[i] = 100; continue; }
    const moneyRatio = posFlow / negFlow;
    out[i] = 100 - 100 / (1 + moneyRatio);
  }
  return out;
}

// Simple price-vs-moving-average trend filters, the most common real-world
// use of a moving average: is price currently above or below it.
function computePriceVsSMA(closes, period) { return computeSMA(closes, period); }
function computePriceVsEMA(closes, period) { return computeEMA(closes, period); }

// Standard deviation of closing price over the window, expressed later as
// a % of price the same way ATR is, so it's comparable across symbols.
function computeStdDev(closes, period) {
  const out = new Array(closes.length).fill(null);
  for (let i = period - 1; i < closes.length; i++) {
    let sum = 0;
    for (let j = i - period + 1; j <= i; j++) sum += closes[j];
    const mean = sum / period;
    let sqSum = 0;
    for (let j = i - period + 1; j <= i; j++) sqSum += (closes[j] - mean) ** 2;
    out[i] = Math.sqrt(sqSum / period);
  }
  return out;
}

// Chaikin Money Flow: volume-weighted measure of buying vs selling
// pressure within each bar's own range, summed over the window. Standard
// 20-period.
function computeCMF(bars, period) {
  const n = bars.length;
  const out = new Array(n).fill(null);
  for (let i = period - 1; i < n; i++) {
    let mfVolSum = 0, volSum = 0;
    for (let j = i - period + 1; j <= i; j++) {
      const range = bars[j].high - bars[j].low;
      const mfMultiplier = range === 0 ? 0 : ((bars[j].close - bars[j].low) - (bars[j].high - bars[j].close)) / range;
      mfVolSum += mfMultiplier * bars[j].volume;
      volSum += bars[j].volume;
    }
    out[i] = volSum === 0 ? 0 : mfVolSum / volSum;
  }
  return out;
}

// Aroon Oscillator: how recently price made a new high vs a new low,
// scaled -100 to 100. Standard 25-period.
function computeAroon(bars, period) {
  const n = bars.length;
  const out = new Array(n).fill(null);
  for (let i = period; i < n; i++) {
    let hiIdx = i - period, loIdx = i - period;
    for (let j = i - period; j <= i; j++) {
      if (bars[j].high >= bars[hiIdx].high) hiIdx = j;
      if (bars[j].low <= bars[loIdx].low) loIdx = j;
    }
    const aroonUp = 100 * (period - (i - hiIdx)) / period;
    const aroonDown = 100 * (period - (i - loIdx)) / period;
    out[i] = aroonUp - aroonDown;
  }
  return out;
}

// Keltner Channels: an EMA midline with ATR-scaled bands, a volatility
// channel like Bollinger Bands but built from average true range instead
// of standard deviation. Standard 20-period EMA, 10-period ATR, 2x
// multiplier.
function computeKeltner(bars, period, atrPeriod, mult) {
  const closes = bars.map(b => b.close);
  const mid = computeEMA(closes, period);
  const atr = computeATR(bars, atrPeriod);
  const n = bars.length;
  const upper = new Array(n).fill(null), lower = new Array(n).fill(null);
  for (let i = 0; i < n; i++) {
    if (mid[i] === null || atr[i] === null) continue;
    upper[i] = mid[i] + mult * atr[i];
    lower[i] = mid[i] - mult * atr[i];
  }
  return { upper, lower, mid };
}

// Donchian Channel position: where the close currently sits within the
// N-period high/low channel, 0-100, the same scale as Stochastic %K, but
// built from the channel extremes rather than a smoothed calculation.
// Standard 20-period.
function computeDonchianPosition(bars, period) {
  const out = new Array(bars.length).fill(null);
  for (let i = period - 1; i < bars.length; i++) {
    let hh = -Infinity, ll = Infinity;
    for (let j = i - period + 1; j <= i; j++) { hh = Math.max(hh, bars[j].high); ll = Math.min(ll, bars[j].low); }
    out[i] = hh === ll ? 50 : 100 * (bars[i].close - ll) / (hh - ll);
  }
  return out;
}

// TRIX: the rate of change of a triple-smoothed EMA, filters out minor
// price fluctuations more aggressively than a single or double EMA.
// Standard 15-period.
function computeTRIX(closes, period) {
  const ema1 = computeEMA(closes, period);
  const ema1Clean = ema1.filter(v => v !== null);
  const ema2Raw = computeEMA(ema1Clean, period);
  const ema3Raw = computeEMA(ema2Raw.filter(v => v !== null), period);
  const out = new Array(closes.length).fill(null);
  const startIdx = closes.length - ema3Raw.filter(v => v !== null).length;
  const ema3Clean = ema3Raw.filter(v => v !== null);
  for (let k = 1; k < ema3Clean.length; k++) {
    const idx = startIdx + k;
    if (idx >= 0 && idx < out.length && ema3Clean[k - 1] !== 0) {
      out[idx] = 100 * (ema3Clean[k] - ema3Clean[k - 1]) / ema3Clean[k - 1];
    }
  }
  return out;
}

// Awesome Oscillator: the difference between a fast and slow SMA of the
// bar midpoint (not closing price), a momentum read independent of RSI
// style calculations. Standard 5 and 34 period.
function computeAwesomeOscillator(bars) {
  const mid = bars.map(b => (b.high + b.low) / 2);
  const fast = computeSMA(mid, 5);
  const slow = computeSMA(mid, 34);
  const out = new Array(bars.length).fill(null);
  for (let i = 0; i < bars.length; i++) {
    if (fast[i] !== null && slow[i] !== null) out[i] = fast[i] - slow[i];
  }
  return out;
}

// Ultimate Oscillator: blends buying pressure across three timeframes
// (7/14/28 bars) into one 0-100 reading, designed to need agreement
// across short, medium and longer-term pressure before firing. Standard
// periods and 4:2:1 weighting.
function computeUltimateOscillator(bars) {
  const n = bars.length;
  const bp = new Array(n).fill(0), tr = new Array(n).fill(0);
  for (let i = 1; i < n; i++) {
    const prevClose = bars[i - 1].close;
    bp[i] = bars[i].close - Math.min(bars[i].low, prevClose);
    tr[i] = Math.max(bars[i].high, prevClose) - Math.min(bars[i].low, prevClose);
  }
  const out = new Array(n).fill(null);
  const periods = [7, 14, 28], weights = [4, 2, 1];
  for (let i = 28; i < n; i++) {
    let weightedSum = 0, weightTotal = 0;
    for (let p = 0; p < periods.length; p++) {
      let bpSum = 0, trSum = 0;
      for (let j = i - periods[p] + 1; j <= i; j++) { bpSum += bp[j]; trSum += tr[j]; }
      const avg = trSum === 0 ? 0 : bpSum / trSum;
      weightedSum += avg * weights[p];
      weightTotal += weights[p];
    }
    out[i] = 100 * weightedSum / weightTotal;
  }
  return out;
}

function buildIndicatorCache(bars, entryConditions) {
  const closes = bars.map(b => b.close);
  const cache = {};
  for (const c of entryConditions) {
    if (c.indicator === 'rsi' && !cache.rsi) {
      cache.rsi = computeRSI(closes, 14);
    } else if (c.indicator === 'macd' && !cache.macd) {
      cache.macd = computeMACD(closes);
    } else if (c.indicator === 'bbands' && !cache.bbands) {
      cache.bbands = computeBollingerBands(closes, 20, 2);
    } else if (c.indicator === 'vwap' && !cache.vwap) {
      cache.vwap = computeRollingVWAP(bars, 20);
    } else if (c.indicator === 'sma_cross' || c.indicator === 'ema_cross') {
      const key = c.indicator + ':' + c.value;
      if (!cache[key]) {
        const [fastP, slowP] = String(c.value || '9/21').split('/').map(n => parseInt(n, 10) || 0);
        const fast = c.indicator === 'sma_cross' ? computeSMA(closes, fastP || 9) : computeEMA(closes, fastP || 9);
        const slow = c.indicator === 'sma_cross' ? computeSMA(closes, slowP || 21) : computeEMA(closes, slowP || 21);
        cache[key] = { fast, slow };
      }
    } else if (c.indicator === 'breakout') {
      const n = parseInt(c.value, 10) || 20;
      const key = 'breakout:' + n;
      if (!cache[key]) {
        const highs = new Array(bars.length).fill(null);
        const lows = new Array(bars.length).fill(null);
        for (let i = n; i < bars.length; i++) {
          let hh = -Infinity, ll = Infinity;
          for (let j = i - n; j < i; j++) { hh = Math.max(hh, bars[j].high); ll = Math.min(ll, bars[j].low); }
          highs[i] = hh; lows[i] = ll;
        }
        cache[key] = { highs, lows };
      }
    } else if (c.indicator === 'volume' && !cache.volAvg) {
      const vols = bars.map(b => b.volume);
      cache.volAvg = computeSMA(vols, 20);
    } else if (c.indicator === 'stochastic' && !cache.stochastic) {
      cache.stochastic = computeStochastic(bars, 14);
    } else if (c.indicator === 'atr' && !cache.atr) {
      cache.atr = computeATR(bars, 14);
    } else if (c.indicator === 'adx' && !cache.adx) {
      cache.adx = computeADX(bars, 14);
    } else if (c.indicator === 'cci' && !cache.cci) {
      cache.cci = computeCCI(bars, 20);
    } else if (c.indicator === 'williamsr' && !cache.williamsr) {
      cache.williamsr = computeWilliamsR(bars, 14);
    } else if (c.indicator === 'roc' && !cache.roc) {
      cache.roc = computeROC(closes, 12);
    } else if (c.indicator === 'mfi' && !cache.mfi) {
      cache.mfi = computeMFI(bars, 14);
    } else if (c.indicator === 'pricevssma' && !cache.pricevssma) {
      cache.pricevssma = computePriceVsSMA(closes, 20);
    } else if (c.indicator === 'pricevsema' && !cache.pricevsema) {
      cache.pricevsema = computePriceVsEMA(closes, 20);
    } else if (c.indicator === 'stddev' && !cache.stddev) {
      cache.stddev = computeStdDev(closes, 20);
    } else if (c.indicator === 'cmf' && !cache.cmf) {
      cache.cmf = computeCMF(bars, 20);
    } else if (c.indicator === 'aroon' && !cache.aroon) {
      cache.aroon = computeAroon(bars, 25);
    } else if (c.indicator === 'keltner' && !cache.keltner) {
      cache.keltner = computeKeltner(bars, 20, 10, 2);
    } else if (c.indicator === 'donchianpos' && !cache.donchianpos) {
      cache.donchianpos = computeDonchianPosition(bars, 20);
    } else if (c.indicator === 'trix' && !cache.trix) {
      cache.trix = computeTRIX(closes, 15);
    } else if (c.indicator === 'awesome' && !cache.awesome) {
      cache.awesome = computeAwesomeOscillator(bars);
    } else if (c.indicator === 'ultimate' && !cache.ultimate) {
      cache.ultimate = computeUltimateOscillator(bars);
    } else if (c.indicator === 'vwapdist' && !cache.vwapdist) {
      cache.vwapdist = computeRollingVWAP(bars, 20);
    }
  }
  return cache;
}

function evaluateConditionAt(c, i, bars, cache) {
  if (i < 1) return null;
  if (c.indicator === 'custom_equation') return evalCustomEquation(c, i, bars);
  if (c.indicator === 'rsi') {
    const v = cache.rsi[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is below' ? v < threshold : v > threshold;
  }
  if (c.indicator === 'macd') {
    const { macdLine, signalLine } = cache.macd;
    if (macdLine[i] === null || signalLine[i] === null || macdLine[i - 1] === null || signalLine[i - 1] === null) return null;
    const wasBelow = macdLine[i - 1] <= signalLine[i - 1];
    const nowAbove = macdLine[i] > signalLine[i];
    const wasAbove = macdLine[i - 1] >= signalLine[i - 1];
    const nowBelow = macdLine[i] < signalLine[i];
    return c.operator === 'crosses above signal' ? (wasBelow && nowAbove) : (wasAbove && nowBelow);
  }
  if (c.indicator === 'bbands') {
    const { upper, lower } = cache.bbands;
    if (upper[i] === null || lower[i] === null) return null;
    return c.operator === 'price breaks upper band' ? bars[i].close > upper[i] : bars[i].close < lower[i];
  }
  if (c.indicator === 'vwap') {
    const v = cache.vwap[i];
    if (v === null || cache.vwap[i - 1] === null) return null;
    const wasBelow = bars[i - 1].close <= cache.vwap[i - 1];
    const nowAbove = bars[i].close > v;
    const wasAbove = bars[i - 1].close >= cache.vwap[i - 1];
    const nowBelow = bars[i].close < v;
    return c.operator === 'price crosses above' ? (wasBelow && nowAbove) : (wasAbove && nowBelow);
  }
  if (c.indicator === 'sma_cross' || c.indicator === 'ema_cross') {
    const key = c.indicator + ':' + c.value;
    const { fast, slow } = cache[key];
    if (fast[i] === null || slow[i] === null || fast[i - 1] === null || slow[i - 1] === null) return null;
    const wasBelow = fast[i - 1] <= slow[i - 1];
    const nowAbove = fast[i] > slow[i];
    const wasAbove = fast[i - 1] >= slow[i - 1];
    const nowBelow = fast[i] < slow[i];
    return c.operator === 'fast crosses above slow' ? (wasBelow && nowAbove) : (wasAbove && nowBelow);
  }
  if (c.indicator === 'breakout') {
    const n = parseInt(c.value, 10) || 20;
    const key = 'breakout:' + n;
    const { highs, lows } = cache[key];
    if (highs[i] === null || lows[i] === null) return null;
    return c.operator === 'breaks above N-bar high' ? bars[i].close > highs[i] : bars[i].close < lows[i];
  }
  if (c.indicator === 'volume') {
    const avg = cache.volAvg[i];
    if (avg === null) return null;
    const threshold = parseFloat(c.value) / 100;
    return bars[i].volume > avg * threshold;
  }
  if (c.indicator === 'stochastic') {
    const v = cache.stochastic.k[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is below' ? v < threshold : v > threshold;
  }
  if (c.indicator === 'atr') {
    const v = cache.atr[i];
    if (v === null) return null;
    const pctOfPrice = 100 * v / bars[i].close;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? pctOfPrice > threshold : pctOfPrice < threshold;
  }
  if (c.indicator === 'adx') {
    const v = cache.adx[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'cci') {
    const v = cache.cci[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'williamsr') {
    const v = cache.williamsr[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is below' ? v < threshold : v > threshold;
  }
  if (c.indicator === 'roc') {
    const v = cache.roc[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'mfi') {
    const v = cache.mfi[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is below' ? v < threshold : v > threshold;
  }
  if (c.indicator === 'pricevssma') {
    const v = cache.pricevssma[i];
    if (v === null) return null;
    return c.operator === 'is above' ? bars[i].close > v : bars[i].close < v;
  }
  if (c.indicator === 'pricevsema') {
    const v = cache.pricevsema[i];
    if (v === null) return null;
    return c.operator === 'is above' ? bars[i].close > v : bars[i].close < v;
  }
  if (c.indicator === 'stddev') {
    const v = cache.stddev[i];
    if (v === null) return null;
    const pctOfPrice = 100 * v / bars[i].close;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? pctOfPrice > threshold : pctOfPrice < threshold;
  }
  if (c.indicator === 'cmf') {
    const v = cache.cmf[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'aroon') {
    const v = cache.aroon[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'keltner') {
    const { upper, lower } = cache.keltner;
    if (upper[i] === null || lower[i] === null) return null;
    return c.operator === 'price breaks upper band' ? bars[i].close > upper[i] : bars[i].close < lower[i];
  }
  if (c.indicator === 'donchianpos') {
    const v = cache.donchianpos[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'trix') {
    const v = cache.trix[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'awesome') {
    const v = cache.awesome[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'ultimate') {
    const v = cache.ultimate[i];
    if (v === null) return null;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? v > threshold : v < threshold;
  }
  if (c.indicator === 'vwapdist') {
    const v = cache.vwapdist[i];
    if (v === null) return null;
    const distPct = 100 * (bars[i].close - v) / v;
    const threshold = parseFloat(c.value);
    return c.operator === 'is above' ? distPct > threshold : distPct < threshold;
  }
  return null;
}

// Companion to evaluateConditionAt: same cache, same bar index, but returns
// a human-readable snapshot of what the condition actually saw (not just
// pass/fail), this is the entire point of the audit view: showing a trader
// WHY their strategy hasn't fired yet (e.g. "RSI is 42.3, needs to be below
// 30"), not just a silent "watching" status with no visibility into it.
function describeConditionAt(c, i, bars, cache) {
  const base = { indicator: c.indicator, operator: c.operator, value: c.value, logic: c.logic || 'AND' };
  if (i < 1) return { ...base, currentValueLabel: 'Not enough data yet', passed: null };
  const passed = evaluateConditionAt(c, i, bars, cache);
  if (c.indicator === 'custom_equation') {
    return { ...base, currentValueLabel: passed === null ? 'Not enough data yet, or the equation has an error' : `Equation evaluates to ${passed}`, passed };
  }
  if (c.indicator === 'rsi') {
    const v = cache.rsi[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `RSI is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'macd') {
    const { macdLine, signalLine } = cache.macd;
    const m = macdLine[i], sg = signalLine[i];
    return { ...base, currentValueLabel: (m === null || sg === null) ? 'Warming up' : `MACD ${m.toFixed(3)} vs signal ${sg.toFixed(3)}`, passed };
  }
  if (c.indicator === 'bbands') {
    const { upper, lower } = cache.bbands;
    return { ...base, currentValueLabel: (upper[i] === null) ? 'Warming up' : `Price ${bars[i].close.toFixed(2)}, band ${lower[i].toFixed(2)}-${upper[i].toFixed(2)}`, passed };
  }
  if (c.indicator === 'vwap') {
    const v = cache.vwap[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Price ${bars[i].close.toFixed(2)} vs VWAP ${v.toFixed(2)}`, passed };
  }
  if (c.indicator === 'sma_cross' || c.indicator === 'ema_cross') {
    const key = c.indicator + ':' + c.value;
    const { fast, slow } = cache[key] || {};
    return { ...base, currentValueLabel: (!fast || fast[i] === null) ? 'Warming up' : `Fast ${fast[i].toFixed(2)} vs slow ${slow[i].toFixed(2)}`, passed };
  }
  if (c.indicator === 'breakout') {
    const n = parseInt(c.value, 10) || 20;
    const { highs, lows } = cache['breakout:' + n] || {};
    return { ...base, currentValueLabel: (!highs || highs[i] === null) ? 'Warming up' : `Price ${bars[i].close.toFixed(2)}, ${n}-bar range ${lows[i].toFixed(2)}-${highs[i].toFixed(2)}`, passed };
  }
  if (c.indicator === 'volume') {
    const avg = cache.volAvg[i];
    return { ...base, currentValueLabel: avg === null ? 'Warming up' : `Volume ${Math.round(bars[i].volume)} vs avg ${Math.round(avg)}`, passed };
  }
  if (c.indicator === 'stochastic') {
    const v = cache.stochastic.k[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `%K is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'atr') {
    const v = cache.atr[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `ATR ${v.toFixed(3)}, ${(100 * v / bars[i].close).toFixed(2)}% of price`, passed };
  }
  if (c.indicator === 'adx') {
    const v = cache.adx[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `ADX is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'cci') {
    const v = cache.cci[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `CCI is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'williamsr') {
    const v = cache.williamsr[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Williams %R is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'roc') {
    const v = cache.roc[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `ROC is ${v.toFixed(2)}%`, passed };
  }
  if (c.indicator === 'mfi') {
    const v = cache.mfi[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `MFI is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'pricevssma') {
    const v = cache.pricevssma[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Price ${bars[i].close.toFixed(2)} vs SMA ${v.toFixed(2)}`, passed };
  }
  if (c.indicator === 'pricevsema') {
    const v = cache.pricevsema[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Price ${bars[i].close.toFixed(2)} vs EMA ${v.toFixed(2)}`, passed };
  }
  if (c.indicator === 'stddev') {
    const v = cache.stddev[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Std. dev ${(100 * v / bars[i].close).toFixed(2)}% of price`, passed };
  }
  if (c.indicator === 'cmf') {
    const v = cache.cmf[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `CMF is ${v.toFixed(3)}`, passed };
  }
  if (c.indicator === 'aroon') {
    const v = cache.aroon[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Aroon Oscillator is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'keltner') {
    const { upper, lower } = cache.keltner;
    return { ...base, currentValueLabel: (!upper || upper[i] === null) ? 'Warming up' : `Price ${bars[i].close.toFixed(2)}, channel ${lower[i].toFixed(2)}-${upper[i].toFixed(2)}`, passed };
  }
  if (c.indicator === 'donchianpos') {
    const v = cache.donchianpos[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Channel position ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'trix') {
    const v = cache.trix[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `TRIX is ${v.toFixed(3)}%`, passed };
  }
  if (c.indicator === 'awesome') {
    const v = cache.awesome[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Awesome Oscillator is ${v.toFixed(2)}`, passed };
  }
  if (c.indicator === 'ultimate') {
    const v = cache.ultimate[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `Ultimate Oscillator is ${v.toFixed(1)}`, passed };
  }
  if (c.indicator === 'vwapdist') {
    const v = cache.vwapdist[i];
    return { ...base, currentValueLabel: v === null ? 'Warming up' : `${(100 * (bars[i].close - v) / v).toFixed(2)}% from VWAP`, passed };
  }
  return { ...base, currentValueLabel: 'Unknown indicator', passed: null };
}
function buildAuditSnapshot(conditions, bars, cache) {
  const lastIdx = bars.length - 1;
  const details = conditions.map(c => describeConditionAt(c, lastIdx, bars, cache));
  const signal = evaluateConditionsAt(conditions, lastIdx, bars, cache);
  return { details, signal, price: bars[lastIdx].close };
}
function evaluateConditionsAt(conditions, i, bars, cache) {
  let result = null;
  for (let idx = 0; idx < conditions.length; idx++) {
    const v = evaluateConditionAt(conditions[idx], i, bars, cache);
    if (v === null) return null; // not enough warm-up data yet
    if (idx === 0) { result = v; continue; }
    const connector = conditions[idx].logic === 'OR' ? 'OR' : 'AND';
    result = connector === 'AND' ? (result && v) : (result || v);
  }
  return result;
}
// ===================== CUSTOM EQUATION EXPRESSION ENGINE =====================
// Lets a condition be a free-form formula ("RSI(14) < 30 AND CLOSE > SMA(50)")
// instead of picking from the fixed indicator/operator dropdowns above. This
// is untrusted user input, so it's a genuine hand-rolled tokenizer ->
// recursive-descent parser -> tree-walking evaluator, never eval()/Function().
// This exact engine (verified against 49 direct tests before integration) is
// ALSO ported byte-identical into server.js for live execution.
// Custom equation expression engine.
// Grammar (highest to lowest precedence):
//   primary    := NUMBER | IDENT | IDENT '(' expr ')' | '(' expr ')' | '-' primary
//   term       := primary (('*'|'/') primary)*
//   arith      := term (('+'|'-') term)*
//   comparison := arith (('<'|'>'|'<='|'>='|'=='|'!=') arith)?
//   notExpr    := 'NOT' notExpr | comparison
//   andExpr    := notExpr ('AND' notExpr)*
//   orExpr     := andExpr ('OR' andExpr)*
// No eval()/Function()/dynamic code execution anywhere, this is a plain
// hand-rolled tokenizer -> recursive-descent parser -> tree-walking
// evaluator, since this expression is untrusted user input.

const FUNCS_WITH_ARG = new Set(['RSI', 'SMA', 'EMA', 'BB_UPPER', 'BB_LOWER']);
const BARE_IDENTS = new Set(['CLOSE', 'OPEN', 'HIGH', 'LOW', 'VOLUME', 'VWAP', 'MACD_LINE', 'MACD_SIGNAL']);

function tokenizeExpr(src) {
  const tokens = [];
  let i = 0;
  const isDigit = c => c >= '0' && c <= '9';
  const isAlpha = c => /[A-Za-z_]/.test(c);
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    if (isDigit(c) || (c === '.' && isDigit(src[i + 1]))) {
      let j = i; while (j < src.length && (isDigit(src[j]) || src[j] === '.')) j++;
      tokens.push({ type: 'NUM', value: parseFloat(src.slice(i, j)) }); i = j; continue;
    }
    if (isAlpha(c)) {
      let j = i; while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j).toUpperCase();
      if (word === 'AND' || word === 'OR' || word === 'NOT') tokens.push({ type: word });
      else tokens.push({ type: 'IDENT', value: word });
      i = j; continue;
    }
    if (c === '<' && src[i + 1] === '=') { tokens.push({ type: '<=' }); i += 2; continue; }
    if (c === '>' && src[i + 1] === '=') { tokens.push({ type: '>=' }); i += 2; continue; }
    if (c === '=' && src[i + 1] === '=') { tokens.push({ type: '==' }); i += 2; continue; }
    if (c === '!' && src[i + 1] === '=') { tokens.push({ type: '!=' }); i += 2; continue; }
    if ('<>+-*/(),'.includes(c)) { tokens.push({ type: c }); i++; continue; }
    throw new Error(`Unexpected character "${c}" at position ${i}`);
  }
  tokens.push({ type: 'EOF' });
  return tokens;
}

function parseExpr(src) {
  const tokens = tokenizeExpr(src);
  let pos = 0;
  const peek = () => tokens[pos];
  const advance = () => tokens[pos++];
  const expect = (type) => { if (peek().type !== type) throw new Error(`Expected "${type}" but got "${peek().type}" at token ${pos}`); return advance(); };

  function primary() {
    const t = peek();
    if (t.type === 'NUM') { advance(); return { kind: 'num', value: t.value }; }
    if (t.type === '-') { advance(); return { kind: 'neg', expr: primary() }; }
    if (t.type === '(') { advance(); const e = orExpr(); expect(')'); return e; }
    if (t.type === 'IDENT') {
      advance();
      if (peek().type === '(') {
        advance();
        const arg = arith();
        expect(')');
        if (!FUNCS_WITH_ARG.has(t.value)) throw new Error(`"${t.value}" does not take an argument`);
        return { kind: 'func', name: t.value, arg };
      }
      if (!BARE_IDENTS.has(t.value) && !FUNCS_WITH_ARG.has(t.value)) throw new Error(`Unknown identifier "${t.value}"`);
      if (FUNCS_WITH_ARG.has(t.value)) throw new Error(`"${t.value}" requires an argument, e.g. ${t.value}(14)`);
      return { kind: 'ident', name: t.value };
    }
    throw new Error(`Unexpected token "${t.type}" at token ${pos}`);
  }
  function term() {
    let node = primary();
    while (peek().type === '*' || peek().type === '/') {
      const op = advance().type;
      node = { kind: 'binop', op, left: node, right: primary() };
    }
    return node;
  }
  function arith() {
    let node = term();
    while (peek().type === '+' || peek().type === '-') {
      const op = advance().type;
      node = { kind: 'binop', op, left: node, right: term() };
    }
    return node;
  }
  function comparison() {
    const node = arith();
    const cmpOps = ['<', '>', '<=', '>=', '==', '!='];
    if (cmpOps.includes(peek().type)) {
      const op = advance().type;
      return { kind: 'cmp', op, left: node, right: arith() };
    }
    return node;
  }
  function notExpr() {
    if (peek().type === 'NOT') { advance(); return { kind: 'not', expr: notExpr() }; }
    return comparison();
  }
  function andExpr() {
    let node = notExpr();
    while (peek().type === 'AND') { advance(); node = { kind: 'and', left: node, right: notExpr() }; }
    return node;
  }
  function orExpr() {
    let node = andExpr();
    while (peek().type === 'OR') { advance(); node = { kind: 'or', left: node, right: andExpr() }; }
    return node;
  }

  const ast = orExpr();
  expect('EOF');
  return ast;
}

// Evaluates a parsed AST at bar index i, using the same indicator cache
// shape the rest of the engine already builds (buildIndicatorCache), plus a
// small set of ad-hoc lookups (SMA/EMA/RSI/BB at an arbitrary requested
// period, not just the periods a structured condition happened to request)
// computed on demand and memoized per (name,period) within this one eval call.
function evalExprNode(node, i, bars, cache, memo) {
  switch (node.kind) {
    case 'num': return node.value;
    case 'neg': return -evalExprNode(node.expr, i, bars, cache, memo);
    case 'ident': {
      if (node.name === 'CLOSE') return bars[i].close;
      if (node.name === 'OPEN') return bars[i].open;
      if (node.name === 'HIGH') return bars[i].high;
      if (node.name === 'LOW') return bars[i].low;
      if (node.name === 'VOLUME') return bars[i].volume;
      if (node.name === 'VWAP') return getOrCompute(memo, 'VWAP:', () => cache.vwapSeries)[i];
      if (node.name === 'MACD_LINE') return getOrCompute(memo, 'MACD_LINE:', () => cache.macdSeries.macdLine)[i];
      if (node.name === 'MACD_SIGNAL') return getOrCompute(memo, 'MACD_SIGNAL:', () => cache.macdSeries.signalLine)[i];
      throw new Error(`Unknown identifier "${node.name}"`);
    }
    case 'func': {
      const period = evalExprNode(node.arg, i, bars, cache, memo);
      const key = `${node.name}:${period}`;
      if (node.name === 'RSI') return getOrCompute(memo, key, () => cache.rsiFn(period))[i];
      if (node.name === 'SMA') return getOrCompute(memo, key, () => cache.smaFn(period))[i];
      if (node.name === 'EMA') return getOrCompute(memo, key, () => cache.emaFn(period))[i];
      if (node.name === 'BB_UPPER') return getOrCompute(memo, key, () => cache.bbFn(period).upper)[i];
      if (node.name === 'BB_LOWER') return getOrCompute(memo, key, () => cache.bbFn(period).lower)[i];
      throw new Error(`Unknown function "${node.name}"`);
    }
    case 'binop': {
      const l = evalExprNode(node.left, i, bars, cache, memo), r = evalExprNode(node.right, i, bars, cache, memo);
      if (l === null || r === null) return null;
      if (node.op === '+') return l + r;
      if (node.op === '-') return l - r;
      if (node.op === '*') return l * r;
      if (node.op === '/') return r === 0 ? null : l / r;
      throw new Error(`Unknown operator "${node.op}"`);
    }
    case 'cmp': {
      const l = evalExprNode(node.left, i, bars, cache, memo), r = evalExprNode(node.right, i, bars, cache, memo);
      if (l === null || r === null) return null;
      if (node.op === '<') return l < r;
      if (node.op === '>') return l > r;
      if (node.op === '<=') return l <= r;
      if (node.op === '>=') return l >= r;
      if (node.op === '==') return l === r;
      if (node.op === '!=') return l !== r;
      throw new Error(`Unknown comparator "${node.op}"`);
    }
    case 'not': { const v = evalExprNode(node.expr, i, bars, cache, memo); return v === null ? null : !v; }
    case 'and': { const l = evalExprNode(node.left, i, bars, cache, memo); if (l === false) return false; const r = evalExprNode(node.right, i, bars, cache, memo); if (l === null || r === null) return null; return l && r; }
    case 'or': { const l = evalExprNode(node.left, i, bars, cache, memo); if (l === true) return true; const r = evalExprNode(node.right, i, bars, cache, memo); if (l === null || r === null) return null; return l || r; }
    default: throw new Error(`Unknown node kind "${node.kind}"`);
  }
}
function getOrCompute(memo, key, fn) {
  if (!(key in memo)) memo[key] = fn();
  return memo[key];
}

// Builds the lazily-evaluated indicator lookups a custom equation can call
// (RSI(n), SMA(n), etc. at ANY period, not just the fixed periods the
// structured condition types use), reusing the exact same compute* functions
// everything else in the app already relies on.
function buildExprCache(bars) {
  const closes = bars.map(b => b.close);
  const macd = computeMACD(closes);
  return {
    vwapSeries: computeRollingVWAP(bars, 20),
    macdSeries: macd,
    rsiFn: (period) => computeRSI(closes, period),
    smaFn: (period) => computeSMA(closes, period),
    emaFn: (period) => computeEMA(closes, period),
    bbFn: (period) => computeBollingerBands(closes, period, 2),
  };
}
// Translates a COMMON SUBSET of Pine Script v5 and MQL5 indicator-comparison
// syntax into VaticTrader's native equation syntax, which then runs through
// the same parseExpr/evalExprNode engine as everything else. This is
// deliberately not a full language interpreter (neither language is
// remotely that simple), it supports the realistic subset a trader would
// write for an entry condition: indicator calls, OHLCV references,
// comparisons, and boolean logic. Verified against 17 direct tests
// (including a cross-check that Pine, MQL5, and native forms of the same
// logical formula all evaluate identically) before integration.
function extractCallArgs(src, funcName) {
  const idx = src.indexOf(funcName + '(');
  if (idx === -1) return null;
  const start = idx + funcName.length + 1;
  let depth = 1, i = start;
  while (i < src.length && depth > 0) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')') depth--;
    i++;
  }
  const inner = src.slice(start, i - 1);
  const args = [];
  let cur = '', d = 0;
  for (const ch of inner) {
    if (ch === '(') d++;
    if (ch === ')') d--;
    if (ch === ',' && d === 0) { args.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) args.push(cur.trim());
  return { args, fullMatch: src.slice(idx, i) };
}
function replaceAllCalls(src, funcName, replacer) {
  let result = src;
  let guard = 0;
  while (result.includes(funcName + '(') && guard < 50) {
    const found = extractCallArgs(result, funcName);
    if (!found) break;
    result = result.replace(found.fullMatch, replacer(found.args));
    guard++;
  }
  return result;
}
function translatePineToNative(src) {
  let s = src;
  s = replaceAllCalls(s, 'ta.rsi', (args) => `RSI(${args[1] !== undefined ? args[1] : '14'})`);
  s = replaceAllCalls(s, 'ta.sma', (args) => `SMA(${args[1] !== undefined ? args[1] : '20'})`);
  s = replaceAllCalls(s, 'ta.ema', (args) => `EMA(${args[1] !== undefined ? args[1] : '20'})`);
  s = s.replace(/\bclose\b/gi, 'CLOSE').replace(/\bopen\b/gi, 'OPEN')
       .replace(/\bhigh\b/gi, 'HIGH').replace(/\blow\b/gi, 'LOW').replace(/\bvolume\b/gi, 'VOLUME');
  s = s.replace(/\band\b/gi, 'AND').replace(/\bor\b/gi, 'OR').replace(/\bnot\b/gi, 'NOT');
  return s.trim();
}
function translateMql5ToNative(src) {
  let s = src;
  s = replaceAllCalls(s, 'iRSI', (args) => `RSI(${args[2] !== undefined ? args[2] : '14'})`);
  s = replaceAllCalls(s, 'iMA', (args) => {
    const period = args[2] !== undefined ? args[2] : '20';
    const method = (args[4] || '').toUpperCase();
    return method.includes('EMA') ? `EMA(${period})` : `SMA(${period})`;
  });
  s = s.replace(/\bClose\s*\[\s*\d+\s*\]/gi, 'CLOSE').replace(/\bOpen\s*\[\s*\d+\s*\]/gi, 'OPEN')
       .replace(/\bHigh\s*\[\s*\d+\s*\]/gi, 'HIGH').replace(/\bLow\s*\[\s*\d+\s*\]/gi, 'LOW')
       .replace(/\bVolume\s*\[\s*\d+\s*\]/gi, 'VOLUME');
  s = s.replace(/&&/g, ' AND ').replace(/\|\|/g, ' OR ').replace(/!(?!=)/g, ' NOT ');
  return s.trim();
}
function translateToNativeEquation(value, language) {
  if (language === 'pine') return translatePineToNative(value);
  if (language === 'mql5') return translateMql5ToNative(value);
  return value; // 'native' or unset: no translation needed
}
// Parses once, caches the result on the condition object itself (keyed by
// the source string) so re-evaluating the same formula across many bars in
// a backtest doesn't re-tokenize/re-parse it every single time.
function evalCustomEquation(c, i, bars) {
  try {
    const lang = c.language || 'native';
    const cacheKey = lang + ':' + c.value;
    if (!c._parsedCache || c._parsedCache.key !== cacheKey) {
      const native = translateToNativeEquation(c.value, lang);
      c._parsedCache = { key: cacheKey, ast: parseExpr(native) };
    }
    if (!c._exprCache) c._exprCache = buildExprCache(bars);
    return evalExprNode(c._parsedCache.ast, i, bars, c._exprCache, {});
  } catch (e) {
    return null; // malformed equation: treated as "not evaluable", same as insufficient warm-up data
  }
}
async function runLiveTickForDeployment(dep, client) {
  try {
    const adapter = getBrokerAdapter(dep.broker);
    if (!adapter || !adapter.supportsAutomatedExecution) {
      await client.query('UPDATE live_deployments SET status=$1, last_error=$2, last_checked_at=now() WHERE id=$3', ['error', `${dep.broker} does not support automated execution.`, dep.id]);
      return;
    }
    const credRes = await client.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [dep.username, dep.broker]);
    if (!credRes.rows.length) { await client.query('UPDATE live_deployments SET status=$1, last_error=$2, last_checked_at=now() WHERE id=$3', ['error', 'Broker no longer connected', dep.id]); return; }
    const creds = { primary: credRes.rows[0].api_key_id, secretPlain: decryptSecret(credRes.rows[0].api_secret_enc), baseUrl: credRes.rows[0].base_url };

    if (dep.status === 'watching') {
      const bars = await adapter.getBars(creds, dep.symbol, dep.timeframe, 200);
      if (bars.length < 30) { await client.query('UPDATE live_deployments SET last_checked_at=now() WHERE id=$1', [dep.id]); return; }
      const conditions = dep.entry_conditions;
      const cache = buildIndicatorCache(bars, conditions);
      const lastIdx = bars.length - 1;
      const audit = buildAuditSnapshot(conditions, bars, cache);
      await client.query(
        'UPDATE live_deployments SET audit_conditions=$1, audit_signal=$2, audit_price=$3, audit_at=now(), last_checked_at=now() WHERE id=$4',
        [JSON.stringify(audit.details), audit.signal, audit.price, dep.id]
      );
      const signal = audit.signal;
      if (!signal) return;

      const acctResult = await adapter.fetchAccount(creds);
      if (!acctResult.ok) { await client.query('UPDATE live_deployments SET status=$1, last_error=$2, last_checked_at=now() WHERE id=$3', ['error', 'Could not read account equity', dep.id]); return; }
      const equity = parseFloat(acctResult.accountSummary.equity) || 0;
      const entryPrice = bars[lastIdx].close;
      const riskAmt = equity * (parseFloat(dep.position_size_pct) / 100);
      const qty = Math.max(1, Math.floor(riskAmt / entryPrice));
      const side = dep.direction === 'short' ? 'sell' : 'buy';
      const tp = parseFloat(dep.take_profit_pct) / 100, sl = parseFloat(dep.stop_loss_pct) / 100;
      const takeProfitPrice = dep.direction === 'short' ? entryPrice * (1 - tp) : entryPrice * (1 + tp);
      const stopLossPrice = dep.direction === 'short' ? entryPrice * (1 + sl) : entryPrice * (1 - sl);

      const orderRes = await adapter.placeOrder(creds, {
        symbol: dep.symbol, qty: String(qty), side, type: 'market', time_in_force: 'day',
        order_class: 'bracket',
        take_profit: { limit_price: takeProfitPrice.toFixed(2) },
        stop_loss: { stop_price: stopLossPrice.toFixed(2) },
      });
      if (!orderRes.ok) {
        const errBody = await orderRes.json().catch(() => ({}));
        await client.query('UPDATE live_deployments SET status=$1, last_error=$2, last_checked_at=now() WHERE id=$3', ['error', (errBody.message || `Order rejected by ${adapter.name}`).slice(0, 500), dep.id]);
        return;
      }
      const order = await orderRes.json();
      await client.query(
        `UPDATE live_deployments SET status='open', entry_order_id=$1, entry_price=$2, qty=$3, opened_at=now(), last_checked_at=now(), last_error=NULL WHERE id=$4`,
        [order.id, entryPrice, qty, dep.id]
      );
      await client.query(
        `INSERT INTO live_trade_log (username, strategy_id, strategy_name, broker, symbol, side, qty, entry_order_id, entry_price, opened_at, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),'open')`,
        [dep.username, dep.strategy_id, dep.strategy_name, dep.broker, dep.symbol, side, qty, order.id, entryPrice]
      );
    } else if (dep.status === 'open') {
      // Check whether the position is still open at the broker (the
      // bracket's take-profit or stop-loss leg may have already closed it
      // broker-side, independent of this server).
      const posRes = await adapter.getPosition(creds, dep.symbol);
      if (posRes.status === 404) {
        await client.query(`UPDATE live_deployments SET status='closed', closed_at=now(), last_checked_at=now() WHERE id=$1`, [dep.id]);
        const exitPrice = adapter.findRecentExitPrice ? await adapter.findRecentExitPrice(creds, dep.symbol, dep.entry_order_id) : null;
        await client.query(
          `UPDATE live_trade_log SET status='closed', closed_at=now(), exit_price=$1
           WHERE username=$2 AND strategy_id=$3 AND entry_order_id=$4 AND status='open'`,
          [exitPrice, dep.username, dep.strategy_id, dep.entry_order_id]
        );
      } else {
        await client.query('UPDATE live_deployments SET last_checked_at=now() WHERE id=$1', [dep.id]);
      }
    }
  } catch (e) {
    console.error('live tick error for deployment', dep.id, e.message);
    await client.query('UPDATE live_deployments SET last_error=$1, last_checked_at=now() WHERE id=$2', [String(e.message).slice(0, 500), dep.id]).catch(() => {});
  }
}

async function runLiveTick() {
  const client = await pool.connect();
  try {
    const res = await client.query(`SELECT * FROM live_deployments WHERE status IN ('watching','open') FOR UPDATE SKIP LOCKED`);
    for (const dep of res.rows) {
      await runLiveTickForDeployment(dep, client);
    }
  } catch (e) {
    console.error('runLiveTick error:', e.message);
  } finally {
    client.release();
  }
}
if (process.env.DISABLE_LIVE_TICK !== '1') {
  setInterval(() => { runLiveTick().catch(e => console.error('live tick loop error:', e.message)); }, LIVE_TICK_INTERVAL_MS);
}

app.post('/api/live/deploy', requireAuth, async (req, res) => {
  const { strategyId, strategyName, symbol, timeframe, direction, entryConditions, takeProfit, stopLoss, positionSizePct } = req.body || {};
  if (!strategyId || !symbol || !direction || !Array.isArray(entryConditions) || !entryConditions.length) {
    return res.status(400).json({ error: 'Missing required strategy fields.' });
  }
  if (!isAlpacaTradable(symbol)) {
    return res.status(422).json({ error: `Real live execution is only available for plain US equity/ETF tickers Alpaca can trade, "${symbol}" isn't one. Every other instrument (GCC, forex, commodities, crypto, indices, and every broker besides Alpaca) remains demo/simulation only for now.` });
  }
  const credRes = await pool.query('SELECT 1 FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
  if (!credRes.rows.length) return res.status(422).json({ error: 'Connect Alpaca before going live.' });
  try {
    await pool.query(
      `INSERT INTO live_deployments (username, strategy_id, strategy_name, broker, symbol, timeframe, direction, entry_conditions, take_profit_pct, stop_loss_pct, position_size_pct, status)
       VALUES ($1,$2,$3,'alpaca',$4,$5,$6,$7,$8,$9,$10,'watching')
       ON CONFLICT (username, strategy_id) DO UPDATE SET
         strategy_name=$3, symbol=$4, timeframe=$5, direction=$6, entry_conditions=$7, take_profit_pct=$8, stop_loss_pct=$9, position_size_pct=$10,
         status='watching', entry_order_id=NULL, entry_price=NULL, qty=NULL, opened_at=NULL, closed_at=NULL, last_error=NULL`,
      [req.username, strategyId, strategyName || '', symbol, timeframe || '15m', direction, JSON.stringify(entryConditions), takeProfit, stopLoss, positionSizePct]
    );
    res.json({ ok: true, status: 'watching' });
  } catch (e) {
    console.error('live deploy error:', e.message);
    res.status(500).json({ error: 'Could not start live monitoring.' });
  }
});

app.get('/api/live/status', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT strategy_id, symbol, status, direction, entry_price, qty, entry_order_id, opened_at, last_error, last_checked_at, audit_conditions, audit_signal, audit_price, audit_at FROM live_deployments WHERE username=$1', [req.username]);
  res.json({ deployments: result.rows });
});

// Full real trade history for one strategy, independent of live_deployments'
// single current-state row, this is every entry/exit the strategy has
// genuinely made, scoped to just that strategy rather than mixed into the
// account-wide activity feed.
app.get('/api/live/trades/:strategyId', requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT symbol, side, qty, entry_price, opened_at, exit_price, closed_at, status
     FROM live_trade_log WHERE username=$1 AND strategy_id=$2 ORDER BY opened_at DESC LIMIT 200`,
    [req.username, req.params.strategyId]
  );
  res.json({ trades: result.rows });
});

// The dashboard's equity figure needs a genuine, accumulating number, not a
// static blend of each strategy's backtest percentage. This sums REAL
// realized P&L across every one of the user's closed real trades, in
// dollar terms, computed straight from actual entry/exit fills, not a
// projection. A user with no real closed trades yet correctly gets 0, so
// the dashboard can show the clean $10,000 baseline rather than a
// misleading number.
app.get('/api/live/realized-pnl', requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN side = 'buy' THEN (exit_price - entry_price) * qty
                          ELSE (entry_price - exit_price) * qty END), 0) AS realized_pnl,
       COUNT(*) AS closed_trades
     FROM live_trade_log
     WHERE username=$1 AND status='closed' AND exit_price IS NOT NULL`,
    [req.username]
  );
  const row = result.rows[0];
  res.json({ realizedPnl: parseFloat(row.realized_pnl), closedTrades: parseInt(row.closed_trades, 10) });
});

// Shared by the single-strategy close endpoint and the new close-all/
// emergency-stop bulk actions below, closing a real broker position is
// genuinely the same operation regardless of how many strategies triggered
// it at once.
async function closeDeploymentPosition(username, dep) {
  if (dep.status !== 'open') {
    await pool.query(`UPDATE live_deployments SET status='closed', closed_at=now() WHERE id=$1`, [dep.id]);
    return { ok: true, note: 'No open position, deployment stopped.' };
  }
  const credRes = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [username, dep.broker]);
  if (!credRes.rows.length) return { ok: false, status: 422, error: 'Broker no longer connected.' };
  const apiKeyId = credRes.rows[0].api_key_id;
  const baseUrl = credRes.rows[0].base_url;
  try {
    // Decryption failure (a stored credential encrypted under a since-
    // rotated key, or corrupted data) must not be able to crash the whole
    // process, it needs to surface as a normal, catchable failure for this
    // one request like everything else in this block.
    const apiSecretKey = decryptSecret(credRes.rows[0].api_secret_enc);
    const closeRes = await alpacaRequest(baseUrl, apiKeyId, apiSecretKey, `/v2/positions/${encodeURIComponent(dep.symbol)}`, { method: 'DELETE' });
    if (!closeRes.ok && closeRes.status !== 404) {
      const errBody = await closeRes.json().catch(() => ({}));
      return { ok: false, status: 502, error: errBody.message || 'Alpaca could not close the position.' };
    }
    await pool.query(`UPDATE live_deployments SET status='closed', closed_at=now() WHERE id=$1`, [dep.id]);
    const adapter = getBrokerAdapter(dep.broker);
    const creds = { primary: apiKeyId, secretPlain: apiSecretKey, baseUrl };
    const exitPrice = adapter && adapter.findRecentExitPrice ? await adapter.findRecentExitPrice(creds, dep.symbol, dep.entry_order_id) : null;
    await pool.query(
      `UPDATE live_trade_log SET status='closed', closed_at=now(), exit_price=$1
       WHERE username=$2 AND strategy_id=$3 AND entry_order_id=$4 AND status='open'`,
      [exitPrice, username, dep.strategy_id, dep.entry_order_id]
    );
    return { ok: true };
  } catch (e) {
    console.error('live close error:', e.message);
    return { ok: false, status: 500, error: 'Could not reach Alpaca to close the position.' };
  }
}
app.post('/api/live/close/:strategyId', requireAuth, async (req, res) => {
  const depRes = await pool.query('SELECT * FROM live_deployments WHERE username=$1 AND strategy_id=$2', [req.username, req.params.strategyId]);
  if (!depRes.rows.length) return res.status(404).json({ error: 'No live deployment found for this strategy.' });
  const result = await closeDeploymentPosition(req.username, depRes.rows[0]);
  if (!result.ok) return res.status(result.status || 502).json({ error: result.error });
  res.json(result);
});

// Fully removes a strategy from live tracking, closing any real open
// position first so nothing is left orphaned at the broker with no
// deployment row watching it. Deleting the row (rather than just changing
// its status) means a later redeploy is a clean INSERT, not stale state
// from a previous run.
app.post('/api/live/undeploy/:strategyId', requireAuth, async (req, res) => {
  const depRes = await pool.query('SELECT * FROM live_deployments WHERE username=$1 AND strategy_id=$2', [req.username, req.params.strategyId]);
  if (!depRes.rows.length) return res.json({ ok: true, note: 'Nothing was deployed for this strategy.' });
  const dep = depRes.rows[0];
  if (dep.status === 'open') {
    const closeResult = await closeDeploymentPosition(req.username, dep);
    if (!closeResult.ok) return res.status(closeResult.status || 502).json({ error: `Could not close the open position before undeploying: ${closeResult.error}` });
  }
  await pool.query('DELETE FROM live_deployments WHERE username=$1 AND strategy_id=$2', [req.username, req.params.strategyId]);
  res.json({ ok: true });
});

// ------------------------------------------------------------- quick actions
app.post('/api/live/pause/:strategyId', requireAuth, async (req, res) => {
  // Pausing only makes sense for a deployment still watching for an entry
  // signal, not one that already has a real position open, closing a real
  // open position needs a real close (see below), not just muting the
  // scheduler's attention to it.
  const result = await pool.query(
    `UPDATE live_deployments SET status='paused' WHERE username=$1 AND strategy_id=$2 AND status='watching' RETURNING id`,
    [req.username, req.params.strategyId]
  );
  if (!result.rows.length) return res.status(409).json({ error: 'Only a strategy currently watching for entries can be paused.' });
  res.json({ ok: true });
});
app.post('/api/live/resume/:strategyId', requireAuth, async (req, res) => {
  const result = await pool.query(
    `UPDATE live_deployments SET status='watching' WHERE username=$1 AND strategy_id=$2 AND status='paused' RETURNING id`,
    [req.username, req.params.strategyId]
  );
  if (!result.rows.length) return res.status(409).json({ error: 'This strategy is not currently paused.' });
  res.json({ ok: true });
});
app.post('/api/live/close-all', requireAuth, async (req, res) => {
  const openDeps = await pool.query(`SELECT * FROM live_deployments WHERE username=$1 AND status='open'`, [req.username]);
  const results = [];
  for (const dep of openDeps.rows) {
    const r = await closeDeploymentPosition(req.username, dep);
    results.push({ strategyId: dep.strategy_id, ok: r.ok, error: r.error });
  }
  res.json({ closed: results.filter(r => r.ok).length, failed: results.filter(r => !r.ok).length, results });
});
app.post('/api/live/emergency-stop', requireAuth, async (req, res) => {
  // The kill switch: pause everything still just watching, AND close every
  // real open position, in one call, for when a user wants to stop all
  // activity immediately rather than handle each strategy one at a time.
  await pool.query(`UPDATE live_deployments SET status='paused' WHERE username=$1 AND status='watching'`, [req.username]);
  const openDeps = await pool.query(`SELECT * FROM live_deployments WHERE username=$1 AND status='open'`, [req.username]);
  const results = [];
  for (const dep of openDeps.rows) {
    const r = await closeDeploymentPosition(req.username, dep);
    results.push({ strategyId: dep.strategy_id, ok: r.ok, error: r.error });
  }
  res.json({ paused: true, positionsClosed: results.filter(r => r.ok).length, positionsFailed: results.filter(r => !r.ok).length, results });
});


// --------------------------------------------------------------- AI features
// Unlike the Alpaca integration (where each trader supplies their OWN broker
// key, because it's their own money and liability), AI features use ONE key
// held by the platform itself, the same pattern as GitHub Copilot or Notion
// AI, where the company pays for the underlying model and it's a bundled
// product capability, not something each user separately authenticates to.
// Entirely optional: with no key configured, every AI endpoint below reports
// itself unavailable and the app's existing keyword/rules-based fallbacks
// keep working exactly as before, same graceful-degradation pattern used
// for the backend and broker integration throughout this app.
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || null;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5';
const ANTHROPIC_BASE_URL = process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';

// Simple in-memory sliding-window rate limiter, keyed per user. Resets on
// restart and doesn't share state across multiple server instances, fine
// for a single-instance prototype; a real multi-instance deployment would
// move this to Postgres or Redis, same caveat as any in-memory state here.
const aiRateLimits = new Map(); // username -> array of call timestamps (ms)
const AI_RATE_LIMIT_MAX = 20;
const AI_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
function checkAiRateLimit(username) {
  const now = Date.now();
  const calls = (aiRateLimits.get(username) || []).filter(t => now - t < AI_RATE_LIMIT_WINDOW_MS);
  if (calls.length >= AI_RATE_LIMIT_MAX) { aiRateLimits.set(username, calls); return false; }
  calls.push(now);
  aiRateLimits.set(username, calls);
  return true;
}

async function callClaude(system, userContent, toolSchema) {
  const res = await fetch(ANTHROPIC_BASE_URL + '/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: 1024,
      system,
      messages: [{ role: 'user', content: userContent }],
      tools: [toolSchema],
      tool_choice: { type: 'tool', name: toolSchema.name },
    }),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    const err = new Error((errBody.error && errBody.error.message) || `Anthropic API error ${res.status}`);
    err.status = res.status;
    throw err;
  }
  const data = await res.json();
  const toolUse = (data.content || []).find(b => b.type === 'tool_use');
  if (!toolUse) throw new Error('Model did not return structured output');
  return toolUse.input;
}

const LOGIC_CHECK_SYSTEM_PROMPT = `You are a static analysis tool for algorithmic trading strategy DEFINITIONS. Your ONLY job is to check the internal logical consistency and structural soundness of a set of entry conditions someone has already written in a no-code strategy builder. You have no access to live or historical market data, you form no opinion on whether any market will go up or down, and you must never suggest whether someone should place a trade.

Check ONLY for:
1. Logical contradictions, e.g. two ANDed conditions on the same indicator that can mathematically never both be true at once.
2. Redundant conditions, two conditions that always produce the same result given the same inputs.
3. Parameter values outside sane technical ranges for the indicator (e.g. an RSI threshold outside 0-100, a moving-average period of 0).
4. Risk parameters that are mathematically suspect relative to each other (e.g. take-profit far smaller than stop-loss, or position size that seems disproportionate), describe this ONLY as a factual ratio or structural observation about the numbers entered, never as a market prediction or recommendation.
5. Combinatorial rarity, if many conditions are ANDed together, you may note as a factual observation about combinatorial logic (not a market prediction) that requiring many simultaneous conditions narrows how often a signal fires.

You must NEVER:
- Comment on whether a symbol, direction, or instrument choice is a good idea.
- Reference current, recent, or predicted market conditions of any kind.
- Suggest a specific parameter value as "better," "optimal," or "recommended."
- Use language implying certainty or likelihood about future performance ("will," "should perform," "likely to," "expected to").
- Invent a finding that isn't genuinely present, to seem more useful. An empty findings list is a valid and good result.

Respond only via the check_strategy_logic tool.`;

const LOGIC_CHECK_TOOL = {
  name: 'check_strategy_logic',
  description: 'Report structural/logical findings about a trading strategy definition.',
  input_schema: {
    type: 'object',
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            severity: { type: 'string', enum: ['error', 'warning', 'info'] },
            message: { type: 'string', description: 'Plain-English, factual, non-predictive description of the issue.' },
          },
          required: ['severity', 'message'],
        },
      },
    },
    required: ['findings'],
  },
};

app.get('/api/ai/status', requireAuth, (req, res) => {
  res.json({ available: !!ANTHROPIC_API_KEY });
});

app.post('/api/ai/check-strategy-logic', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI features are not configured on this deployment.', available: false });
  if (!checkAiRateLimit(req.username)) return res.status(429).json({ error: 'AI check limit reached for this hour. Try again later.' });
  const { symbol, timeframe, direction, entryConditions, takeProfit, stopLoss, positionSizePct } = req.body || {};
  if (!Array.isArray(entryConditions) || !entryConditions.length) return res.status(400).json({ error: 'entryConditions required' });
  try {
    const description = JSON.stringify({ symbol, timeframe, direction, entryConditions, takeProfit, stopLoss, positionSizePct }, null, 2);
    const result = await callClaude(
      LOGIC_CHECK_SYSTEM_PROMPT,
      `Check this strategy definition for structural/logical issues only:\n\n${description}`,
      LOGIC_CHECK_TOOL
    );
    const findings = Array.isArray(result.findings) ? result.findings.slice(0, 10) : [];
    res.json({ findings });
  } catch (e) {
    console.error('ai check-strategy-logic error:', e.message);
    res.status(502).json({ error: 'Could not complete the AI logic check right now.' });
  }
});

const STRATEGY_GENERATE_SYSTEM_PROMPT = `You are a translator that converts a plain-English trading strategy description into structured parameters for a no-code strategy builder. You do not recommend strategies, judge whether an idea is sound, or add anything the user didn't describe or a stated convention doesn't justify. Your only job is to map what the user said onto the available schema below, this is translation, not advice.

Available indicators and their exact operator strings (use these exact strings):
- rsi: "is below" | "is above", value is the RSI threshold, 0-100
- macd: "crosses above signal" | "crosses below signal", no value needed, use ""
- sma_cross: "fast crosses above slow" | "fast crosses below slow", value is "fast/slow" like "9/21"
- ema_cross: same operators as sma_cross, value is "fast/slow" like "12/26"
- bbands: "price breaks upper band" | "price breaks lower band", no value needed, use ""
- breakout: "breaks above N-bar high" | "breaks below N-bar low", value is N, an integer bar count
- volume: "is above average by", value is a percentage number, e.g. "150"
- vwap: "price crosses above" | "price crosses below", no value needed, use ""

Rules:
- If the user describes multiple conditions, include multiple, joined with "AND" (all must be true) or "OR" (any is enough) based on their wording, default to AND if ambiguous.
- If the user names a specific instrument (ticker or common company/asset name), extract your best-guess ticker symbol. If genuinely unclear, leave it as an empty string.
- If the user doesn't specify a numeric threshold, use the standard textbook default for that indicator (RSI oversold=30, overbought=70; breakout=20 bars; volume spike=150%) and mark that condition's "defaulted" field true.
- If take-profit or stop-loss aren't mentioned, use 1.5 and 0.8 respectively and note it in matchedSummary.
- Never invent a condition, symbol, or risk parameter that has no basis in what was said or an explicitly-noted default.
- matchedSummary should be short, plain-English bullet points a person can quickly verify against what they typed, noting anything that was defaulted.

Respond only via the generate_strategy tool.`;

const STRATEGY_GENERATE_TOOL = {
  name: 'generate_strategy',
  description: 'Return structured no-code strategy parameters translated from a plain-English description.',
  input_schema: {
    type: 'object',
    properties: {
      symbol: { type: 'string', description: 'Best-guess ticker, or empty string if unclear.' },
      conditions: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            indicator: { type: 'string', enum: ['rsi', 'macd', 'sma_cross', 'ema_cross', 'bbands', 'breakout', 'volume', 'vwap'] },
            operator: { type: 'string' },
            value: { type: 'string' },
            logic: { type: 'string', enum: ['AND', 'OR'] },
            defaulted: { type: 'boolean' },
          },
          required: ['indicator', 'operator', 'value', 'logic', 'defaulted'],
        },
      },
      direction: { type: 'string', enum: ['long', 'short', 'both'] },
      timeframe: { type: 'string', enum: ['1m', '5m', '15m', '30m', '1H', '4H', '1D'] },
      takeProfit: { type: 'number' },
      stopLoss: { type: 'number' },
      matchedSummary: { type: 'array', items: { type: 'string' } },
    },
    required: ['symbol', 'conditions', 'direction', 'timeframe', 'takeProfit', 'stopLoss', 'matchedSummary'],
  },
};

app.post('/api/ai/generate-strategy', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI features are not configured on this deployment.', available: false });
  if (!checkAiRateLimit(req.username)) return res.status(429).json({ error: 'AI generation limit reached for this hour. Try again later.' });
  const { text } = req.body || {};
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'text required' });
  try {
    const result = await callClaude(
      STRATEGY_GENERATE_SYSTEM_PROMPT,
      `Translate this strategy description into the schema:\n\n"${String(text).slice(0, 500)}"`,
      STRATEGY_GENERATE_TOOL
    );
    res.json(result);
  } catch (e) {
    console.error('ai generate-strategy error:', e.message);
    res.status(502).json({ error: 'Could not complete the AI generation right now.' });
  }
});

// The AI Portfolio Agent, Pro-tier only. It reasons ONLY over backtest and
// deployment data the user already has, exactly what the Portfolio page
// itself computes, it has no live market data and forms no view on where
// any price is headed. It never executes anything: every suggestion is
// surfaced in the UI as a prompt for the user to review and act on through
// the same confirmed pause/undeploy flows that already exist, this
// endpoint only returns a structured opinion, nothing it returns can
// itself touch a strategy or a position.
const PORTFOLIO_AGENT_SYSTEM_PROMPT = `You are a portfolio review assistant for a no-code algorithmic trading platform. You analyze a trader's EXISTING active strategies using only the backtest and position-sizing data given to you below. You have no access to live market data, no ability to predict future prices, and no opinion on where any market is headed. Never suggest a trade, a new strategy, or a prediction, your only job is to review what is already deployed and flag things worth a human's attention.

Ground every suggestion in the specific numbers given, reference the exact strategy name when a suggestion is about one strategy. Do not invent numbers or strategies not in the data. If the data shows nothing notable, say so plainly rather than manufacturing a concern.

Each suggestion needs a "type":
- "pause_review": a specific strategy's backtest performance (return, drawdown, Sharpe) looks weak enough to be worth the trader reconsidering whether it should still be live. Only use this for a genuinely weak case, not routine variance.
- "concentration_risk": exposure is heavily concentrated in one asset class or symbol, name the specific class/symbol and the percentage.
- "hedge_note": two or more strategies are naturally offsetting each other (both long and short on the same symbol), note it factually, this isn't necessarily a problem.
- "strong_performer": a specific strategy's backtest numbers are notably good, worth knowing, not necessarily actionable.
- "general": anything else genuinely useful that doesn't fit the above, used sparingly.

For "pause_review" suggestions only, include the exact strategyId from the data so the UI can offer a direct action, for every other type leave strategyId as an empty string.

Respond only via the portfolio_agent_review tool.`;

const PORTFOLIO_AGENT_TOOL = {
  name: 'portfolio_agent_review',
  description: 'Return a structured review of the trader\'s active strategies.',
  input_schema: {
    type: 'object',
    properties: {
      suggestions: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['pause_review', 'concentration_risk', 'hedge_note', 'strong_performer', 'general'] },
            strategyId: { type: 'string', description: 'Exact strategyId from the data, only for pause_review, empty string otherwise.' },
            strategyName: { type: 'string', description: 'The strategy name this is about, empty string if not about one specific strategy.' },
            message: { type: 'string', description: 'One or two plain-English sentences, grounded in the specific numbers given.' },
          },
          required: ['type', 'strategyId', 'strategyName', 'message'],
        },
      },
    },
    required: ['suggestions'],
  },
};

app.post('/api/ai/portfolio-agent', requireAuth, requireProTier, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI features are not configured on this deployment.', available: false });
  if (!checkAiRateLimit(req.username)) return res.status(429).json({ error: 'AI agent limit reached for this hour. Try again later.' });
  try {
    const row = await pool.query('SELECT value FROM kv_shared WHERE key=$1', ['user:' + req.username]);
    if (!row.rows.length) return res.status(404).json({ error: 'No profile data found.' });
    const blob = JSON.parse(row.rows[0].value);
    const strategies = Array.isArray(blob.strategies) ? blob.strategies : [];
    const active = strategies.filter(s => s.status === 'demo' || s.status === 'live');
    if (!active.length) return res.json({ suggestions: [], noActiveStrategies: true });

    const dataForModel = active.map(s => {
      const deployed = (s.positionSizePct || 0) / 100 * 10000;
      const bt = s.backtest || null;
      return {
        strategyId: s.id, name: s.name, symbol: s.symbol, direction: s.direction, status: s.status,
        deployedUsd: Math.round(deployed * 100) / 100,
        backtestWinRatePct: bt ? bt.winRate : null,
        backtestTotalReturnPct: bt ? bt.totalReturn : null,
        backtestSharpe: bt ? bt.sharpe : null,
        backtestMaxDrawdownPct: bt ? bt.maxDrawdown : null,
      };
    });
    const result = await callClaude(
      PORTFOLIO_AGENT_SYSTEM_PROMPT,
      `Here are this trader's active strategies:\n\n${JSON.stringify(dataForModel, null, 2)}`,
      PORTFOLIO_AGENT_TOOL
    );
    const suggestions = Array.isArray(result.suggestions) ? result.suggestions.slice(0, 8) : [];
    res.json({ suggestions });
  } catch (e) {
    console.error('ai portfolio-agent error:', e.message);
    res.status(502).json({ error: 'Could not complete the AI portfolio review right now.' });
  }
});


const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
});

app.use(express.static(path.join(__dirname, '..', 'public')));

// ---------------------------------------------------------------- helpers
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
async function getUserFromToken(token) {
  if (!token) return null;
  const r = await pool.query('SELECT username FROM sessions WHERE token = $1', [token]);
  return r.rows.length ? r.rows[0].username : null;
}
function getToken(req) {
  const h = req.headers['authorization'] || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}
async function requireAuth(req, res, next) {
  const token = getToken(req);
  const username = await getUserFromToken(token);
  if (!username) return res.status(401).json({ error: 'not authenticated' });
  req.username = username;
  next();
}
// Chained after requireAuth (needs req.username already set). Checked fresh
// from the database on every request, not cached on the token, so revoking
// admin access (were that ever needed) takes effect immediately.
async function requireAdmin(req, res, next) {
  const r = await pool.query('SELECT is_admin FROM users WHERE username=$1', [req.username]);
  if (!r.rows.length || !r.rows[0].is_admin) return res.status(403).json({ error: 'Admin access required.' });
  next();
}
// The AI Portfolio Agent is a Pro-tier feature. An active trial counts as
// Pro here too, same exemption the free-tier strategy limit already
// grants, since the trial is meant to be a genuine Pro experience, not a
// crippled preview.
async function requireProTier(req, res, next) {
  const r = await pool.query('SELECT plan_tier, trial_ends_at FROM users WHERE username=$1', [req.username]);
  if (!r.rows.length) return res.status(403).json({ error: 'The AI Portfolio Agent is available on the Pro plan.', upgradeRequired: true });
  const planTier = r.rows[0].plan_tier || 'free';
  const trialActive = r.rows[0].trial_ends_at && new Date(r.rows[0].trial_ends_at).getTime() > Date.now();
  if (planTier === 'pro' || trialActive) return next();
  return res.status(403).json({ error: 'The AI Portfolio Agent is available on the Pro plan.', upgradeRequired: true });
}

const FREE_TIER_STRATEGY_LIMIT = 1; // 1 built from scratch + 1 copied/template, per the product spec
// Guards the free tier's limit at the actual save point (the generic profile
// PUT below), not just in the UI, a client could otherwise bypass any
// front-end-only check by calling the API directly. Only blocks a save that
// would INCREASE a bucket's count past the limit; never blocks unrelated
// edits (settings, XP, etc.) for an account that already has more strategies
// than this (e.g. legacy data, or a downgraded paid account), since the
// point is to stop new over-limit additions, not retroactively lock out
// data that already existed.
async function checkFreeTierStrategyLimit(username, key, newValueRaw) {
  try {
    const userRow = await pool.query('SELECT plan_tier, trial_ends_at FROM users WHERE username=$1', [username]);
    if (!userRow.rows.length) return null;
    const planTier = userRow.rows[0].plan_tier || 'free';
    const trialEndsAt = userRow.rows[0].trial_ends_at;
    const onActiveTrial = trialEndsAt && new Date(trialEndsAt).getTime() > Date.now();
    if (planTier !== 'free' || onActiveTrial) return null;
    const newBlob = JSON.parse(newValueRaw);
    const newStrategies = Array.isArray(newBlob.strategies) ? newBlob.strategies : [];
    const newOwn = newStrategies.filter(s => !s.copiedFromId).length;
    const newCopied = newStrategies.filter(s => s.copiedFromId).length;

    const oldRow = await pool.query('SELECT value FROM kv_shared WHERE key=$1', [key]);
    let oldOwn = 0, oldCopied = 0;
    if (oldRow.rows.length) {
      const oldBlob = JSON.parse(oldRow.rows[0].value);
      const oldStrategies = Array.isArray(oldBlob.strategies) ? oldBlob.strategies : [];
      oldOwn = oldStrategies.filter(s => !s.copiedFromId).length;
      oldCopied = oldStrategies.filter(s => s.copiedFromId).length;
    }
    if (newOwn > oldOwn && newOwn > FREE_TIER_STRATEGY_LIMIT) {
      return { error: 'The free plan is limited to 1 strategy built from scratch. Upgrade to build more.', upgradeRequired: true, limitType: 'own' };
    }
    if (newCopied > oldCopied && newCopied > FREE_TIER_STRATEGY_LIMIT) {
      return { error: 'The free plan is limited to 1 copied strategy or template. Upgrade to copy more.', upgradeRequired: true, limitType: 'copied' };
    }
    return null;
  } catch (e) {
    return null; // not a strategies-bearing blob, or didn't parse as expected: don't block the save over this check
  }
}

app.get('/api/billing/status', requireAuth, async (req, res) => {
  const r = await pool.query('SELECT plan_tier, subscription_status, creator_credit_cents, stripe_customer_id, trial_ends_at FROM users WHERE username=$1', [req.username]);
  const row = r.rows[0] || { plan_tier: 'free', subscription_status: null, creator_credit_cents: 0, stripe_customer_id: null, trial_ends_at: null };
  const trialActive = !!(row.trial_ends_at && new Date(row.trial_ends_at).getTime() > Date.now());
  res.json({
    planTier: row.plan_tier, subscriptionStatus: row.subscription_status,
    billingConfigured: !!(STRIPE_SECRET_KEY && STRIPE_PRICE_IDS.starter && STRIPE_PRICE_IDS.pro),
    creatorCreditCents: row.creator_credit_cents || 0, hasStripeCustomer: !!row.stripe_customer_id,
    trialEndsAt: row.trial_ends_at, trialActive,
  });
});

// A comp-access path entirely separate from real Stripe billing, for
// granting a tier for free (beta testers, the app owner's own account),
// not a discount on a paid subscription. Row-locked inside a transaction
// so two people redeeming the same last-use code at the same instant can't
// both succeed against a code meant for one use.
app.post('/api/billing/redeem', requireAuth, async (req, res) => {
  const code = ((req.body && req.body.code) || '').trim();
  if (!code) return res.status(400).json({ error: 'Enter a code.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const codeRow = await client.query('SELECT * FROM redemption_codes WHERE code=$1 FOR UPDATE', [code]);
    if (!codeRow.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: "That code isn't valid." }); }
    const rc = codeRow.rows[0];
    if (rc.expires_at && new Date(rc.expires_at) < new Date()) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'That code has expired.' }); }
    if (rc.uses_count >= rc.max_uses) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'That code has already been fully redeemed.' }); }
    const already = await client.query('SELECT 1 FROM redemption_code_uses WHERE code=$1 AND username=$2', [code, req.username]);
    if (already.rows.length) { await client.query('ROLLBACK'); return res.status(400).json({ error: "You've already redeemed this code." }); }
    await client.query('UPDATE redemption_codes SET uses_count = uses_count + 1 WHERE code=$1', [code]);
    await client.query('INSERT INTO redemption_code_uses (code, username) VALUES ($1, $2)', [code, req.username]);
    await client.query('UPDATE users SET plan_tier=$1 WHERE username=$2', [rc.tier, req.username]);
    // Redeeming the permanent, single-use founder code is itself proof of
    // being the founder account, since only one person can ever succeed at
    // it (the checks above already enforce max_uses=1 and one redemption
    // per username). Grant admin access as part of the same transaction.
    if (code === 'TAIWOADENUSI') {
      await client.query('UPDATE users SET is_admin=true WHERE username=$1', [req.username]);
    }
    await client.query('COMMIT');
    res.json({ ok: true, tier: rc.tier });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('redeem error:', e.message);
    res.status(500).json({ error: 'Could not redeem that code, try again.' });
  } finally {
    client.release();
  }
});

// Lets any signed-in user mint their own redemption code (e.g. to share
// with a friend or a beta tester), reusing the exact same redemption
// mechanism above, not a separate, unaudited path to a paid tier.
function generateCodeString() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I, easy to read aloud
  let s = '';
  for (let i = 0; i < 10; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}
app.post('/api/billing/generate-code', requireAuth, requireAdmin, async (req, res) => {
  const VALID_TIERS = ['free', 'starter', 'pro'];
  const tier = VALID_TIERS.includes(req.body && req.body.tier) ? req.body.tier : 'pro';
  let maxUses = parseInt(req.body && req.body.maxUses, 10);
  if (!Number.isFinite(maxUses) || maxUses < 1) maxUses = 1;
  if (maxUses > 10000) maxUses = 10000;
  let expiresAt = null;
  const expiresInDays = parseInt(req.body && req.body.expiresInDays, 10);
  if (Number.isFinite(expiresInDays) && expiresInDays > 0) {
    expiresAt = new Date(Date.now() + expiresInDays * 86400000);
  }
  try {
    let code, inserted = false;
    for (let attempt = 0; attempt < 5 && !inserted; attempt++) {
      code = generateCodeString();
      const r = await pool.query(
        `INSERT INTO redemption_codes (code, tier, max_uses, expires_at, note)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (code) DO NOTHING RETURNING code`,
        [code, tier, maxUses, expiresAt, `Generated by ${req.username}`]
      );
      inserted = r.rows.length > 0;
    }
    if (!inserted) return res.status(500).json({ error: 'Could not generate a unique code, try again.' });
    res.json({ code, tier, maxUses, expiresAt });
  } catch (e) {
    console.error('generate-code error:', e.message);
    res.status(500).json({ error: 'Could not generate a code, try again.' });
  }
});

app.get('/api/admin/check', requireAuth, async (req, res) => {
  const r = await pool.query('SELECT is_admin FROM users WHERE username=$1', [req.username]);
  res.json({ isAdmin: !!(r.rows.length && r.rows[0].is_admin) });
});

// Every code, regardless of who generated it, with real usage details, not
// just the count, so an admin can see exactly who has redeemed what.
app.get('/api/admin/redemption-codes', requireAuth, requireAdmin, async (req, res) => {
  const codes = await pool.query('SELECT code, tier, max_uses, uses_count, expires_at, note, created_at FROM redemption_codes ORDER BY created_at DESC');
  const uses = await pool.query('SELECT code, username, redeemed_at FROM redemption_code_uses ORDER BY redeemed_at DESC');
  const usesByCode = {};
  uses.rows.forEach(u => { (usesByCode[u.code] = usesByCode[u.code] || []).push({ username: u.username, redeemedAt: u.redeemed_at }); });
  res.json({ codes: codes.rows.map(c => ({ ...c, uses: usesByCode[c.code] || [] })) });
});

// Deleting is the only admin action beyond visibility, on ON DELETE CASCADE
// this also removes that code's redemption_code_uses rows, it does not
// touch any plan_tier a user already received from redeeming it, revoking
// access retroactively is a separate, deliberate action this doesn't take.
app.delete('/api/admin/redemption-codes/:code', requireAuth, requireAdmin, async (req, res) => {
  const r = await pool.query('DELETE FROM redemption_codes WHERE code=$1 RETURNING code', [req.params.code]);
  if (!r.rows.length) return res.status(404).json({ error: 'That code does not exist.' });
  res.json({ ok: true });
});

app.post('/api/billing/checkout', requireAuth, async (req, res) => {
  if (!STRIPE_SECRET_KEY) return res.status(503).json({ error: 'Billing is not configured on this deployment.' });
  const tier = req.body && req.body.tier;
  const priceId = STRIPE_PRICE_IDS[tier];
  if (!priceId) return res.status(400).json({ error: `No price configured for tier "${tier}".` });
  try {
    const r = await pool.query('SELECT stripe_customer_id FROM users WHERE username=$1', [req.username]);
    const existingCustomerId = r.rows[0] && r.rows[0].stripe_customer_id;
    const params = {
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: req.username,
      metadata: { tier },
      success_url: `${APP_BASE_URL}/?billing=success`,
      cancel_url: `${APP_BASE_URL}/?billing=cancelled`,
    };
    if (existingCustomerId) params.customer = existingCustomerId;
    const result = await stripeRequest('POST', '/v1/checkout/sessions', params);
    if (!result.ok) return res.status(502).json({ error: (result.data.error && result.data.error.message) || 'Stripe rejected the checkout request.' });
    res.json({ url: result.data.url });
  } catch (e) {
    console.error('billing checkout error:', e.message);
    res.status(502).json({ error: 'Could not reach Stripe, try again in a moment.' });
  }
});

app.get('/api/billing/portal', requireAuth, async (req, res) => {
  if (!STRIPE_SECRET_KEY) return res.status(503).json({ error: 'Billing is not configured on this deployment.' });
  try {
    const r = await pool.query('SELECT stripe_customer_id FROM users WHERE username=$1', [req.username]);
    const customerId = r.rows[0] && r.rows[0].stripe_customer_id;
    if (!customerId) return res.status(404).json({ error: 'No billing account found, subscribe first.' });
    const result = await stripeRequest('POST', '/v1/billing_portal/sessions', { customer: customerId, return_url: `${APP_BASE_URL}/` });
    if (!result.ok) return res.status(502).json({ error: (result.data.error && result.data.error.message) || 'Stripe rejected the portal request.' });
    res.json({ url: result.data.url });
  } catch (e) {
    console.error('billing portal error:', e.message);
    res.status(502).json({ error: 'Could not reach Stripe, try again in a moment.' });
  }
});

// ------------------------------------------------------- creator incentive
// Rewards a strategy's ORIGINAL author, not the caller, every time someone
// else copies their published work, real running credit (creator_credit_cents),
// automatically applied as a genuine Stripe invoice credit for authors who've
// been through checkout, so this is an actual incentive to publish good
// strategies, not just a vanity counter. The caller only triggers this by
// copying; they never receive anything themselves.
const COPY_CREDIT_CENTS = 50; // $0.50 per copy of your published strategy
app.post('/api/community/credit-creator', requireAuth, async (req, res) => {
  const entryId = req.body && req.body.entryId;
  if (!entryId) return res.status(400).json({ error: 'entryId is required' });
  try {
    const row = await pool.query('SELECT value FROM kv_shared WHERE key=$1', ['community-index']);
    if (!row.rows.length) return res.json({ credited: false });
    let list;
    try { list = JSON.parse(row.rows[0].value); } catch (e) { return res.json({ credited: false }); }
    const entry = Array.isArray(list) ? list.find(e => e.id === entryId) : null;
    const ownerUsername = entry && entry.ownerUsername;
    // No real owner (a seed/demo entry) or copying your own strategy: nothing to credit.
    if (!ownerUsername || ownerUsername === req.username) return res.json({ credited: false });

    const updated = await pool.query(
      'UPDATE users SET creator_credit_cents = creator_credit_cents + $1 WHERE username=$2 RETURNING stripe_customer_id, creator_credit_cents',
      [COPY_CREDIT_CENTS, ownerUsername]
    );
    if (!updated.rows.length) return res.json({ credited: false });
    const { stripe_customer_id } = updated.rows[0];
    let appliedToStripe = false;
    if (stripe_customer_id && STRIPE_SECRET_KEY) {
      const result = await stripeRequest('POST', `/v1/customers/${stripe_customer_id}/balance_transactions`, {
        amount: -COPY_CREDIT_CENTS, // negative = credit, reduces what the creator owes on their next invoice
        currency: 'usd',
        description: `Strategy copy credit: "${(entry.name || 'a strategy').slice(0, 80)}" copied`,
      });
      appliedToStripe = result.ok;
    }
    res.json({ credited: true, appliedToStripe, ownerUsername });
  } catch (e) {
    console.error('credit-creator error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

// ------------------------------------------------------------------ auth
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'invalid username' });
    if (password.length < 6) return res.status(400).json({ error: 'password too short' });

    const exists = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (exists.rows.length) return res.status(409).json({ error: 'username taken' });

    const hash = await bcrypt.hash(password, 10);
    // The shared showcase demo account is deliberately seeded with example
    // strategies that illustrate the product (see handleDemoLogin() in the
    // frontend), more than the free tier allows. It's a known, intentional
    // fixture, not a real customer trying to exceed their limit, so it
    // registers on the 'pro' tier rather than the 'free' default every other
    // new signup gets.
    const initialTier = username === 'demo' ? 'pro' : 'free';
    await pool.query(
      'INSERT INTO users (username, password_hash, plan_tier, trial_ends_at) VALUES ($1, $2, $3, now() + INTERVAL \'30 days\')',
      [username, hash, initialTier]
    );

    const token = newToken();
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    res.json({ token, username });
  } catch (e) {
    console.error('register error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const r = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
    if (!r.rows.length) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = newToken();
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    res.json({ token, username });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = getToken(req);
  if (token) await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const username = await getUserFromToken(getToken(req));
  if (!username) return res.status(401).json({ error: 'not authenticated' });
  res.json({ username });
});

// -------------------------------------------------------------------- kv
// Mirrors window.storage: GET/PUT/DELETE a key, optionally shared across all users.
app.get('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  try {
    if (shared) {
      const r = await pool.query('SELECT value FROM kv_shared WHERE key = $1', [key]);
      if (!r.rows.length) return res.status(404).json({ error: 'not found' });
      return res.json({ key, value: r.rows[0].value, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    const r = await pool.query('SELECT value FROM kv_personal WHERE username = $1 AND key = $2', [username, key]);
    if (!r.rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ key, value: r.rows[0].value, shared: false });
  } catch (e) {
    console.error('kv get error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.put('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : JSON.stringify(req.body.value);
  if (value === undefined) return res.status(400).json({ error: 'missing value' });
  try {
    if (shared) {
      // Shared writes still require SOME authenticated user (prevents anonymous
      // abuse), and writes to another user's own "user:<username>" profile
      // blob are blocked outright, only that user may modify their own record.
      const username = await getUserFromToken(getToken(req));
      if (!username) return res.status(401).json({ error: 'not authenticated' });
      if (key.startsWith('user:') && key !== 'user:' + username) {
        return res.status(403).json({ error: "cannot modify another user's profile" });
      }
      if (key === 'user:' + username) {
        const gateResult = await checkFreeTierStrategyLimit(username, key, value);
        if (gateResult) return res.status(402).json(gateResult);
      }
      await pool.query(
        `INSERT INTO kv_shared (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [key, value]
      );
      return res.json({ key, value, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    await pool.query(
      `INSERT INTO kv_personal (username, key, value, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (username, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [username, key, value]
    );
    res.json({ key, value, shared: false });
  } catch (e) {
    console.error('kv put error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.delete('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  try {
    if (shared) {
      const username = await getUserFromToken(getToken(req));
      if (!username) return res.status(401).json({ error: 'not authenticated' });
      if (key.startsWith('user:') && key !== 'user:' + username) {
        return res.status(403).json({ error: "cannot modify another user's profile" });
      }
      await pool.query('DELETE FROM kv_shared WHERE key = $1', [key]);
      return res.json({ key, deleted: true, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    await pool.query('DELETE FROM kv_personal WHERE username = $1 AND key = $2', [username, key]);
    res.json({ key, deleted: true, shared: false });
  } catch (e) {
    console.error('kv delete error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

// ------------------------------------------------------------ atomic list ops
// Fixes a real "lost update" race: two different users publishing to the
// community (or joining the waitlist, or following someone) at nearly the
// same moment can both read the same shared list, then each write their own
// modified copy back, the second write silently erases the first user's
// change. SELECT ... FOR UPDATE takes a row-level lock inside a transaction,
// so the read-modify-write happens atomically in the database, not as two
// separate round trips from whichever clients happen to be racing.
app.post('/api/kv-atomic/:key', requireAuth, async (req, res) => {
  const key = req.params.key;
  const { op, entry, id, patch, value: memberValue, field, by, path, uniqueField, uniqueValue } = req.body || {};
  const validOps = ['prepend', 'removeById', 'mergeById', 'toggleMember', 'incrementEntryField', 'setEntryNestedField', 'deleteEntryNestedField', 'toggleEntryArrayMember', 'pushToEntryArray', 'appendUnique', 'toggleFollowPair'];
  if (!validOps.includes(op)) return res.status(400).json({ error: 'unknown op' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query('SELECT value FROM kv_shared WHERE key = $1 FOR UPDATE', [key]);
    let list = [];
    if (r.rows.length) {
      try { list = JSON.parse(r.rows[0].value); if (!Array.isArray(list)) list = []; } catch (e) { list = []; }
    }
    if (op === 'prepend') {
      if (entry === undefined) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'entry required' }); }
      list.unshift(entry);
    } else if (op === 'removeById') {
      if (!id) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id required' }); }
      list = list.filter(x => x && x.id !== id);
    } else if (op === 'mergeById') {
      if (!id || typeof patch !== 'object') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id and patch required' }); }
      list = list.map(x => (x && x.id === id) ? Object.assign({}, x, patch) : x);
    } else if (op === 'toggleMember') {
      if (memberValue === undefined) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'value required' }); }
      const idx = list.indexOf(memberValue);
      if (idx >= 0) list.splice(idx, 1); else list.push(memberValue);
    } else if (op === 'incrementEntryField') {
      // Reads the CURRENT value from the locked row (not a client-supplied
      // number), the only way to make "increment" safe under concurrency.
      if (!id || !field) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id and field required' }); }
      const target = list.find(x => x && x.id === id);
      if (target) target[field] = (Number(target[field]) || 0) + (Number(by) || 1);
    } else if (op === 'setEntryNestedField') {
      if (!id || !Array.isArray(path) || path.length === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id and path required' }); }
      const target = list.find(x => x && x.id === id);
      if (target) {
        let node = target;
        for (let i = 0; i < path.length - 1; i++) { node[path[i]] = node[path[i]] || {}; node = node[path[i]]; }
        node[path[path.length - 1]] = req.body.value;
      }
    } else if (op === 'deleteEntryNestedField') {
      if (!id || !Array.isArray(path) || path.length === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id and path required' }); }
      const target = list.find(x => x && x.id === id);
      if (target) {
        let node = target;
        for (let i = 0; i < path.length - 1; i++) { if (!node[path[i]]) { node = null; break; } node = node[path[i]]; }
        if (node) delete node[path[path.length - 1]];
      }
    } else if (op === 'toggleEntryArrayMember') {
      if (!id || !field || memberValue === undefined) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id, field and value required' }); }
      const target = list.find(x => x && x.id === id);
      if (target) {
        target[field] = target[field] || [];
        const idx = target[field].indexOf(memberValue);
        if (idx >= 0) target[field].splice(idx, 1); else target[field].push(memberValue);
      }
    } else if (op === 'pushToEntryArray') {
      if (!id || !field || req.body.value === undefined) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'id, field and value required' }); }
      const target = list.find(x => x && x.id === id);
      if (target) { target[field] = target[field] || []; target[field].push(req.body.value); }
    } else if (op === 'appendUnique') {
      // Atomically checks-then-inserts, so two near-simultaneous joins with
      // the same uniqueValue (e.g. waitlist identifier) can't both slip past
      // a client-side dedup check that was only ever checking stale data.
      if (!uniqueField || uniqueValue === undefined || entry === undefined) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'uniqueField, uniqueValue and entry required' }); }
      const exists = list.some(x => x && x[uniqueField] === uniqueValue);
      if (!exists) list.push(entry);
    } else if (op === 'toggleFollowPair') {
      const { follower, following } = req.body || {};
      if (!follower || !following) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'follower and following required' }); }
      const idx = list.findIndex(x => x && x.follower === follower && x.following === following);
      if (idx >= 0) list.splice(idx, 1);
      else list.push({ follower, following, ts: Date.now() });
    }
    const newValue = JSON.stringify(list);
    if (r.rows.length) {
      await client.query('UPDATE kv_shared SET value = $1, updated_at = now() WHERE key = $2', [newValue, key]);
    } else {
      await client.query('INSERT INTO kv_shared (key, value, updated_at) VALUES ($1, $2, now())', [key, newValue]);
    }
    await client.query('COMMIT');
    res.json({ key, value: newValue, shared: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('kv-atomic error:', e.message);
    res.status(500).json({ error: 'server error' });
  } finally {
    client.release();
  }
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ----------------------------------------------------- broker: Alpaca (real)
// This is a genuine integration with Alpaca's real Trading API, defaults to
// their paper-trading environment (https://paper-api.alpaca.markets), which
// is free, uses simulated money, and is explicitly designed by Alpaca for
// exactly this kind of algo-trading development use case. Nothing here
// places real-money trades unless someone deliberately points baseUrl at
// Alpaca's live API domain with live credentials, which the app's UI never does.
app.get('/api/broker/alpaca/positions', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    if (!r.rows.length) return res.status(404).json({ error: 'Alpaca is not connected for this account.' });
    const { api_key_id, api_secret_enc, base_url } = r.rows[0];
    const apiSecretKey = decryptSecret(api_secret_enc);
    const alpacaRes = await alpacaRequest(base_url, api_key_id, apiSecretKey, '/v2/positions');
    if (!alpacaRes.ok) return res.status(502).json({ error: 'Could not fetch positions from Alpaca.' });
    const positions = await alpacaRes.json();
    res.json({ positions });
  } catch (e) {
    console.error('alpaca positions error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/broker/alpaca/order', requireAuth, async (req, res) => {
  const { symbol, qty, side, type, time_in_force } = req.body;
  if (!symbol || !qty || !side) return res.status(400).json({ error: 'symbol, qty and side are required' });
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    if (!r.rows.length) return res.status(404).json({ error: 'Alpaca is not connected for this account.' });
    const { api_key_id, api_secret_enc, base_url } = r.rows[0];
    const apiSecretKey = decryptSecret(api_secret_enc);
    const orderBody = {
      symbol: String(symbol).toUpperCase(),
      qty: String(qty),
      side: side === 'sell' ? 'sell' : 'buy',
      type: type || 'market',
      time_in_force: time_in_force || 'day',
    };
    const alpacaRes = await alpacaRequest(base_url, api_key_id, apiSecretKey, '/v2/orders', {
      method: 'POST', body: JSON.stringify(orderBody),
    });
    const data = await alpacaRes.json().catch(() => ({}));
    if (!alpacaRes.ok) return res.status(400).json({ error: data.message || 'Alpaca rejected this order.', detail: data });
    res.json({ order: data });
  } catch (e) {
    console.error('alpaca order error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

// =========================================================================
// GENERIC BROKER ADAPTER FRAMEWORK
// =========================================================================
// Previously, adding a broker meant writing a full new set of hardcoded
// connect/account/disconnect/test-order routes (see the original Alpaca and
// eToro implementations this replaces). That meant every new broker was a
// copy-pasted block of route handlers with broker-specific field names and
// error strings baked directly into Express routes, and the server had no
// single place that answered "which brokers exist and what do they need."
//
// This registry is that single place. Each entry implements a small,
// consistent contract; the four /api/broker/:brokerId/* routes below are
// completely generic; they contain zero broker-specific logic and dispatch
// entirely through this registry. Adding a new broker means adding one
// entry here, not new routes. Alpaca and eToro's behavior is unchanged;
// this is a structural refactor, not a behavior change, verified against
// the same tests that already covered both.
//
// Adapter contract (fields an entry may implement):
//   id, name                     identity
//   requiredFields                array of req.body field names needed to connect,
//                                 used for the generic "missing fields" validation
//                                 and to tell the frontend what form fields to show
//   supportsAutomatedExecution    whether the live-execution scheduler can use this
//                                 broker at all (real bar data + real order placement)
//   connect(body)                 -> { ok, status?, error?, credsForStorage?, accountSummary? }
//                                 credsForStorage: { primary, secretPlain } to persist
//   fetchAccount(creds)           creds = { primary, secretPlain } from storage
//                                 -> { ok, status?, error?, accountSummary? }
//   placeTestOrder(creds)         -> { ok, status?, error?, result? }
//   onDisconnect(username)        optional cleanup beyond deleting the credentials row
//   isSymbolTradable(symbol)      only required if supportsAutomatedExecution
//   getBars/placeOrder/getPosition/closePosition   only required if supportsAutomatedExecution;
//                                 same signatures the execution engine already expects

const BrokerAdapters = {};

BrokerAdapters.alpaca = {
  id: 'alpaca',
  name: 'Alpaca',
  requiredFields: ['apiKeyId', 'apiSecretKey'],
  supportsAutomatedExecution: true,

  async connect(body) {
    const { apiKeyId, apiSecretKey } = body;
    const targetBaseUrl = ALPACA_BASE_URL_DEFAULT.replace(/\/$/, '');
    const res = await alpacaRequest(targetBaseUrl, apiKeyId, apiSecretKey, '/v2/account');
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: 400, error: 'Alpaca rejected these credentials, check your API Key ID and Secret Key.' };
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, status: 502, error: 'Alpaca returned an unexpected error.', detail: text.slice(0, 300) };
    }
    const account = await res.json();
    return {
      ok: true,
      credsForStorage: { primary: apiKeyId, secretPlain: apiSecretKey, baseUrl: targetBaseUrl },
      accountSummary: {
        accountNumber: account.account_number, status: account.status, currency: account.currency,
        cash: account.cash, buyingPower: account.buying_power, portfolioValue: account.portfolio_value,
        equity: account.equity, tradingBlocked: account.trading_blocked,
      },
    };
  },

  async fetchAccount(creds) {
    const res = await alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, '/v2/account');
    if (!res.ok) return { ok: false, status: 502, error: 'Could not fetch account from Alpaca.' };
    const account = await res.json();
    return {
      ok: true,
      accountSummary: {
        accountNumber: account.account_number, status: account.status, currency: account.currency,
        cash: account.cash, buyingPower: account.buying_power, portfolioValue: account.portfolio_value,
        equity: account.equity, tradingBlocked: account.trading_blocked,
      },
    };
  },

  async placeTestOrder(creds) {
    const orderBody = { symbol: 'AAPL', qty: '1', side: 'buy', type: 'market', time_in_force: 'day' };
    const res = await alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, '/v2/orders', { method: 'POST', body: JSON.stringify(orderBody) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, status: 400, error: data.message || 'Alpaca rejected this order.', detail: data };
    return { ok: true, result: { order: data } };
  },

  isSymbolTradable(symbol) { return isAlpacaTradable(symbol); },
  async getBars(creds, symbol, timeframe, limit) { return alpacaGetBars(creds.baseUrl, creds.primary, creds.secretPlain, symbol, timeframe, limit); },
  async placeOrder(creds, orderSpec) {
    return alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, '/v2/orders', { method: 'POST', body: JSON.stringify(orderSpec) });
  },
  async getPosition(creds, symbol) {
    return alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, `/v2/positions/${encodeURIComponent(symbol)}`);
  },
  async closePosition(creds, symbol) {
    return alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, `/v2/positions/${encodeURIComponent(symbol)}`, { method: 'DELETE' });
  },
  // Finds the real fill price of whichever order actually closed the
  // position (the bracket's take-profit or stop-loss leg, or a manual
  // close), so the trade log can show a genuine exit price rather than
  // leaving it blank or guessing at the current market price.
  async findRecentExitPrice(creds, symbol, excludeOrderId) {
    try {
      const res = await alpacaRequest(creds.baseUrl, creds.primary, creds.secretPlain, `/v2/orders?symbols=${encodeURIComponent(symbol)}&status=closed&limit=10&direction=desc`);
      if (!res.ok) return null;
      const orders = await res.json();
      const filled = orders.find(o => o.id !== excludeOrderId && o.status === 'filled' && o.filled_avg_price);
      return filled ? parseFloat(filled.filled_avg_price) : null;
    } catch (e) { return null; }
  },
};

BrokerAdapters.etoro = {
  id: 'etoro',
  name: 'eToro',
  requiredFields: ['apiKey', 'userKey'],
  supportsAutomatedExecution: false, // see note above BrokerAdapters: no real intraday bar history available

  async connect(body) {
    const { apiKey, userKey } = body;
    const targetBaseUrl = ETORO_BASE_URL_DEFAULT.replace(/\/$/, '');
    const res = await etoroRequest(targetBaseUrl, apiKey, userKey, '/api/v1/trading/info/demo/portfolio');
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: 400, error: 'eToro rejected these credentials, check your API key and user key.' };
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, status: 502, error: 'eToro returned an unexpected error.', detail: text.slice(0, 300) };
    }
    const portfolio = await res.json();
    return {
      ok: true,
      credsForStorage: { primary: apiKey, secretPlain: userKey, baseUrl: targetBaseUrl },
      accountSummary: { credit: portfolio.credit, totalPositionsCount: (portfolio.positions || []).length },
    };
  },

  async fetchAccount(creds) {
    const res = await etoroRequest(creds.baseUrl, creds.primary, creds.secretPlain, '/api/v1/trading/info/demo/portfolio');
    if (!res.ok) return { ok: false, status: 502, error: 'Could not fetch account from eToro.' };
    const portfolio = await res.json();
    return { ok: true, accountSummary: { credit: portfolio.credit, totalPositionsCount: (portfolio.positions || []).length } };
  },

  async placeTestOrder(creds) {
    // AAPL's eToro instrumentId is a well-known, stable public constant (1001),
    // used only for this one hardcoded connectivity-proof order.
    const res = await etoroRequest(creds.baseUrl, creds.primary, creds.secretPlain, '/api/v1/trading/execution/demo/market-open-orders/by-amount', {
      method: 'POST', body: JSON.stringify({ InstrumentID: 1001, IsBuy: true, Leverage: 1, Amount: 100 }),
    });
    if (!res.ok) { const errBody = await res.json().catch(() => ({})); return { ok: false, status: 502, error: errBody.message || 'eToro rejected the test order.' }; }
    const order = await res.json();
    return { ok: true, result: { order } };
  },

  async onDisconnect(username) {
    await pool.query(`UPDATE live_deployments SET status='closed', closed_at=now() WHERE username=$1 AND broker='etoro' AND status IN ('watching','open')`, [username]);
  },
};

function getBrokerAdapter(brokerId) { return BrokerAdapters[brokerId] || null; }

// ---------------------------------------------------------- generic routes
// These four routes are the entire broker-integration surface now. There is
// no broker-specific code here at all; everything broker-specific lives in
// BrokerAdapters above. A new real broker means adding one adapter entry;
// these routes never change.
app.post('/api/broker/:brokerId/connect', requireAuth, async (req, res) => {
  const adapter = getBrokerAdapter(req.params.brokerId);
  if (!adapter) return res.status(404).json({ error: `Unknown broker "${req.params.brokerId}".` });
  const missing = (adapter.requiredFields || []).filter(f => !req.body || !req.body[f]);
  if (missing.length) return res.status(400).json({ error: `${missing.join(' and ')} ${missing.length > 1 ? 'are' : 'is'} required` });
  try {
    const result = await adapter.connect(req.body);
    if (!result.ok) return res.status(result.status || 502).json({ error: result.error, detail: result.detail });
    const { primary, secretPlain, baseUrl } = result.credsForStorage;
    const encSecret = encryptSecret(secretPlain);
    await pool.query(
      `INSERT INTO broker_credentials (username, broker, api_key_id, api_secret_enc, base_url, connected_at)
       VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (username, broker) DO UPDATE SET api_key_id = EXCLUDED.api_key_id, api_secret_enc = EXCLUDED.api_secret_enc, base_url = EXCLUDED.base_url, connected_at = now()`,
      [req.username, adapter.id, primary, encSecret, baseUrl]
    );
    res.json({ connected: true, account: result.accountSummary, portfolio: result.accountSummary });
  } catch (e) {
    console.error(`${adapter.id} connect error:`, e.message);
    res.status(502).json({ error: `Could not reach ${adapter.name}, check your network or try again.` });
  }
});

app.get('/api/broker/:brokerId/account', requireAuth, async (req, res) => {
  const adapter = getBrokerAdapter(req.params.brokerId);
  if (!adapter) return res.status(404).json({ error: `Unknown broker "${req.params.brokerId}".` });
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, adapter.id]);
    if (!r.rows.length) return res.status(404).json({ error: `${adapter.name} is not connected for this account.` });
    const creds = { primary: r.rows[0].api_key_id, secretPlain: decryptSecret(r.rows[0].api_secret_enc), baseUrl: r.rows[0].base_url };
    const result = await adapter.fetchAccount(creds);
    if (!result.ok) return res.status(result.status || 502).json({ error: result.error });
    res.json({ account: result.accountSummary, portfolio: result.accountSummary });
  } catch (e) {
    console.error(`${adapter.id} account error:`, e.message);
    res.status(500).json({ error: 'server error' });
  }
});

// A genuine round-trip check, not a cached flag: actually calls the broker
// right now and classifies the real response time, since "connected" from
// the credentials table alone doesn't tell you whether the broker is
// actually reachable at this moment.
app.get('/api/broker/:brokerId/health', requireAuth, async (req, res) => {
  const adapter = getBrokerAdapter(req.params.brokerId);
  if (!adapter) return res.status(404).json({ error: `Unknown broker "${req.params.brokerId}".` });
  const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, adapter.id]);
  if (!r.rows.length) return res.json({ status: 'disconnected', latencyMs: null });
  const started = Date.now();
  try {
    // A decryption failure here (credential encrypted under a since-
    // rotated key, corrupted data) is a real, if rare, possibility and
    // must be a "disconnected" result for this one check, not a crash.
    const creds = { primary: r.rows[0].api_key_id, secretPlain: decryptSecret(r.rows[0].api_secret_enc), baseUrl: r.rows[0].base_url };
    const result = await adapter.fetchAccount(creds);
    const latencyMs = Date.now() - started;
    if (!result.ok) return res.json({ status: 'disconnected', latencyMs });
    res.json({ status: latencyMs > 3000 ? 'lagging' : 'connected', latencyMs, tradingBlocked: !!(result.accountSummary && result.accountSummary.tradingBlocked) });
  } catch (e) {
    res.json({ status: 'disconnected', latencyMs: Date.now() - started });
  }
});

app.post('/api/broker/:brokerId/disconnect', requireAuth, async (req, res) => {
  const adapter = getBrokerAdapter(req.params.brokerId);
  if (!adapter) return res.status(404).json({ error: `Unknown broker "${req.params.brokerId}".` });
  try {
    await pool.query('DELETE FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, adapter.id]);
    if (adapter.onDisconnect) await adapter.onDisconnect(req.username);
    res.json({ ok: true, disconnected: true });
  } catch (e) {
    console.error(`${adapter.id} disconnect error:`, e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/broker/:brokerId/test-order', requireAuth, async (req, res) => {
  const adapter = getBrokerAdapter(req.params.brokerId);
  if (!adapter) return res.status(404).json({ error: `Unknown broker "${req.params.brokerId}".` });
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, adapter.id]);
    if (!r.rows.length) return res.status(404).json({ error: `${adapter.name} is not connected for this account.` });
    const creds = { primary: r.rows[0].api_key_id, secretPlain: decryptSecret(r.rows[0].api_secret_enc), baseUrl: r.rows[0].base_url };
    const result = await adapter.placeTestOrder(creds);
    if (!result.ok) return res.status(result.status || 502).json({ error: result.error, detail: result.detail });
    res.json(Object.assign({ ok: true }, result.result));
  } catch (e) {
    console.error(`${adapter.id} test-order error:`, e.message);
    res.status(502).json({ error: `Could not reach ${adapter.name} to place the test order.` });
  }
});



// SPA fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not found' });
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// --------------------------------------------------------- schema + start
// Applies schema.sql on every boot. Every statement in it is idempotent
// (CREATE TABLE/INDEX IF NOT EXISTS), so this is safe to run on first deploy
// AND on every restart afterward, no manual database setup step required.
async function initSchema() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
  console.log('Database schema verified.');
}

async function start() {
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await initSchema();
      break;
    } catch (e) {
      if (attempt === maxAttempts) {
        console.error('FATAL: could not apply database schema after', maxAttempts, 'attempts:', e.message);
        process.exit(1);
      }
      console.log(`Database not ready yet (attempt ${attempt}/${maxAttempts}), retrying in 3s...`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => {
    console.log(`VaticTrader server listening on port ${PORT}`);
  });
}

start();
