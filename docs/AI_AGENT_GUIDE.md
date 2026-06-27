# AI Agent Deployment Guide

A comprehensive guide for deploying and operating a Beignet Lightning node for AI agent workflows.

## Prerequisites

- **Node.js** 18+ (LTS recommended)
- **npm** 9+
- Bitcoin on-chain funds for channel opening
- Electrum server access (mainnet default: `fulcrum.bitkit.blocktank.to:8900`)

## Import Paths

| Path | Contents |
|------|----------|
| `beignet` | On-chain wallet only (`Wallet`, `generateMnemonic`) |
| `beignet/cli` | `BeignetNode`, `startDaemon`, `isRetryableError`, errors (recommended for agents) |
| `beignet/lightning` | Low-level protocol modules (`LightningNode`, `Channel`, etc.) |

## Quick Start

Get from zero to payment-ready in under 30 lines of TypeScript:

```typescript
import { BeignetNode } from 'beignet/cli';

// 1. Create a node (generates mnemonic if none provided)
const node = await BeignetNode.create({
  network: 'mainnet',
  alias: 'my-agent',
  autoReconnect: true,
});

// 2. Get on-chain address and fund it
const address = await node.getNewAddress();
console.log('Fund this address:', address);

// 3. Wait for on-chain funds, then connect + open a channel in one call
await node.connectAndOpenChannel(peerPubkey, peerHost, peerPort, 1_000_000);

// 4. Wait for channel to become active
await node.waitForChannelReady(channelId);

// 5. Pay an invoice
const result = await node.payInvoiceSafe(bolt11Invoice);
console.log('Payment:', result.status); // 'COMPLETED' or 'FAILED'
```

## HTTP Daemon

For framework integrations (LangChain, CrewAI, etc.), use the HTTP daemon:

```typescript
import { startDaemon } from 'beignet/cli';

const { server, node } = await startDaemon({
  network: 'mainnet',
  daemonPort: 2112,
  apiToken: process.env.BEIGNET_API_TOKEN,
  cors: true,
  rateLimit: { maxRequests: 100, windowMs: 60_000 }, // Optional: protect against runaway loops
});
```

All endpoints use JSON. Example:

```bash
# Pay an invoice
curl -X POST http://localhost:2112/invoice/pay-safe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"bolt11": "lnbc..."}'

# Check payment status
curl http://localhost:2112/payment?paymentHash=abc123 \
  -H "Authorization: Bearer $TOKEN"
```

## Channel Strategy

### When to open channels
Use the **Liquidity Advisor** to make informed decisions:

```typescript
const snapshot = node.getLiquiditySnapshot();
for (const rec of snapshot.recommendations) {
  console.log(`[${rec.priority}] ${rec.type}: ${rec.reason}`);
}
```

### Which node to connect to
Use **Channel Suggestions** for graph-aware recommendations:

```typescript
const suggestions = node.getChannelSuggestions(3);
for (const s of suggestions) {
  console.log(`${s.alias || s.nodeId} (score: ${s.score}): ${s.reason}`);
}
```

### Timing channel opens
Use the **Fee Advisor** to avoid overpaying on-chain fees:

```typescript
const fees = node.getFeeSnapshot();
if (fees?.recommendation === 'OPEN_NOW') {
  console.log('Good time to open a channel');
} else if (fees?.recommendation === 'WAIT') {
  console.log('Fees are high, consider waiting');
}
```

## Liquidity Management

### Check capacity before paying
```typescript
const check = node.canSend(50000); // 50k sats
if (!check.canSend) {
  console.log('Insufficient capacity. Available:', check.availableSats, 'sats');
}
```

### Monitor liquidity health
```typescript
const snapshot = node.getLiquiditySnapshot();
console.log('Outbound:', snapshot.outboundLiquidityPct + '%');
console.log('Inbound:', snapshot.inboundLiquidityPct + '%');
```

## Monitoring

### Health checks
```typescript
const health = node.getHealth();
// health.status: 'ready' | 'syncing' | 'degraded'
```

### Prometheus metrics

Export metrics for monitoring dashboards and alerting:

```typescript
const metrics = node.getMetrics();
// Returns Prometheus text exposition format (text/plain)
```

Via HTTP (auth-exempt):
```bash
curl http://localhost:2112/metrics
# HELP beignet_channels_total Number of channels by state
# TYPE beignet_channels_total gauge
beignet_channels_total{state="NORMAL"} 2
beignet_balance_sats{type="lightning"} 50000
beignet_peers_connected 3
beignet_uptime_seconds 3600
...
```

Via CLI:
```bash
beignet metrics
```

Key metrics: `beignet_channels_total`, `beignet_payments_total`, `beignet_balance_sats`, `beignet_electrum_connected`, `beignet_peers_connected`, `beignet_uptime_seconds`, `beignet_block_height`, `beignet_payment_success_rate`, `beignet_fees_paid_sats`, `beignet_graph_nodes`, `beignet_graph_channels`.

### Event-driven monitoring
```typescript
// Via EventEmitter
node.on('payment:received', (info) => {
  console.log('Received', info.amountSats, 'sats');
});

// Via SSE (HTTP daemon)
// GET /events (Server-Sent Events)

// Via Webhooks (HTTP daemon) — persistent across restarts
// POST /webhooks/register { "url": "https://...", "events": ["payment:received"] }
```

### Action log
Query what happened while you were away:
```typescript
const logs = node.getActionLog({ category: 'payment', since: Date.now() - 3600000 });
for (const log of logs) {
  console.log(`[${log.action}] ${JSON.stringify(log.data)}`);
}
```

## Pre-Flight Payment Validation

Before sending any payment, validate it first. `validatePayment()` checks everything in one call — invoice validity, expiry, amount limits, spending limits, channel capacity, and route availability:

```typescript
const validation = node.validatePayment(bolt11);

if (validation.status === 'FAIL') {
  console.log('Do not send:', validation.summary);
  // Individual check details:
  for (const check of validation.checks) {
    if (check.status === 'FAIL') console.log(`  [FAIL] ${check.name}: ${check.message}`);
  }
  return;
}

if (validation.status === 'WARN') {
  console.log('Proceed with caution:', validation.summary);
}

// All clear — send it
const result = await node.payInvoiceSafe(bolt11);
```

Via HTTP:
```bash
curl -X POST http://localhost:2112/invoice/validate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"bolt11": "lnbc..."}'
# Returns: { ok: true, result: { status: "OK"|"WARN"|"FAIL", summary: "...", checks: [...] } }
```

**Checks performed:** `INVOICE_DECODE`, `AMOUNT`, `EXPIRY`, `MAX_PAYMENT`, `DAILY_LIMIT`, `CAPACITY`, `ROUTE`, `SERVICE_STATE`, `CHANNELS`.

## Safety Rails

Protect your agent from accidental overspend:

```typescript
const node = await BeignetNode.create({
  maxPaymentSats: 100_000,       // Reject any single payment over 100k sats
  dailySpendLimitSats: 500_000,  // Cap total daily spend at 500k sats
});

// This will throw SPENDING_LIMIT_EXCEEDED if the invoice is over 100k sats:
await node.payInvoice(bigInvoice);

// Or use validatePayment() to check before sending:
const check = node.validatePayment(bigInvoice);
// check.status === 'FAIL', check.summary includes "exceeds per-payment limit"
```

## Error Handling

### Decision tree
```
Payment failed?
├── Is error retryable? (check isRetryableError(error))
│   ├── Yes → Retry with backoff
│   └── No → Report permanent failure
├── Is it a routing error? (error.code === 'NO_ROUTE')
│   └── Check liquidity, try different amount, or open new channel
├── Is it a timeout? (error.code === 'PAYMENT_TIMEOUT')
│   └── Check channel health, try again later
└── Is it a capacity issue? (canSend returns false)
    └── Open a new channel or wait for inbound payment
```

### Safe payment pattern
```typescript
// payInvoiceSafe() NEVER throws — it always returns a PaymentInfo object.
// On failure, result.status === 'FAILED' and result.failureDescription contains
// a machine-parseable error code like [INSUFFICIENT_BALANCE], [INVOICE_EXPIRED], etc.
const result = await node.payInvoiceSafe(bolt11);
if (result.status === 'COMPLETED') {
  // Cryptographically verify the proof
  // Get a standalone proof bundle for record-keeping
  const proof = node.getPaymentProof(result.paymentHash);
  // { paymentHash, preimage, amountSats, completedAt, invoice?, hopCount?, feeSats? }

  // Verify the proof cryptographically (SHA256(preimage) === paymentHash)
  const verification = node.verifyPaymentProof(result.paymentHash);
  console.log('Valid proof:', verification.valid);
} else {
  // result.status === 'FAILED'
  console.log('Failure:', result.failureDescription);
  // Parse the error code from failureDescription for programmatic handling:
  // e.g. "[INSUFFICIENT_BALANCE] Not enough outbound capacity"
}
```

### Payment queuing
For batch payments with concurrency control. The queue is **persistent** — queued payments survive daemon restarts and crashes. Payments that were mid-dispatch at crash time are automatically reset to `queued` on recovery.

```typescript
const queue = node.enqueuePayment(bolt11, 1); // priority 1 (highest)
console.log('Queued:', queue.id);

// Monitor progress
const items = node.listQueue();
```

## Keysend (Spontaneous Payments)

Send payments without an invoice using keysend (bLIP-0003). Critical for AI agents making spontaneous payments:

```typescript
// Safe pattern — never throws
const result = await node.sendKeysendSafe(
  '03...destination_pubkey',  // recipient node pubkey
  1000,                        // amount in sats
  60_000,                      // timeout in ms (default: 60s)
  50,                          // max fee in sats (optional)
  { purpose: 'tip' },          // metadata (optional)
);

if (result.status === 'COMPLETED') {
  console.log('Keysend sent! Preimage:', result.preimage);
} else {
  console.log('Failed:', result.failureDescription);
}

// Throwing pattern — for try/catch workflows
const payment = await node.sendKeysend('03...pubkey', 1000);
```

Via HTTP:
```bash
# Safe (returns FAILED status, never errors)
curl -X POST http://localhost:2112/keysend/safe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"pubkey": "03...", "amountSats": 1000}'

# Throwing (returns error on failure)
curl -X POST http://localhost:2112/keysend \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"pubkey": "03...", "amountSats": 1000, "maxFeeSats": 50}'
```

## Channel Health

Monitor individual channel health for proactive liquidity management:

```typescript
const health = node.getChannelHealth(channelId);
// IChannelHealth {
//   channelId, state, localBalancePct, remoteBalancePct,
//   htlcCount, maxHtlcs, capacitySats, warnings
// }

// Warnings indicate actionable issues:
// - LOW_OUTBOUND_LIQUIDITY: local balance < 10% — can't send
// - LOW_INBOUND_LIQUIDITY: remote balance < 10% — can't receive
// - HTLC_SLOTS_NEARLY_FULL: active HTLCs > 80% of max
// - AWAITING_REESTABLISH: channel pending reconnection

for (const warning of health.warnings) {
  console.log('Warning:', warning);
}
```

Via HTTP:
```bash
curl "http://localhost:2112/channel/health?channelId=abc123..." \
  -H "Authorization: Bearer $TOKEN"
```

## Payment Lifecycle

### Timeout behavior

`payInvoice()` calls `failPayment()` internally on timeout, but the HTLC may still settle after the timeout fires. Always check `getPayment(hash)` before retrying to avoid duplicate payments.

### Duplicate payment protection

Retrying the same invoice while the payment is still `PENDING` will throw `DUPLICATE_PAYMENT`. The correct pattern: check the payment status first, use `waitForPayment()` if still pending.

### Method comparison

| Method | Blocks? | Throws on failure? | Best for |
|--------|---------|-------------------|----------|
| `payInvoice()` | Yes | Yes | Simple scripts |
| `payInvoiceSafe()` | Yes | No (returns `FAILED`) | Agent loops |
| `sendPaymentAsync()` | No | No | Fire-and-forget |
| `payInvoiceWithRetry()` | Yes | No | Production agents |

### Recommended safe pattern

```typescript
import { BeignetNode, isRetryableError } from 'beignet/cli';

async function safePay(node: BeignetNode, bolt11: string): Promise<void> {
  // 1. Check if we already attempted this payment
  const decoded = node.decodeInvoice(bolt11);
  const existing = node.getPayment(decoded.paymentHash);
  if (existing?.status === 'COMPLETED') return; // Already paid
  if (existing?.status === 'PENDING') {
    // Wait for in-flight payment instead of creating a duplicate
    await node.waitForPayment(decoded.paymentHash);
    return;
  }

  // 2. Use payInvoiceWithRetry for automatic backoff
  const result = await node.payInvoiceWithRetry(bolt11, {
    maxRetries: 3,
    backoffMs: 2000,
    maxFeeSats: 100,
  });
  console.log('Status:', result.status, 'Attempts:', result.attempts);
}
```

## Payment Retry with Backoff

Instead of implementing your own retry loop, use the built-in retry method:

```typescript
// Retries up to 3 times with exponential backoff (2s, 4s, 8s).
// Automatically stops retrying if drain mode is enabled (SERVICE_DRAINING).
const result = await node.payInvoiceWithRetry(bolt11);
console.log('Attempts:', result.attempts, 'Status:', result.status);

// Custom retry options
const result = await node.payInvoiceWithRetry(bolt11, {
  maxRetries: 5,
  backoffMs: 1000,     // 1s base delay
  maxFeeSats: 100,     // cap routing fees
});

// Monitor retries via events
node.on('payment:retry', (data) => {
  console.log(`Retry ${data.attempt}/${data.maxRetries} in ${data.nextRetryMs}ms: ${data.error}`);
});
```

Via HTTP:
```bash
curl -X POST http://localhost:2112/invoice/pay-retry \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"bolt11": "lnbc...", "maxRetries": 3, "backoffMs": 2000}'
```

Via CLI:
```bash
beignet invoice pay-retry lnbc... --max-retries 5 --backoff-ms 1000 --max-fee 100
```

## Peer Connection Timeout

By default, `connectPeer()` times out after 15 seconds to prevent hangs on unreachable hosts:

```typescript
const node = await BeignetNode.create({
  network: 'mainnet',
  connectTimeoutMs: 10_000, // 10 second timeout (default: 15s)
});

// Throws CONNECT_TIMEOUT if the peer is unreachable within the timeout
await node.connectPeer(pubkey, host, port);
```

Via environment variable:
```bash
export BEIGNET_CONNECT_TIMEOUT_MS=10000
```

## Filtering Payments by Metadata

Agents can store request IDs in payment metadata and query by them later:

```typescript
// Attach metadata when paying
await node.payInvoice(bolt11, 60_000, undefined, undefined, {
  requestId: 'order-12345',
  agent: 'purchasing-bot',
});

// Later, filter payments by metadata
const payments = node.listPayments({ metadataKey: 'requestId', metadataValue: 'order-12345' });
// Returns only payments where metadata.requestId === 'order-12345'

// Filter by key existence (any value)
const allTagged = node.listPayments({ metadataKey: 'agent' });
```

Via HTTP:
```bash
curl "http://localhost:2112/payments?metadataKey=requestId&metadataValue=order-12345" \
  -H "Authorization: Bearer $TOKEN"
```

## Electrum Failover

For production reliability, configure multiple Electrum servers:

```typescript
const node = await BeignetNode.create({
  network: 'mainnet',
  electrumServers: [
    { host: 'fulcrum.bitkit.blocktank.to', port: 8900, tls: true },
    { host: 'electrum.blockstream.info', port: 700, tls: true },
  ],
});

// Failover is automatic — when the current server fails, beignet reconnects to the next one
node.on('electrum:failover', (data) => {
  console.log(`Switched from ${data.from.host}:${data.from.port} to ${data.to.host}:${data.to.port}`);
});
```

The readiness checker will warn if only one server is configured:
```typescript
const report = node.getMainnetReadiness();
// Check: ELECTRUM_REDUNDANCY — WARN if < 2 servers
```

## Automated Backups

Enable automated periodic backups for unattended operation:

```typescript
const node = await BeignetNode.create({
  network: 'mainnet',
  backupPath: '/var/backups/beignet/node.db',
  backupIntervalMs: 6 * 60 * 60 * 1000, // every 6 hours (default)
});

// Monitor backup status
node.on('backup:completed', ({ path, timestamp }) => {
  console.log('Backup saved to', path);
});
node.on('backup:failed', ({ path, error }) => {
  console.error('Backup failed:', error);
});

// Trigger on-demand backup
await node.triggerBackup();
```

Via CLI:
```bash
# Start with automated backups
beignet start --backup-path /var/backups/beignet/node.db --backup-interval 21600000

# Manual backup
beignet backup /tmp/snapshot.db
```

## Auto-Open Minimum Channels

Ensure your node always has sufficient channels. The method automatically connects to peers using gossip graph addresses before opening:

```typescript
// Auto-connect + open channels up to a minimum count
const channels = await node.ensureMinimumChannels(3, 500_000);
// Returns existing ready channels + newly opened channels
console.log('Channels:', channels.length);

// Or connect + open a specific channel in one call:
const ch = await node.connectAndOpenChannel(pubkey, host, port, 500_000);
```

Via HTTP:
```bash
curl -X POST http://localhost:2112/channels/ensure-minimum \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"count": 3, "satsPerChannel": 500000}'
```

## Backup & Recovery

```typescript
// Manual backup
await node.backup('/path/to/backup.db');

// Automated backups (configured at node creation)
const node = await BeignetNode.create({
  backupPath: '/var/backups/beignet/node.db',
  backupIntervalMs: 6 * 60 * 60 * 1000,
});

// Recovery: create node with same mnemonic
const recovered = await BeignetNode.create({
  mnemonic: savedMnemonic,
  network: 'mainnet',
});
// Channels and payment history are restored from SQLite
```

## Spending Limits

Enforce a daily budget to prevent runaway spending by AI agents:

```typescript
const node = await BeignetNode.create({
  network: 'mainnet',
  dailySpendLimitSats: 100_000, // 100k sats/day budget
});

// Check current spend info
const info = node.getDailySpendInfo();
console.log('Limit:', info.limitSats, 'Spent:', info.spentSats, 'Remaining:', info.remainingSats);
// Resets at midnight UTC (info.resetsAt)

// payInvoice and sendKeysend will throw SPENDING_LIMIT_EXCEEDED if the limit is hit.
// Spend is recorded AFTER payment settles — failed payments do not count against the limit.
// Concurrent payments are guarded by a pending counter to prevent overshoot.
```

Via environment variable:
```bash
export BEIGNET_DAILY_SPEND_LIMIT_SATS=100000
```

Via CLI:
```bash
beignet start --daily-spend-limit 100000
```

Via HTTP:
```bash
curl http://localhost:2112/spend-limit -H "Authorization: Bearer $TOKEN"
# { "ok": true, "result": { "limitSats": 100000, "spentSats": 42000, "remainingSats": 58000, "resetsAt": 1709078400000 } }
```

## Idempotency Keys

Prevent duplicate payments from agent retry loops by adding the `X-Idempotency-Key` header to payment requests:

```bash
# First request — payment is executed, response is cached for 24 hours
curl -X POST http://localhost:2112/invoice/pay-safe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Idempotency-Key: order-12345" \
  -d '{"bolt11": "lnbc..."}'

# Retry with same key + same body — returns cached response (no duplicate payment)
curl -X POST http://localhost:2112/invoice/pay-safe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Idempotency-Key: order-12345" \
  -d '{"bolt11": "lnbc..."}'

# Same key with DIFFERENT body — returns 409 IDEMPOTENCY_CONFLICT
```

Supported endpoints: `/invoice/pay`, `/invoice/pay-safe`, `/invoice/pay-async`, `/invoice/pay-retry`, `/keysend`, `/keysend/safe`.

## Graceful Shutdown (Drain Mode)

Stop accepting new payments, wait for in-flight ones to settle, then shutdown:

```bash
# Drain mode: rejects new payments (SERVICE_DRAINING), waits up to 60s for pending payments
curl -X POST http://localhost:2112/stop \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"drain": true, "drainTimeoutMs": 60000}'
```

Programmatic:
```typescript
node.setDraining(true);  // New payInvoice/sendKeysend calls will throw SERVICE_DRAINING
// Wait for in-flight payments...
while (node.hasPendingPayments()) {
  await new Promise(r => setTimeout(r, 2000));
}
await node.gracefulShutdown();
```

## Security

- **API Token**: Always set `apiToken` in production
- **Mnemonic**: Store securely, never log
- **Network**: Bind daemon to `127.0.0.1` (default)
- **TLS**: For production, enable HTTPS with `--tls-cert` and `--tls-key` (or `BEIGNET_TLS_CERT`/`BEIGNET_TLS_KEY` env vars)
- **CORS**: Only enable if needed, specify exact origin
- **Spending Limits**: Set `dailySpendLimitSats` to cap daily agent spending
- **Idempotency Keys**: Use `X-Idempotency-Key` header on payment requests to prevent duplicates
- **Webhook Secrets**: Use HMAC-SHA256 verification (secrets are hashed in storage, never stored plaintext)
- **Rate Limiting**: Enable `rateLimit` option to protect against runaway agent loops (429 `RATE_LIMITED` response). Health and metrics endpoints are exempt.

## Mainnet Checklist

Use the built-in readiness checker:

```typescript
const report = node.getMainnetReadiness();
console.log('Score:', report.score + '/100');
console.log('Ready:', report.ready);
for (const check of report.checks) {
  const icon = check.status === 'PASS' ? 'OK' : check.status === 'WARN' ? '!!' : 'XX';
  console.log(`[${icon}] ${check.name}: ${check.message}`);
}
```

## Upgrade Path

Beignet follows semver. When upgrading:

1. **Backup** the database before upgrading
2. **Read** the changelog for breaking changes
3. **Test** on testnet/regtest first
4. **Monitor** the action log after upgrading

## Payment Intelligence

Estimate payment success before sending:

```typescript
const estimate = node.estimatePayment(bolt11);
if (estimate) {
  console.log('Success probability:', estimate.successProbabilityPct + '%');
  console.log('Estimated fee:', estimate.estimatedFeeSats, 'sats');
  console.log('Route quality:', estimate.routeQuality);
  if (estimate.warning) console.log('Warning:', estimate.warning);
}
```

## Time-Windowed Statistics

Get stats for a specific time window:

```typescript
// Last hour stats
const hourStats = node.getStats(3600000);
console.log('Payments sent (last hour):', hourStats.totalPaymentsSent);
console.log('Avg payment time:', hourStats.avgPaymentTimeSec, 'sec');
console.log('Avg fee %:', hourStats.avgFeePct);
```
