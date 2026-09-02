/**
 * OpenAPI 3.0 specification for the Beignet Lightning daemon.
 *
 * Generated from daemon routes. Served at GET /openapi.json.
 */

import { ROUTE_SCOPES } from './auth';

export function getOpenApiSpec(): Record<string, unknown> {
	const spec: Record<string, unknown> = {
		openapi: '3.0.3',
		info: {
			title: 'Beignet Lightning API',
			version: '1.0.0',
			description:
				'HTTP API for a self-custodial Bitcoin + Lightning node. Designed for AI agents.\n\n' +
				'**Idempotency:** Payment endpoints (`/invoice/pay`, `/invoice/pay-safe`, `/invoice/pay-async`, `/invoice/pay-retry`, `/keysend`, `/keysend/safe`) support the `X-Idempotency-Key` header. ' +
				'When provided, the response is cached for 24 hours — repeated requests with the same key and body return the cached response. ' +
				'If the same key is reused with a different request body, a `409 IDEMPOTENCY_CONFLICT` error is returned.\n\n' +
				'**TLS:** The daemon supports HTTPS when started with `--tls-cert` and `--tls-key` flags (or `BEIGNET_TLS_CERT`/`BEIGNET_TLS_KEY` env vars).\n\n' +
				'**Scoped API keys:** Besides the legacy single `apiToken` (implicit admin scope), the `apiKeys` config defines named keys with `readonly`, `invoice`, and/or `admin` scopes. Each operation lists the scopes it accepts in `x-accepted-scopes`; unclassified routes are admin-only. Requests fail with 401 (bad/absent key) or 403 (valid key, insufficient scope).\n\n' +
				'**Spending Limits:** Configure `dailySpendLimitSats` (or `BEIGNET_DAILY_SPEND_LIMIT_SATS` env var) to enforce a daily budget. Query `GET /spend-limit` for current usage.\n\n' +
				'**Drain Mode:** `POST /stop` accepts `{ "drain": true }` to stop accepting new payments and wait for in-flight ones to settle before shutdown.'
		},
		servers: [{ url: 'http://127.0.0.1:2112', description: 'Local daemon' }],
		paths: {
			'/info': {
				get: {
					summary: 'Get node info',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Node info',
							content: jsonContent({ $ref: '#/components/schemas/NodeInfo' })
						}
					}
				}
			},
			'/balance': {
				get: {
					summary: 'Get balance (on-chain + lightning)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Balance',
							content: jsonContent({ $ref: '#/components/schemas/BalanceInfo' })
						}
					}
				}
			},
			'/health': {
				get: {
					summary: 'Health check (auth-exempt)',
					tags: ['Node'],
					security: [],
					responses: {
						'200': {
							description: 'Health status',
							content: jsonContent({ $ref: '#/components/schemas/HealthInfo' })
						}
					}
				}
			},
			'/ready': {
				get: {
					summary:
						'Simple readiness check — true when the node has at least one channel that is NORMAL and will accept a new HTLC. A channel restored from a Recovery Capsule whose state has not been proven current is NORMAL but holds, so it does not count (auth-exempt)',
					tags: ['Node'],
					security: [],
					responses: {
						'200': {
							description: 'Ready status',
							content: jsonContent({
								type: 'object',
								properties: { ready: { type: 'boolean' } }
							})
						}
					}
				}
			},
			'/peers': {
				get: {
					summary: 'List connected peers',
					tags: ['Peers'],
					responses: {
						'200': {
							description: 'Peer list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/PeerInfo' }
							})
						}
					}
				}
			},
			'/channels': {
				get: {
					summary: 'List all channels',
					tags: ['Channels'],
					responses: {
						'200': {
							description: 'Channel list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ChannelInfo' }
							})
						}
					}
				}
			},
			'/channels/ready': {
				get: {
					summary:
						'List channels that are NORMAL and will accept a new HTLC (a capsule-restored channel holding for recency is excluded)',
					tags: ['Channels'],
					responses: {
						'200': {
							description: 'Ready channels',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ChannelInfo' }
							})
						}
					}
				}
			},
			'/payments': {
				get: {
					summary: 'List payments with optional filtering',
					tags: ['Payments'],
					parameters: [
						{
							name: 'status',
							in: 'query',
							schema: {
								type: 'string',
								enum: ['PENDING', 'COMPLETED', 'FAILED']
							}
						},
						{
							name: 'direction',
							in: 'query',
							schema: { type: 'string', enum: ['OUTGOING', 'INCOMING'] }
						},
						{ name: 'since', in: 'query', schema: { type: 'integer' } },
						{ name: 'limit', in: 'query', schema: { type: 'integer' } },
						{ name: 'offset', in: 'query', schema: { type: 'integer' } },
						{
							name: 'metadataKey',
							in: 'query',
							schema: { type: 'string' },
							description:
								'Filter by metadata key existence (or key=value when paired with metadataValue)'
						},
						{
							name: 'metadataValue',
							in: 'query',
							schema: { type: 'string' },
							description:
								'Filter by metadata key=value match (requires metadataKey)'
						}
					],
					responses: {
						'200': {
							description: 'Payment list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/PaymentInfo' }
							})
						}
					}
				}
			},
			'/forwards': {
				get: {
					summary: 'List settled forwards (fees earned), newest first',
					tags: ['Payments'],
					parameters: [
						{
							name: 'since',
							in: 'query',
							schema: { type: 'integer' },
							description: 'Only events settled at/after this ms timestamp'
						},
						{
							name: 'until',
							in: 'query',
							schema: { type: 'integer' },
							description: 'Only events settled at/before this ms timestamp'
						},
						{ name: 'limit', in: 'query', schema: { type: 'integer' } },
						{ name: 'offset', in: 'query', schema: { type: 'integer' } },
						{
							name: 'channelId',
							in: 'query',
							schema: { type: 'string' },
							description: 'Match the inbound OR outbound leg'
						}
					],
					responses: {
						'200': {
							description: 'Forwarding events (msat values as strings)',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ForwardingEvent' }
							})
						}
					}
				}
			},
			'/forwards/summary': {
				get: {
					summary: 'Forwarding totals: count, volume out, fees earned',
					tags: ['Payments'],
					parameters: [
						{
							name: 'since',
							in: 'query',
							schema: { type: 'integer' },
							description: 'Only events settled at/after this ms timestamp'
						}
					],
					responses: {
						'200': {
							description: 'Forwarding summary (msat values as strings)',
							content: jsonContent({
								$ref: '#/components/schemas/ForwardingSummary'
							})
						}
					}
				}
			},
			'/watchtowers': {
				get: {
					summary:
						'List configured watchtowers with per-tower session + backlog health',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Watchtower health',
							content: jsonContent({
								type: 'object',
								properties: {
									towers: {
										type: 'array',
										items: { $ref: '#/components/schemas/WatchtowerInfo' }
									}
								}
							})
						}
					}
				}
			},
			'/watchtower/add': {
				post: {
					summary: 'Add a watchtower (pubkey@host:port, LND altruist tower)',
					tags: ['Node'],
					requestBody: bodyContent({ uri: 'string' }),
					responses: { '200': { description: 'Tower added' } }
				}
			},
			'/watchtower/remove': {
				delete: {
					summary: 'Remove a watchtower and drop its sessions + backlog',
					tags: ['Node'],
					requestBody: bodyContent({ uri: 'string' }),
					responses: { '200': { description: 'Tower removed' } }
				}
			},
			'/invoices': {
				get: {
					summary: 'List created invoices',
					tags: ['Invoices'],
					responses: {
						'200': {
							description: 'Invoice list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/InvoiceInfo' }
							})
						}
					}
				}
			},
			'/invoice/create': {
				post: {
					summary: 'Create a BOLT 11 invoice',
					tags: ['Invoices'],
					requestBody: bodyContent({
						amountSats: 'number?',
						description: 'string?',
						expirySecs: 'number?',
						descriptionHash: 'string?',
						minFinalCltvExpiry: 'number?'
					}),
					responses: {
						'200': {
							description: 'Created invoice',
							content: jsonContent({ $ref: '#/components/schemas/InvoiceInfo' })
						}
					}
				}
			},
			'/jit/invoice': {
				post: {
					summary:
						'Create a JIT receive invoice: registers a receive intent with the LSP and returns an invoice payable through a channel that does not exist yet. The LSP intercepts the HTLC, funds the channel and forwards, deducting the quoted opening fee (flatFeeSat + feePpm) from the delivery. Requires the LSP peer to be connected and running the JIT receive engine',
					tags: ['Invoices'],
					requestBody: bodyContent({
						lspPubkey: 'string',
						amountSats: 'number?',
						description: 'string?',
						expirySecs: 'number?',
						targetRemainingInboundSat: 'number?',
						maxFlatFeeSat: 'number?',
						maxFeePpm: 'number?'
					}),
					responses: {
						'200': {
							description: 'Created invoice plus the agreed opening fee',
							content: jsonContent({
								allOf: [
									{ $ref: '#/components/schemas/InvoiceInfo' },
									{
										type: 'object',
										properties: {
											flatFeeSat: { type: 'number' },
											feePpm: { type: 'number' }
										}
									}
								]
							})
						}
					}
				}
			},
			'/direct-funding/configure': {
				post: {
					summary:
						'Set the direct-funding policy: the liquidity peer every direct-funded channel is negotiated with, where it is reachable, whether such an open may go zero-conf, and the minimum offer served. A partial MERGE, never a replace: a field the body does not name keeps its value. minAmountSat clamps up to the 5000 sat protocol floor and the response reports the clamped value. targetInboundSat is recorded and reported but not yet consumed. Admin scope',
					tags: ['DirectFunding'],
					requestBody: bodyContent({
						lspPubkey: 'string?',
						lspHost: 'string?',
						lspPort: 'number?',
						targetInboundSat: 'number?',
						trusted: 'boolean?',
						minAmountSat: 'number?'
					}),
					responses: {
						'200': {
							description: 'The full effective policy after the merge',
							content: jsonContent({
								$ref: '#/components/schemas/DirectFundingConfig'
							})
						}
					}
				}
			},
			'/direct-funding/config': {
				get: {
					summary:
						'Read the effective direct-funding policy. lspPubkey is null when no liquidity peer has been set, in which case this node serves no offers. Readonly scope',
					tags: ['DirectFunding'],
					responses: {
						'200': {
							description: 'The effective policy',
							content: jsonContent({
								$ref: '#/components/schemas/DirectFundingConfig'
							})
						}
					}
				}
			},
			'/direct-funding/request': {
				post: {
					summary:
						'Mint a direct-funding payment request. Returns the receipt hash (its preimage stays here and is revealed to the payer after broadcast, as a delivery receipt) and `request`, the base64url envelope a payer pays; put it in a BIP 21 URI under the bgnq parameter. host and port are the address a payer can reach this node on and are used exactly as given: the daemon has no way to know which of a browser hostname and a public host is right. With neither, no direct-peer descriptor is emitted and the payer reaches this node through the liquidity peer. Invoice scope',
					tags: ['DirectFunding'],
					requestBody: bodyContent({
						host: 'string?',
						port: 'number?',
						amountSats: 'number?'
					}),
					responses: {
						'200': {
							description: 'The minted request',
							content: jsonContent({
								type: 'object',
								properties: {
									paymentHash: { type: 'string' },
									expiresAt: { type: 'number' },
									request: { type: 'string' }
								}
							})
						}
					}
				}
			},
			'/direct-funding/send': {
				post: {
					summary:
						'Pay a direct-funding request by funding the receiver channel from one of our coins. THIS CALL REJECTS ONLY BEFORE OUR WITNESS LEAVES THE DEVICE: after that it resolves, with whatever is known and a `caveat` saying what was lost. That is a protocol MUST, and it is load bearing, because a client that falls back to a plain on-chain send on any error cannot tell a late rejection from an early one and would pay twice. Anyone adding an error path here must keep it on the pre-witness side. The call sets no deadline of its own and may block for the whole offer to receipt exchange. Idempotent on the request id: a second send against a request that already has an attempt returns that attempt rather than starting a new one, so a retry can never commit a second coin. feeHeadroomSats is a documented alias for maxTotalFeeSat, the ceiling on our own cost above the amount. Admin scope',
					tags: ['DirectFunding'],
					requestBody: bodyContent({
						request: 'string',
						amountSats: 'number?',
						maxTotalFeeSat: 'number?',
						feeHeadroomSats: 'number?'
					}),
					responses: {
						'200': {
							description: 'The payment as it stands',
							content: jsonContent({
								$ref: '#/components/schemas/DirectFundingSendResult'
							})
						}
					}
				}
			},
			'/invoice/create-hold': {
				post: {
					summary:
						'Create a hold invoice for a caller-supplied payment hash (preimage stays with the caller; the incoming HTLC parks until settle/cancel)',
					tags: ['Invoices'],
					requestBody: bodyContent({
						paymentHash: 'string',
						amountMsat: 'string?',
						amountSats: 'number?',
						description: 'string?',
						expiry: 'number?'
					}),
					responses: {
						'200': {
							description: 'Created hold invoice',
							content: jsonContent({ $ref: '#/components/schemas/InvoiceInfo' })
						}
					}
				}
			},
			'/invoice/settle-hold': {
				post: {
					summary:
						'Settle a hold invoice with its preimage: validates sha256(preimage) and fulfills every parked HTLC (all MPP parts)',
					tags: ['Invoices'],
					requestBody: bodyContent({ preimage: 'string' }),
					responses: {
						'200': {
							description: 'Settled',
							content: jsonContent({
								type: 'object',
								properties: { paymentHash: { type: 'string' } }
							})
						}
					}
				}
			},
			'/invoice/cancel-hold': {
				post: {
					summary:
						'Cancel a hold invoice: fails parked HTLCs back with incorrect_or_unknown_payment_details and rejects future ones',
					tags: ['Invoices'],
					requestBody: bodyContent({ paymentHash: 'string' }),
					responses: {
						'200': {
							description: 'Cancelled',
							content: jsonContent({
								type: 'object',
								properties: {
									paymentHash: { type: 'string' },
									htlcsFailed: { type: 'integer' }
								}
							})
						}
					}
				}
			},
			'/invoices/held': {
				get: {
					summary: 'List hold invoices with lifecycle state and parked totals',
					tags: ['Invoices'],
					responses: {
						'200': {
							description: 'Hold invoices',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/HoldInvoiceInfo' }
							})
						}
					}
				}
			},
			'/invoice': {
				get: {
					summary: 'Get a specific invoice by payment hash',
					tags: ['Invoices'],
					parameters: [
						{
							name: 'paymentHash',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Invoice info',
							content: jsonContent({ $ref: '#/components/schemas/InvoiceInfo' })
						}
					}
				}
			},
			'/invoice/decode': {
				post: {
					summary: 'Decode a BOLT 11 invoice',
					tags: ['Invoices'],
					requestBody: bodyContent({ bolt11: 'string' }),
					responses: { '200': { description: 'Decoded invoice' } }
				}
			},
			'/invoice/validate': {
				post: {
					summary:
						'Pre-flight payment validation — checks decode, expiry, limits, capacity, route',
					tags: ['Payments'],
					requestBody: bodyContent({ bolt11: 'string', amountSats: 'number?' }),
					responses: {
						'200': {
							description: 'Validation result',
							content: jsonContent({
								type: 'object',
								properties: {
									status: { type: 'string', enum: ['OK', 'WARN', 'FAIL'] },
									summary: { type: 'string' },
									checks: {
										type: 'array',
										items: {
											type: 'object',
											properties: {
												name: { type: 'string' },
												status: {
													type: 'string',
													enum: ['OK', 'WARN', 'FAIL']
												},
												message: { type: 'string' }
											}
										}
									},
									invoice: { $ref: '#/components/schemas/DecodedInvoice' }
								}
							})
						}
					}
				}
			},
			'/invoice/pay': {
				post: {
					summary: 'Pay an invoice (blocks until settled or timeout)',
					tags: ['Payments'],
					requestBody: bodyContent({
						bolt11: 'string',
						timeoutMs: 'number?',
						maxFeeSats: 'number?',
						amountSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Payment result',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/invoice/pay-async': {
				post: {
					summary: 'Pay an invoice (returns immediately)',
					tags: ['Payments'],
					requestBody: bodyContent({
						bolt11: 'string',
						maxFeeSats: 'number?',
						amountSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description:
								'Pending payment, or FAILED when the engine refused it without dispatching an HTLC (an expired invoice, a locally refused HTLC)',
							content: jsonContent({
								type: 'object',
								properties: {
									paymentHash: { type: 'string' },
									status: { type: 'string', enum: ['PENDING', 'FAILED'] }
								}
							})
						}
					}
				}
			},
			'/invoice/pay-safe': {
				post: {
					summary:
						'Pay an invoice (never throws — always returns PaymentInfo with COMPLETED or FAILED status)',
					tags: ['Payments'],
					requestBody: bodyContent({
						bolt11: 'string',
						timeoutMs: 'number?',
						maxFeeSats: 'number?',
						amountSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Payment result (always resolves)',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/channel/open': {
				post: {
					summary: 'Open a channel',
					tags: ['Channels'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						pushSats: 'number?',
						satsPerVbyte: 'number?',
						max: 'boolean?'
					}),
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						},
						'400': {
							description:
								'INVALID_PARAMS: the request cannot be served as written (fractional amount, push toward a dual-fund peer, out-of-range feerate)'
						},
						'409': {
							description:
								'FUNDING_PROVIDER_REQUIRED or INSUFFICIENT_BALANCE: the node cannot fund this open as things stand'
						},
						'503': {
							description:
								'FEE_ESTIMATE_NOT_READY: the estimator has not sampled yet, retry shortly'
						}
					}
				}
			},
			'/channel/open-and-wait': {
				post: {
					summary: 'Open a channel and wait for it to be ready',
					tags: ['Channels'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						pushSats: 'number?',
						timeoutMs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel info (ready)',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						}
					}
				}
			},
			'/channel/close': {
				post: {
					summary:
						'Cooperatively close a channel. The payout goes to a wallet-scanned address: the current unused wallet address when the wallet can produce one (consecutive closes may get the same address until it sees use), else the startup sweep address, else the funding-key address, so the closed balance is tracked and spendable without a rescue sweep. A channel restored from a Recovery Capsule needs acceptStaleStateRisk: true, because a mutual close pays out the balances that row carries and a stale allocation is peer-favourable by construction: any payment received after the capsule was written is missing from it. Letting the peer close unilaterally is the safe outcome; the flag is the labelled way to accept the risk anyway',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						// Conditionally required, and only for a capsule-restored
						// channel, so the schema cannot say "required" without
						// misdescribing every other close.
						acceptStaleStateRisk: 'boolean?'
					}),
					responses: { '200': { description: 'Close result' } }
				}
			},
			'/channel/forceclose': {
				post: {
					summary:
						'Force close a channel (returns commitment txid). A channel restored from a Recovery Capsule needs acceptStaleStateRisk: true, because its recency cannot be proven: the node refuses to broadcast such a commitment on its own initiative, and if the peer holds a newer state the broadcast is revoked and the whole channel balance goes to the justice path. Waiting for the peer to close is the safe outcome; the flag is the labelled way to accept the risk anyway',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						// Conditionally required, and only for a capsule-restored
						// channel, so the schema cannot say "required" without
						// misdescribing every other force close.
						acceptStaleStateRisk: 'boolean?'
					}),
					responses: {
						'200': { description: 'Force close result with commitment txid' }
					}
				}
			},
			'/channel/rebroadcast-close': {
				post: {
					summary:
						'Rebroadcast the recorded close transaction of a force-closed channel (or an unconfirmed mutual close). Idempotent; always rebuilds from the latest state, so no older commitment can be selected.',
					tags: ['Channels'],
					requestBody: bodyContent({ channelId: 'string' }),
					responses: {
						'200': {
							description: 'Rebroadcast result',
							content: jsonContent({
								type: 'object',
								properties: {
									txid: {
										type: 'string',
										description: 'Txid of the rebroadcast close transaction'
									},
									broadcastOk: {
										type: 'boolean',
										description:
											'Whether the broadcast reached the network (a duplicate rejection counts as success)'
									}
								}
							})
						}
					}
				}
			},
			'/channel/update-commitment-feerate': {
				post: {
					summary:
						'Update the channel commitment transaction feerate (BOLT 2 update_fee). Not the routing fee policy.',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						feeratePerKw: 'number'
					}),
					responses: { '200': { description: 'Commitment feerate updated' } }
				}
			},
			'/channel/update-fee': {
				post: {
					summary:
						'Deprecated alias for /channel/update-commitment-feerate. Sets the commitment feerate, not the routing fee policy.',
					deprecated: true,
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						feeratePerKw: 'number'
					}),
					responses: { '200': { description: 'Commitment feerate updated' } }
				}
			},
			'/channel/update-policy': {
				post: {
					summary:
						'Set the ROUTING fee policy for one channel (channelId) or all channels (all: true); regenerates and re-broadcasts the channel_update. Msat fields accept number or decimal string.',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string?',
						all: 'boolean?',
						feeBaseMsat: 'number?',
						feeProportionalMillionths: 'number?',
						cltvExpiryDelta: 'number?',
						htlcMinimumMsat: 'string?',
						htlcMaximumMsat: 'string?'
					}),
					responses: {
						'200': {
							description: 'Updated count + effective policies',
							content: jsonContent({
								type: 'object',
								properties: {
									updated: { type: 'integer' },
									policies: {
										type: 'array',
										items: { $ref: '#/components/schemas/ChannelPolicy' }
									}
								}
							})
						}
					}
				}
			},
			'/channel/policy': {
				get: {
					summary:
						'Get the effective routing fee policy for a channel (override or node defaults)',
					tags: ['Channels'],
					parameters: [
						{
							name: 'channelId',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Effective channel policy',
							content: jsonContent({
								$ref: '#/components/schemas/ChannelPolicy'
							})
						},
						'400': { description: 'Missing channelId' },
						'404': { description: 'Channel not found' }
					}
				}
			},
			'/channels/ensure-minimum': {
				post: {
					summary:
						'Ensure a minimum number of channels are open (uses channel suggestions)',
					tags: ['Channels'],
					requestBody: bodyContent({
						count: 'number',
						satsPerChannel: 'number',
						timeoutMs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel list (existing + newly opened)',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ChannelInfo' }
							})
						}
					}
				}
			},
			'/channel/connect-and-open': {
				post: {
					summary: 'Connect to peer and open channel in one call',
					tags: ['Channels'],
					requestBody: bodyContent({
						pubkey: 'string',
						host: 'string',
						port: 'number',
						amountSats: 'number',
						pushSats: 'number?',
						satsPerVbyte: 'number?',
						max: 'boolean?',
						trusted: 'boolean?'
					}),
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						}
					}
				}
			},
			'/channel': {
				get: {
					summary: 'Get a specific channel by ID',
					tags: ['Channels'],
					parameters: [
						{
							name: 'channelId',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						}
					}
				}
			},
			'/channel/health': {
				get: {
					summary: 'Get channel health assessment with liquidity warnings',
					tags: ['Channels'],
					parameters: [
						{
							name: 'channelId',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Channel health',
							content: jsonContent({
								$ref: '#/components/schemas/ChannelHealth'
							})
						},
						'400': { description: 'Missing channelId' },
						'404': { description: 'Channel not found' }
					}
				}
			},
			'/peer/connect': {
				post: {
					summary:
						'Connect to a peer (omit host+port to resolve the address from the gossip graph / DNS bootstrap; pass transport "ws" and/or a ws:///wss:// url to dial over WebSocket)',
					tags: ['Peers'],
					requestBody: bodyContent({
						pubkey: 'string',
						host: 'string?',
						port: 'number?',
						transport: 'string?',
						url: 'string?'
					}),
					responses: {
						'200': {
							description: 'Peer info',
							content: jsonContent({ $ref: '#/components/schemas/PeerInfo' })
						},
						'400': {
							description:
								'INVALID_PARAMS: malformed pubkey, host without port, or host/port contradicting the ws url'
						},
						'502': { description: 'CONNECT_FAILED: the dial failed' },
						'504': {
							description: 'CONNECT_TIMEOUT: the peer did not answer in time'
						}
					}
				}
			},
			'/peer/disconnect': {
				post: {
					summary: 'Disconnect from a peer',
					tags: ['Peers'],
					requestBody: bodyContent({ pubkey: 'string' }),
					responses: { '200': { description: 'Disconnected' } }
				}
			},
			'/payment/cancel': {
				post: {
					summary: 'Cancel a pending payment',
					tags: ['Payments'],
					requestBody: bodyContent({ paymentHash: 'string' }),
					responses: { '200': { description: 'Cancelled' } }
				}
			},
			'/payment': {
				get: {
					summary: 'Get a specific payment by hash',
					tags: ['Payments'],
					parameters: [
						{
							name: 'paymentHash',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Payment info',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/l402/fetch': {
				post: {
					summary:
						'Fetch an L402-gated URL, paying the challenge under a price cap',
					description:
						'Parses the WWW-Authenticate L402 challenge, verifies the invoice payment hash against the macaroon commitment, pays under maxPriceSats (on top of the node spend limits), then retries with the paid credential. Pays at most once per call.',
					tags: ['Payments'],
					requestBody: {
						required: true,
						content: jsonContent({
							type: 'object',
							required: ['url', 'maxPriceSats'],
							properties: {
								url: { type: 'string' },
								method: { type: 'string' },
								headers: { type: 'object', additionalProperties: true },
								body: { type: 'string' },
								maxPriceSats: {
									type: 'number',
									description:
										'Required satoshi cap on what one challenge may cost'
								},
								maxFeeSats: {
									type: 'number',
									description:
										'Routing fee cap in satoshis. Defaults to 5% of the price with a 5 sat floor, never to uncapped'
								},
								timeoutMs: { type: 'number' },
								fetchTimeoutMs: {
									type: 'number',
									description: 'Per HTTP request timeout, default 30000'
								},
								maxResponseBytes: {
									type: 'number',
									description:
										'Ceiling on the proxied response body, default 5242880'
								},
								scopePerPath: { type: 'boolean' },
								allowUnverifiedMacaroon: {
									type: 'boolean',
									description:
										'Unsafe: pay a challenge whose macaroon could not be parsed, so its payment hash commitment is unchecked'
								},
								allowCrossOriginChallenge: {
									type: 'boolean',
									description:
										'Unsafe: pay a challenge served from a different origin than requested, after a redirect'
								},
								allowPrivateNetwork: {
									type: 'boolean',
									description:
										'Permit a target on a private, loopback, or link-local host, which is refused by default because this endpoint fetches on behalf of the caller from the node machine'
								}
							}
						})
					},
					responses: {
						'200': {
							description: 'Response from the gated resource',
							content: jsonContent({
								type: 'object',
								properties: {
									status: { type: 'number' },
									body: { type: 'string' },
									truncated: {
										type: 'boolean',
										description:
											'True when the body was cut at maxResponseBytes'
									},
									paid: { type: 'boolean' },
									amountPaidSats: { type: 'number' },
									paymentHash: { type: 'string' }
								}
							})
						}
					}
				}
			},
			'/l402/credentials': {
				get: {
					summary: 'List paid L402 credentials held by this process',
					description:
						'Preimages are masked: the list identifies what is held and what it cost, it does not export usable bearer tokens.',
					tags: ['Payments'],
					responses: {
						'200': {
							description: 'Held credentials, preimages masked',
							content: jsonContent({ type: 'array', items: { type: 'object' } })
						}
					}
				}
			},
			'/l402/credential': {
				delete: {
					summary:
						'Forget a paid L402 credential so the next request pays again',
					tags: ['Payments'],
					parameters: [
						{
							name: 'scope',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Credential forgotten',
							content: jsonContent({ type: 'object' })
						}
					}
				}
			},
			'/payment/proof': {
				get: {
					summary: 'Get cryptographic payment proof',
					tags: ['Payments'],
					parameters: [
						{
							name: 'paymentHash',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Payment proof',
							content: jsonContent({
								$ref: '#/components/schemas/PaymentProof'
							})
						}
					}
				}
			},
			'/payment/verify-proof': {
				get: {
					summary:
						'Cryptographically verify a payment proof (sha256(preimage) === paymentHash)',
					tags: ['Payments'],
					parameters: [
						{
							name: 'paymentHash',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': {
							description: 'Verification result',
							content: jsonContent({
								$ref: '#/components/schemas/PaymentProofVerification'
							})
						}
					}
				}
			},
			'/node/uri': {
				get: {
					summary: 'Get node connection URI (pubkey@host:port)',
					tags: ['Node'],
					parameters: [
						{
							name: 'host',
							in: 'query',
							schema: { type: 'string' },
							description: 'External host/IP override (defaults to 127.0.0.1)'
						}
					],
					responses: {
						'200': {
							description: 'Node URI',
							content: jsonContent({
								type: 'object',
								properties: { uri: { type: 'string' } }
							})
						},
						'404': { description: 'Node is not listening' }
					}
				}
			},
			'/invoice/pay-retry': {
				post: {
					summary:
						'Pay an invoice with automatic retry and exponential backoff',
					tags: ['Payments'],
					requestBody: bodyContent({
						bolt11: 'string',
						maxRetries: 'number?',
						backoffMs: 'number?',
						maxFeeSats: 'number?',
						amountSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Payment result with retry info',
							content: jsonContent({
								$ref: '#/components/schemas/RetryPaymentResult'
							})
						}
					}
				}
			},
			'/keysend': {
				post: {
					summary:
						'Send a keysend (spontaneous) payment — blocks until settled or timeout',
					tags: ['Payments'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						timeoutMs: 'number?',
						maxFeeSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Payment result',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/keysend/safe': {
				post: {
					summary:
						'Send a keysend payment — never throws, always returns PaymentInfo',
					tags: ['Payments'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						timeoutMs: 'number?',
						maxFeeSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Payment result (always succeeds)',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/offer/create': {
				post: {
					summary: 'Create a BOLT 12 offer',
					tags: ['Offers'],
					requestBody: bodyContent({
						description: 'string',
						amountSats: 'number?',
						issuer: 'string?',
						expirySecs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Offer info',
							content: jsonContent({ $ref: '#/components/schemas/OfferInfo' })
						}
					}
				}
			},
			'/offer': {
				delete: {
					summary: 'Remove a stored offer',
					tags: ['Offers'],
					parameters: [
						{
							name: 'offerId',
							in: 'query',
							required: true,
							schema: { type: 'string' },
							description: 'Offer id (64 hex characters)'
						}
					],
					responses: {
						'200': {
							description: 'Removal result',
							content: jsonContent({ removed: 'boolean' })
						}
					}
				}
			},
			'/offer/decode': {
				post: {
					summary: 'Decode a BOLT 12 offer',
					tags: ['Offers'],
					requestBody: bodyContent({ offer: 'string' }),
					responses: {
						'200': {
							description: 'Offer info',
							content: jsonContent({ $ref: '#/components/schemas/OfferInfo' })
						}
					}
				}
			},
			'/offers': {
				get: {
					summary: 'List created offers',
					tags: ['Offers'],
					responses: {
						'200': {
							description: 'Offer list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/OfferInfo' }
							})
						}
					}
				}
			},
			'/route/estimate': {
				post: {
					summary: 'Estimate route fee for a BOLT 11 invoice',
					tags: ['Routing'],
					requestBody: bodyContent({ bolt11: 'string', amountSats: 'number?' }),
					responses: { '200': { description: 'Route estimate' } }
				}
			},
			'/payment/estimate': {
				post: {
					summary:
						'Estimate payment success probability, fees, and route quality',
					tags: ['Payments'],
					requestBody: bodyContent({ bolt11: 'string', amountSats: 'number?' }),
					responses: {
						'200': {
							description: 'Payment estimate',
							content: jsonContent({
								$ref: '#/components/schemas/PaymentEstimate'
							})
						},
						'400': { description: 'Invalid params' },
						'502': { description: 'NO_ROUTE, no path to the destination' }
					}
				}
			},
			'/route/probe': {
				post: {
					summary: 'Probe route viability to a destination',
					tags: ['Routing'],
					requestBody: bodyContent({
						destination: 'string',
						amountSats: 'number'
					}),
					responses: { '200': { description: 'Probe result' } }
				}
			},
			'/graph/info': {
				get: {
					summary: 'Network graph summary (node/channel counts, last sync)',
					tags: ['Graph'],
					responses: {
						'200': {
							description: 'Graph summary',
							content: jsonContent({ $ref: '#/components/schemas/GraphInfo' })
						}
					}
				}
			},
			'/graph/node': {
				get: {
					summary:
						'Node announcement info (alias, addresses, features) + its known channels',
					tags: ['Graph'],
					parameters: [
						{
							name: 'pubkey',
							in: 'query',
							required: true,
							schema: { type: 'string' },
							description: '33-byte node public key (hex)'
						}
					],
					responses: {
						'200': {
							description: 'Graph node info',
							content: jsonContent({
								$ref: '#/components/schemas/GraphNodeInfo'
							})
						},
						'404': { description: 'Node not found in graph' }
					}
				}
			},
			'/graph/channel': {
				get: {
					summary:
						'Channel info from gossip: endpoints, capacity and both directions of routing policy',
					tags: ['Graph'],
					parameters: [
						{
							name: 'scid',
							in: 'query',
							required: true,
							schema: { type: 'string' },
							description:
								'Short channel id as <block>x<txIndex>x<output> or 16-char hex'
						}
					],
					responses: {
						'200': {
							description: 'Graph channel info',
							content: jsonContent({
								$ref: '#/components/schemas/GraphChannelInfo'
							})
						},
						'404': { description: 'Channel not found in graph' }
					}
				}
			},
			'/graph/describe': {
				get: {
					summary:
						'Paged dump of known graph channels (limit defaults to 500 and is capped at 500)',
					tags: ['Graph'],
					parameters: [
						{ name: 'limit', in: 'query', schema: { type: 'integer' } },
						{ name: 'offset', in: 'query', schema: { type: 'integer' } }
					],
					responses: {
						'200': {
							description: 'Paged channel dump with totalChannels/limit/offset',
							content: jsonContent({
								type: 'object',
								properties: {
									totalChannels: { type: 'integer' },
									limit: { type: 'integer' },
									offset: { type: 'integer' },
									channels: {
										type: 'array',
										items: { $ref: '#/components/schemas/GraphChannelInfo' }
									}
								}
							})
						}
					}
				}
			},
			'/route/query': {
				post: {
					summary:
						'Compute a route to a destination WITHOUT sending; hops feed /payment/send-to-route',
					tags: ['Routing'],
					requestBody: bodyContent({
						destination: 'string',
						amountSats: 'number',
						maxFeeSats: 'number?'
					}),
					responses: {
						'200': {
							description: 'Route with per-hop fees and totals',
							content: jsonContent({
								$ref: '#/components/schemas/RouteQueryResult'
							})
						},
						'409': {
							description:
								'FEE_EXCEEDS_MAX, the route costs more than maxFeeSats'
						},
						'502': { description: 'NO_ROUTE, no path to the destination' }
					}
				}
			},
			'/payment/send-to-route': {
				post: {
					summary:
						'Send a payment along an explicit route (hops from POST /route/query)',
					tags: ['Payments'],
					requestBody: {
						content: {
							'application/json': {
								schema: {
									type: 'object',
									properties: {
										paymentHash: { type: 'string' },
										route: {
											type: 'object',
											properties: {
												hops: {
													type: 'array',
													items: { $ref: '#/components/schemas/RouteHop' }
												}
											},
											required: ['hops']
										},
										paymentSecret: {
											type: 'string',
											description:
												'Invoice payment_secret (required by most modern invoices)'
										}
									},
									required: ['paymentHash', 'route']
								}
							}
						}
					},
					responses: {
						'200': {
							description: 'Payment info',
							content: jsonContent({
								$ref: '#/components/schemas/PaymentInfo'
							})
						}
					}
				}
			},
			'/message/sign': {
				post: {
					summary:
						"Sign a message with the node identity key (LND-compatible: double-SHA256 of 'Lightning Signed Message:' + message, compact recoverable ECDSA, zbase32)",
					tags: ['Node'],
					requestBody: bodyContent({ message: 'string' }),
					responses: {
						'200': {
							description: 'Signature (zbase32) and our node pubkey',
							content: jsonContent({
								type: 'object',
								properties: {
									signature: { type: 'string' },
									pubkey: { type: 'string' }
								}
							})
						}
					}
				}
			},
			'/message/verify': {
				post: {
					summary:
						'Verify an LND-style message signature: recovers the signer pubkey and reports whether it is a known graph node. Compare pubkey against the expected signer.',
					tags: ['Node'],
					requestBody: bodyContent({ message: 'string', signature: 'string' }),
					responses: {
						'200': {
							description: 'Verification result',
							content: jsonContent({
								type: 'object',
								properties: {
									valid: { type: 'boolean' },
									pubkey: { type: 'string', nullable: true },
									knownNode: { type: 'boolean' }
								}
							})
						}
					}
				}
			},
			'/gossip/sync': {
				post: {
					summary:
						'Request a gossip graph sync from one peer (pubkey) or all connected peers',
					tags: ['Graph'],
					requestBody: bodyContent({ pubkey: 'string?' }),
					responses: {
						'200': {
							description: 'Pubkeys a sync was initiated with',
							content: jsonContent({
								type: 'object',
								properties: {
									syncedFrom: {
										type: 'array',
										items: { type: 'string' }
									}
								}
							})
						}
					}
				}
			},
			'/gossip/sync-rapid': {
				post: {
					summary:
						'Download and apply a Rapid Gossip Sync snapshot (mainnet only)',
					tags: ['Graph'],
					responses: {
						'200': {
							description: 'Ingestion counts',
							content: jsonContent({
								type: 'object',
								properties: {
									channelsAdded: { type: 'integer' },
									updatesApplied: { type: 'integer' }
								}
							})
						}
					}
				}
			},
			'/channel/diagnostics': {
				get: {
					summary:
						'Routing-readiness diagnostics for a channel (SCID/announcement/peer-connection issues)',
					tags: ['Channels'],
					parameters: [
						{
							name: 'channelId',
							in: 'query',
							required: true,
							schema: { type: 'string' }
						}
					],
					responses: {
						'200': { description: 'Diagnostics with an issues list' },
						'404': { description: 'Channel not found' }
					}
				}
			},
			'/address/validate': {
				post: {
					summary: 'Validate a Bitcoin address for the active network',
					tags: ['Node'],
					requestBody: bodyContent({ address: 'string' }),
					responses: {
						'200': {
							description: 'Validity',
							content: jsonContent({
								type: 'object',
								properties: {
									address: { type: 'string' },
									valid: { type: 'boolean' }
								}
							})
						}
					}
				}
			},
			'/recover-fallback-funds': {
				post: {
					summary:
						'Sweep UTXOs at the funding-key fallback address into the wallet',
					tags: ['Node'],
					requestBody: bodyContent({ feeRatePerVbyte: 'number?' }),
					responses: {
						'200': {
							description:
								'Broadcast txid and recovered amount, or { recovered: false } when nothing to recover',
							content: jsonContent({
								type: 'object',
								properties: {
									txid: { type: 'string' },
									amountSat: { type: 'integer' },
									inputCount: { type: 'integer' },
									recovered: { type: 'boolean' }
								}
							})
						}
					}
				}
			},
			'/backup/trigger': {
				post: {
					summary:
						'Trigger an on-demand backup to the configured backupPath (no-op when unset)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Trigger acknowledged',
							content: jsonContent({
								type: 'object',
								properties: { triggered: { type: 'boolean' } }
							})
						}
					}
				}
			},
			'/backup': {
				post: {
					summary: 'Create database backup',
					tags: ['Node'],
					requestBody: bodyContent({ destPath: 'string' }),
					responses: { '200': { description: 'Backup result' } }
				}
			},
			'/backup/scb': {
				get: {
					summary:
						'Export the encrypted static channel backup (seed-encrypted blob)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Encoded SCB blob, channel count, and on-disk path'
						}
					}
				}
			},
			'/backup/peer-retrieved': {
				get: {
					summary:
						'Get the newest valid SCB a peer returned via BOLT 1 peer storage, directly or embedded in a Recovery Capsule (recovery flow: reinstall with the mnemonic, connect to peers, fetch this, then POST /restore/scb with its encoded blob; in peer-storage mode prefer POST /recovery/restore-capsule, which can resume the channels)',
					tags: ['Node'],
					responses: {
						'200': {
							description:
								'Encoded SCB blob, its creation timestamp, channel count, source (scb or capsule), and the peer that returned it'
						},
						'404': {
							description: 'No peer has returned a valid backup this session'
						}
					}
				}
			},
			'/restore/scb': {
				post: {
					summary:
						'Restore channels from a static channel backup (on-chain recovery only: the peer force-closes and our balance is swept from its commitment)',
					tags: ['Node'],
					requestBody: bodyContent({ encoded: 'string?', path: 'string?' }),
					responses: {
						'200': {
							description:
								'Channel ids now recovering, entries skipped with reasons, and total channel count in the backup'
						},
						'400': {
							description:
								'Invalid params (need exactly one of encoded/path), wrong seed, or wrong network'
						}
					}
				}
			},
			'/recovery/status': {
				get: {
					summary:
						'Recovery Protocol status: the configured mode and guardian set, the daemon state (disabled/running/restore-required/restoring/restart-required/fenced), the node view (startup gate, durability, last durable sequence, per-channel recovery status), and the Recovery Capsules storage peers returned this session. A 404 means the daemon predates the feature; a 200 with state "disabled" means supported but off',
					tags: ['Node'],
					responses: {
						'200': {
							description:
								'Mode, profile, guardians, daemon state, node recovery status (null when off, restore-pending or restart-required), retrieved capsule candidates with the best head and the guardian locators that capsule names (credentials redacted; reported, never adopted over the configured set), and restore progress when one is pending or running. In peer-storage mode node.heldReestablish lists peers whose channel_reestablish for a channel this node has no record of is being held rather than answered: each entry carries the expiresAt by which a capsule must be applied, after which the peer is told the channel is unknown and force-closes. A channel restored from a capsule carries node.channels[].restoreRecencyUnproven for as long as it exists: a capsule is best-effort recency and a compatible channel_reestablish does not prove otherwise, so the daemon will never force-close that channel on its own initiative (a peer error and the timeout backstops are held, and the channel asks its peer to close instead). Such a channel also takes no new HTLCs, since its on-chain HTLC deadline backstops can never fire, though existing ones still settle; a cooperative close is refused in both directions too, since a mutual close pays out restored balances that cannot be proven current. The exits are the peer closing, or the operator acknowledging the risk with acceptStaleStateRisk: true on /channel/close (covers the whole negotiation) or /channel/forceclose'
						}
					}
				}
			},
			'/recovery/restore': {
				post: {
					summary:
						'Restore this node from its guardian replicas and start it on the restored state (channels RESUME instead of force-closing). Only valid while the daemon is restore-pending: a fresh database whose recovery namespace the guardian set holds. The epoch takeover permanently fences any still-running previous writer, so confirm must be true. Progress streams over SSE as recovery:restore-progress; crash-safe and re-runnable',
					tags: ['Node'],
					requestBody: bodyContent({ confirm: 'boolean' }),
					responses: {
						'200': {
							description:
								'Restore report: exact (wire-safety proven), frames applied, guardians repaired, and the acquired writer epoch'
						},
						'400': {
							description:
								'Missing confirm, or the target storage is unsupported'
						},
						'404': {
							description: 'The guardian set does not know this namespace'
						},
						'409': {
							description:
								'Not restore-pending, a restore is already running, or conflicting guardian artifacts (outside the crash-fault model)'
						},
						'502': {
							description: 'No verifiable head among the guardian answers'
						},
						'503': {
							description:
								'No guardian quorum reachable, or the epoch CAS retries were exhausted; retry when the set is reachable'
						}
					}
				}
			},
			'/recovery/restore-capsule': {
				post: {
					summary:
						'Peer-storage mode: restore this node from the Recovery Capsules storage peers returned this session (connect to the peers the node had channels with first; GET /recovery/status lists the candidates). Tier 2 (inline journal validates) installs the exact state into a fresh database, tears the node down and holds the daemon in the restart-required state: restart it to resume the channels; the previous database is kept beside it. Tier 1 (SCB only) recovers the channels on the live node like POST /restore/scb. Local durability has no fencing, so confirm must be true. A capsule that names guardians is refused unless unfenced is true: the labelled escape hatch for a guardian set that is gone, which cannot fence the previous writer (it keeps acting on the channels if it still runs) and never applies to a quorum-durability journal',
					tags: ['Node'],
					requestBody: bodyContent({
						confirm: 'boolean',
						unfenced: 'boolean?'
					}),
					responses: {
						'200': {
							description:
								'Restore report: tier, channel count, frames applied, the restored head and the newest head seen, rejected candidates, whether a restart is required, and, after an unfenced restore, the guardians the capsule named under unfenced (Tier 1 adds the recovering and skipped channel lists)'
						},
						'400': {
							description: 'Missing confirm, or unfenced is not a boolean'
						},
						'404': {
							description: 'No storage peer has returned a capsule this session'
						},
						'409': {
							description:
								'Not in peer-storage mode, a restore is already running, this database already holds state a restore would discard, no candidate validates, the best capsule names a guardian set and unfenced is not set (CAPSULE_RESTORE_GUARDIAN_BACKED: that state restores through the guardians with fencing; restart in the guardian mode with the locators under capsules.best.guardians, or the capsule-guardians handoff when they need credentials), or it carries a quorum-durability journal, which no unfenced restore can boot (CAPSULE_RESTORE_QUORUM_NAMESPACE)'
						},
						'500': {
							description:
								'The restored database could not be written or swapped in (an operational fault, not a candidate defect)'
						}
					}
				}
			},
			'/recovery/capsule-guardians': {
				post: {
					summary:
						'The guardian set the best retrieved Recovery Capsule names, INCLUDING transport credentials, as config entries for recoveryGuardians. The status route redacts credentials because it is readonly; this admin handoff is how a seed restore whose guardians require authentication gets them back. Nothing is adopted or persisted; confirm must be true',
					tags: ['Node'],
					requestBody: bodyContent({ confirm: 'boolean' }),
					responses: {
						'200': {
							description:
								'The peer the capsule came from, its head, the full descriptors, and config-file ready entries (guardianId, url, auth when present)'
						},
						'400': { description: 'Missing confirm' },
						'404': {
							description: 'No storage peer has returned a capsule this session'
						}
					}
				}
			},
			'/send': {
				post: {
					summary: 'Send on-chain Bitcoin',
					tags: ['Node'],
					requestBody: bodyContent({
						address: 'string',
						amountSats: 'number',
						satsPerVbyte: 'number?'
					}),
					responses: { '200': { description: 'Transaction info' } }
				}
			},
			'/send-max': {
				post: {
					summary:
						'Sweep the entire spendable on-chain balance to one address (amount = balance minus fee)',
					tags: ['Node'],
					requestBody: bodyContent({
						address: 'string',
						satsPerVbyte: 'number?'
					}),
					responses: {
						'200': {
							description: 'Transaction info',
							content: jsonContent({ $ref: '#/components/schemas/TxInfo' })
						},
						'400': { description: 'Invalid address/fee rate or no UTXOs' }
					}
				}
			},
			'/tx/bump-fee': {
				post: {
					summary:
						'Replace an unconfirmed RBF-signalling wallet transaction with a higher-fee version (BIP 125)',
					tags: ['Node'],
					requestBody: bodyContent({
						txid: 'string',
						satsPerVbyte: 'number'
					}),
					responses: {
						'200': {
							description: 'Boost result',
							content: jsonContent({ $ref: '#/components/schemas/BoostResult' })
						},
						'400': { description: 'Invalid params' },
						'409': {
							description:
								'NOT_BOOSTABLE (unknown/confirmed/non-RBF tx; try /tx/boost for CPFP)'
						}
					}
				}
			},
			'/tx/boost': {
				post: {
					summary:
						'Fee-bump an unconfirmed wallet transaction: RBF when possible, otherwise CPFP',
					tags: ['Node'],
					requestBody: bodyContent({
						txid: 'string',
						satsPerVbyte: 'number?'
					}),
					responses: {
						'200': {
							description: 'Boost result',
							content: jsonContent({ $ref: '#/components/schemas/BoostResult' })
						},
						'400': { description: 'Invalid params' },
						'409': { description: 'NOT_BOOSTABLE' }
					}
				}
			},
			'/transactions/boostable': {
				get: {
					summary:
						'List unconfirmed wallet transactions eligible for RBF and/or CPFP fee bumping',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Boostable transactions by method',
							content: jsonContent({
								$ref: '#/components/schemas/BoostableTransactions'
							})
						}
					}
				}
			},
			'/consolidate': {
				post: {
					summary:
						'Merge all spendable UTXOs into a single output at a fresh wallet address (send-max-to-self)',
					tags: ['Node'],
					requestBody: bodyContent({ satsPerVbyte: 'number?' }),
					responses: {
						'200': {
							description: 'Consolidation result',
							content: jsonContent({
								$ref: '#/components/schemas/ConsolidateResult'
							})
						},
						'400': { description: 'Invalid params' },
						'409': {
							description: 'NOTHING_TO_CONSOLIDATE (fewer than 2 UTXOs)'
						}
					}
				}
			},
			'/psbt/build': {
				post: {
					summary:
						'Build an UNSIGNED PSBT for an external signer (hardware wallet); includes bip32 derivation metadata, nothing is signed or broadcast',
					tags: ['Node'],
					requestBody: bodyContent({
						outputs: 'array',
						satsPerVbyte: 'number?'
					}),
					responses: {
						'200': {
							description:
								'Unsigned PSBT (base64) with fee, vsize estimate and input/output summary'
						},
						'400': { description: 'Invalid outputs/fee rate or no UTXOs' }
					}
				}
			},
			'/psbt/import-signed': {
				post: {
					summary:
						'Validate and finalize an externally signed PSBT; returns { txid, txHex } WITHOUT broadcasting',
					tags: ['Node'],
					requestBody: bodyContent({ psbtBase64: 'string' }),
					responses: {
						'200': { description: 'Finalized transaction (not broadcast)' },
						'400': {
							description: 'PSBT_IMPORT_FAILED (missing/invalid signatures)'
						}
					}
				}
			},
			'/psbt/combine': {
				post: {
					summary:
						'Combine partially signed copies of the same PSBT (multi-party signing)',
					tags: ['Node'],
					requestBody: bodyContent({ psbts: 'array' }),
					responses: {
						'200': { description: 'Combined PSBT (base64)' },
						'400': { description: 'Fewer than two PSBTs or malformed input' }
					}
				}
			},
			'/readiness': {
				get: {
					summary: 'Get mainnet readiness report with weighted checks',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Readiness report',
							content: jsonContent({
								$ref: '#/components/schemas/ReadinessReport'
							})
						}
					}
				}
			},
			'/stats': {
				get: {
					summary: 'Get node statistics',
					tags: ['Node'],
					parameters: [
						{
							name: 'window',
							in: 'query',
							schema: { type: 'integer' },
							description:
								'Time window in milliseconds. Only payments created within this window are included.'
						}
					],
					responses: {
						'200': {
							description: 'Node stats',
							content: jsonContent({ $ref: '#/components/schemas/NodeStats' })
						}
					}
				}
			},
			'/liquidity': {
				get: {
					summary: 'Get liquidity snapshot with recommendations',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Liquidity snapshot',
							content: jsonContent({
								$ref: '#/components/schemas/LiquiditySnapshot'
							})
						}
					}
				}
			},
			'/advisor/recommendations': {
				get: {
					summary:
						'Liquidity analysis (advisor analyze) plus the concrete circular-rebalance plan',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Advisor recommendations',
							content: jsonContent({
								$ref: '#/components/schemas/AdvisorRecommendations'
							})
						}
					}
				}
			},
			'/advisor/execute-rebalances': {
				post: {
					summary:
						'Execute the advisor rebalance plan under a strict per-UTC-day routing-fee budget (persisted across restarts)',
					tags: ['Node'],
					requestBody: bodyContent({ budgetSatsPerDay: 'number?' }),
					responses: {
						'200': {
							description: 'Execution summary (msat values as strings)',
							content: jsonContent({
								$ref: '#/components/schemas/RebalanceExecutionSummary'
							})
						}
					}
				}
			},
			'/rebalance': {
				post: {
					summary:
						'Circular rebalance: self-payment out over fromChannelId and back in over toChannelId; aborts without paying if the route fee exceeds maxFeeSats',
					tags: ['Channels'],
					requestBody: bodyContent({
						fromChannelId: 'string',
						toChannelId: 'string',
						amountSats: 'number',
						maxFeeSats: 'number'
					}),
					responses: {
						'200': {
							description: 'Rebalance result',
							content: jsonContent({
								$ref: '#/components/schemas/RebalanceResult'
							})
						},
						'400': {
							description: 'No route, fee exceeds maxFeeSats, or invalid params'
						}
					}
				}
			},
			'/fees': {
				get: {
					summary:
						'Get on-chain fee rate snapshot with trend analysis and channel-open recommendation',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Fee snapshot',
							content: jsonContent({ $ref: '#/components/schemas/FeeSnapshot' })
						},
						'404': { description: 'NO_DATA, no fee samples recorded yet' }
					}
				}
			},
			'/fees/estimates': {
				get: {
					summary: 'Get current on-chain fee rate estimates in sats/vbyte',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Fee estimates',
							content: jsonContent({ $ref: '#/components/schemas/OnchainFees' })
						}
					}
				}
			},
			'/transactions': {
				get: {
					summary: 'List on-chain wallet transactions, newest first',
					tags: ['Node'],
					parameters: [
						{
							name: 'limit',
							in: 'query',
							schema: { type: 'integer' },
							description: 'Maximum number of transactions to return'
						}
					],
					responses: {
						'200': {
							description: 'On-chain transactions',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/OnchainTxInfo' }
							})
						},
						'400': { description: 'Invalid limit parameter' }
					}
				}
			},
			'/utxos': {
				get: {
					summary: 'List on-chain wallet UTXOs',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'UTXOs',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/UtxoInfo' }
							})
						}
					}
				}
			},
			'/channel/suggestions': {
				get: {
					summary:
						'Get channel open suggestions based on gossip graph analysis',
					tags: ['Channels'],
					parameters: [
						{
							name: 'count',
							in: 'query',
							schema: { type: 'integer', default: 5 },
							description: 'Maximum number of suggestions'
						}
					],
					responses: {
						'200': {
							description: 'Channel suggestions sorted by score',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ChannelSuggestion' }
							})
						}
					}
				}
			},
			'/logs': {
				get: {
					summary: 'Query persisted structured action log entries',
					tags: ['Node'],
					parameters: [
						{
							name: 'category',
							in: 'query',
							schema: {
								type: 'string',
								enum: ['payment', 'channel', 'htlc', 'fee', 'peer', 'chain']
							},
							description: 'Filter by log category'
						},
						{
							name: 'since',
							in: 'query',
							schema: { type: 'integer' },
							description: 'Filter entries from this timestamp (ms)'
						},
						{
							name: 'limit',
							in: 'query',
							schema: { type: 'integer', default: 1000 },
							description: 'Maximum number of entries to return'
						}
					],
					responses: {
						'200': {
							description: 'Action log entries',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/ActionLogEntry' }
							})
						}
					}
				}
			},
			'/metrics': {
				get: {
					summary: 'Prometheus-compatible metrics (auth-exempt)',
					tags: ['Node'],
					security: [],
					responses: {
						'200': {
							description: 'Prometheus text exposition format',
							content: { 'text/plain': { schema: { type: 'string' } } }
						}
					}
				}
			},
			'/events': {
				get: {
					summary:
						'Server-Sent Events stream (payment:received, payment:sent, payment:failed, invoice:settled, transaction:received, transaction:sent, transaction:confirmed, channel:opening, channel:ready, channel:pending-close, channel:force-closing, channel:closed, channel:resolved, peer:connect, peer:disconnect, node:ready, and the Recovery Protocol events recovery:durable, recovery:fenced, recovery:backfill-lost, recovery:reestablish-held, recovery:guardian_unreachable, recovery:restore-progress, recovery:restored; plus htlc:forwarded, htlc:fulfilled, htlc:failed when the daemon is started with htlcEvents)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'SSE stream',
							content: { 'text/event-stream': {} }
						}
					}
				}
			},
			'/stop': {
				post: {
					summary: 'Gracefully stop the daemon (supports drain mode)',
					tags: ['Node'],
					requestBody: bodyContent({
						'drain?': 'boolean',
						'drainTimeoutMs?': 'number'
					}),
					responses: {
						'200': {
							description: 'Stopped',
							content: jsonContent({
								type: 'object',
								properties: {
									stopped: { type: 'boolean' },
									drained: { type: 'boolean' }
								}
							})
						}
					}
				}
			},
			'/spend-limit': {
				get: {
					summary:
						'Get combined daily spending limit info (Lightning + external on-chain sends share one budget)',
					description:
						'The daily limit covers Lightning payments AND external on-chain sends (amount + fee). Consolidation, channel funding and fee bumps are excluded. spentSats mirrors totalSats for back-compat.',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Spending limit info with LN/onchain breakdown',
							content: jsonContent({
								type: 'object',
								properties: {
									limitSats: { type: 'integer', nullable: true },
									spentSats: { type: 'integer' },
									remainingSats: { type: 'number' },
									resetsAt: { type: 'integer' },
									totalSats: { type: 'integer' },
									lightningSats: { type: 'integer' },
									onchainSats: { type: 'integer' }
								}
							})
						}
					}
				}
			},
			'/utxo/freeze': {
				post: {
					summary:
						'Freeze a UTXO so coin selection cannot spend it until unfrozen',
					tags: ['Node'],
					requestBody: bodyContent({ txid: 'string', index: 'integer' }),
					responses: {
						'200': {
							description: 'Frozen outpoint',
							content: jsonContent({
								type: 'object',
								properties: { frozen: { type: 'string' } }
							})
						}
					}
				}
			},
			'/utxo/unfreeze': {
				post: {
					summary: 'Unfreeze a previously frozen UTXO',
					tags: ['Node'],
					requestBody: bodyContent({ txid: 'string', index: 'integer' }),
					responses: {
						'200': {
							description: 'Unfrozen outpoint',
							content: jsonContent({
								type: 'object',
								properties: { unfrozen: { type: 'string' } }
							})
						}
					}
				}
			},
			'/address/label': {
				post: {
					summary: 'Set a user label for an address (empty label clears it)',
					tags: ['Node'],
					requestBody: bodyContent({ address: 'string', label: 'string' }),
					responses: {
						'200': {
							description: 'Stored label',
							content: jsonContent({
								type: 'object',
								properties: {
									address: { type: 'string' },
									label: { type: 'string' }
								}
							})
						}
					}
				}
			},
			'/address/labels': {
				get: {
					summary: 'List all user address labels keyed by address',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Labels map',
							content: jsonContent({
								type: 'object',
								additionalProperties: { type: 'string' }
							})
						}
					}
				}
			},
			'/wallet/descriptors': {
				get: {
					summary:
						'Export BIP 380 output descriptors for the on-chain wallet (public keys only)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Descriptors',
							content: jsonContent({
								$ref: '#/components/schemas/DescriptorsInfo'
							})
						}
					}
				}
			},
			'/address/new': {
				post: {
					summary: 'Generate a new on-chain receiving address',
					description:
						'Pass bip21:true (with optional amountSats/label/message) to also receive the address encoded as a BIP21 payment URI.',
					tags: ['Node'],
					requestBody: bodyContent({
						bip21: 'boolean?',
						amountSats: 'integer?',
						label: 'string?',
						message: 'string?'
					}),
					responses: {
						'200': {
							description: 'New address',
							content: jsonContent({
								type: 'object',
								properties: {
									address: { type: 'string' },
									bip21: { type: 'string' }
								}
							})
						}
					}
				}
			},
			'/wallet/refresh': {
				post: {
					summary: 'Refresh on-chain wallet (rescan UTXOs)',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Refreshed',
							content: jsonContent({
								type: 'object',
								properties: { refreshed: { type: 'boolean' } }
							})
						}
					}
				}
			},
			'/mnemonic': {
				get: {
					summary: 'Get wallet mnemonic (requires API token)',
					description:
						'Seed generation is CLI-only: `beignet init` creates the mnemonic; the daemon never generates or replaces a seed. This endpoint only reveals the configured mnemonic, and only when apiToken is set (returns MNEMONIC_REQUIRES_AUTH otherwise).',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Mnemonic',
							content: jsonContent({
								type: 'object',
								properties: { mnemonic: { type: 'string' } }
							})
						}
					}
				}
			},
			'/peers/bootstrap': {
				post: {
					summary: 'Bootstrap peer connections via DNS seeds',
					tags: ['Peers'],
					responses: {
						'200': {
							description: 'Bootstrap result',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/BootstrapPeerInfo' }
							})
						}
					}
				}
			},
			'/peers/connect-seeds': {
				post: {
					summary: 'Connect to DNS seed peers',
					tags: ['Peers'],
					requestBody: bodyContent({ maxPeers: 'number?' }),
					responses: {
						'200': {
							description: 'Connected count',
							content: jsonContent({
								type: 'object',
								properties: { connected: { type: 'integer' } }
							})
						}
					}
				}
			},
			'/trusted-peer/add': {
				post: {
					summary: 'Add a trusted peer for zero-conf channels',
					tags: ['Peers'],
					requestBody: bodyContent({ pubkey: 'string' }),
					responses: {
						'200': {
							description: 'Trusted peer info',
							content: jsonContent({
								$ref: '#/components/schemas/TrustedPeerInfo'
							})
						}
					}
				}
			},
			'/trusted-peer/remove': {
				post: {
					summary: 'Remove a trusted peer',
					tags: ['Peers'],
					requestBody: bodyContent({ pubkey: 'string' }),
					responses: { '200': { description: 'Removed' } }
				}
			},
			'/trusted-peers': {
				get: {
					summary: 'List trusted peers',
					tags: ['Peers'],
					responses: {
						'200': {
							description: 'Trusted peer list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/TrustedPeerInfo' }
							})
						}
					}
				}
			},
			'/channel/open-zeroconf': {
				post: {
					summary: 'Open a zero-conf channel (requires trusted peer)',
					tags: ['Channels'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						pushSats: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						},
						'400': {
							description:
								'INVALID_PARAMS: the request cannot be served as written (fractional amount, push toward a dual-fund peer, out-of-range feerate)'
						},
						'409': {
							description:
								'FUNDING_PROVIDER_REQUIRED or INSUFFICIENT_BALANCE: the node cannot fund this open as things stand'
						},
						'503': {
							description:
								'FEE_ESTIMATE_NOT_READY: the estimator has not sampled yet, retry shortly'
						}
					}
				}
			},
			'/channel/open-v2': {
				post: {
					summary: 'Open a dual-funded (v2) channel',
					tags: ['Channels'],
					// Hand-written body: the lease params are nested objects,
					// which the flat bodyContent() helper cannot express
					// (issue #532 workstream 1B).
					requestBody: {
						content: {
							'application/json': {
								schema: {
									type: 'object',
									properties: {
										pubkey: { type: 'string' },
										amountSats: { type: 'number' },
										fundingFeeratePerkw: { type: 'number' },
										commitmentFeeratePerkw: { type: 'number' },
										locktime: { type: 'number' },
										requestFunds: {
											type: 'object',
											description:
												'Liquidity ads buyer (option_will_fund): ask the peer to lease this much inbound into the channel being opened. Requires maxLeaseRates.',
											properties: {
												requestedSats: {
													type: 'integer',
													minimum: 1
												},
												blockheight: {
													type: 'integer',
													minimum: 1,
													maximum: 4294967295,
													description:
														'Current chain tip height; the seller refuses a stale value'
												}
											},
											required: ['requestedSats', 'blockheight']
										},
										maxLeaseRates: {
											type: 'object',
											description:
												"The buyer's own price ceiling for the lease, compared as a computed total fee. Choose it locally; echoing the seller's advertised rates back makes any price acceptable. Field bounds are the option_will_fund wire widths.",
											properties: {
												fundingWeightWitness: {
													type: 'integer',
													minimum: 0,
													maximum: 65535
												},
												leaseFeeBasis: {
													type: 'integer',
													minimum: 0,
													maximum: 65535
												},
												leaseFeeBaseSat: {
													type: 'integer',
													minimum: 0,
													maximum: 4294967295
												},
												channelFeeMaxBaseMsat: {
													type: 'integer',
													minimum: 0,
													maximum: 4294967295
												},
												channelFeeMaxProportionalThousandths: {
													type: 'integer',
													minimum: 0,
													maximum: 65535
												}
											},
											required: [
												'fundingWeightWitness',
												'leaseFeeBasis',
												'leaseFeeBaseSat',
												'channelFeeMaxBaseMsat',
												'channelFeeMaxProportionalThousandths'
											]
										}
									},
									required: ['pubkey', 'amountSats'],
									// OpenAPI 3.0 has no dependentRequired, so the
									// "requestFunds needs maxLeaseRates" rule is the
									// 3.0-compatible implication: either no
									// requestFunds, or maxLeaseRates present.
									anyOf: [
										{ not: { required: ['requestFunds'] } },
										{ required: ['maxLeaseRates'] }
									]
								}
							}
						}
					},
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						},
						'400': {
							description:
								'INVALID_PARAMS: the request cannot be served as written (fractional amount, push toward a dual-fund peer, out-of-range feerate, requestFunds without maxLeaseRates, or a lease field outside its wire width)'
						},
						'409': {
							description:
								'FUNDING_PROVIDER_REQUIRED or INSUFFICIENT_BALANCE: the node cannot fund this open as things stand'
						},
						'503': {
							description:
								'FEE_ESTIMATE_NOT_READY: the estimator has not sampled yet, retry shortly'
						}
					}
				}
			},
			'/channel/funding-quote': {
				post: {
					summary:
						'Peer-aware max channel-funding quote: decides v1 vs v2 the same way openChannel does (both inits advertising option_dual_fund) and prices the max open with the exact formula that flow commits, so the previewed amount matches the opened channel',
					tags: ['Channels'],
					requestBody: bodyContent({
						peerPubkey: 'string',
						satsPerVbyte: 'number'
					}),
					responses: {
						'200': {
							description: 'Channel funding quote',
							content: jsonContent({
								type: 'object',
								properties: {
									method: { type: 'string', enum: ['v1', 'v2'] },
									peerKnown: {
										type: 'boolean',
										description:
											'false when the peer sent no init (not connected); the quote then falls back to the v1 sweep'
									},
									satsPerVbyte: { type: 'number' },
									fundingSatoshis: { type: 'number' },
									feeSats: { type: 'number' },
									feeratePerKw: {
										type: 'number',
										description: 'v2 only'
									},
									spendableSats: {
										type: 'number',
										description: 'v2 only'
									},
									inputCount: { type: 'number' },
									vsize: { type: 'number', description: 'v1 only' },
									maxSatsPerVbyte: {
										type: 'number',
										description: 'v1 only'
									}
								}
							})
						}
					}
				}
			},
			'/channel/splice-quote': {
				post: {
					summary:
						'Quote a splice: the on-chain fee and the largest amount that can move at this feerate (splice-in prices against spendable wallet UTXOs, splice-out against local balance net of the peer-set channel reserve)',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						direction: 'string',
						feeratePerkw: 'number'
					}),
					responses: {
						'200': {
							description: 'Splice quote',
							content: jsonContent({
								type: 'object',
								properties: {
									direction: { type: 'string', enum: ['in', 'out'] },
									feeSats: { type: 'number' },
									spendableSats: { type: 'number' },
									maxAmountSats: { type: 'number' },
									reserveSats: {
										type: 'number',
										description: 'splice-out only'
									},
									inputCount: {
										type: 'number',
										description: 'splice-in only'
									}
								}
							})
						},
						'409': {
							description:
								'FUNDING_PROVIDER_REQUIRED: no funding provider able to quote a splice-in'
						},
						'400': {
							description:
								'INVALID_PARAMS: malformed channelId, non-integer amount, or a feeratePerkw outside 1..4294967295'
						},
						'404': { description: 'CHANNEL_NOT_FOUND' }
					}
				}
			},
			'/channel/splice-in': {
				post: {
					summary: 'Splice funds into a channel',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						amountSats: 'number',
						feeratePerkw: 'number'
					}),
					responses: {
						'200': {
							description:
								'Splice started. The negotiation runs on: watch splice:complete / node:error for the outcome.',
							content: jsonContent({
								$ref: '#/components/schemas/SpliceResult'
							})
						},
						'400': {
							description:
								'INVALID_PARAMS: malformed channelId, non-integer amount, a feeratePerkw outside 1..4294967295, or an amount below the dust floor'
						},
						'404': { description: 'CHANNEL_NOT_FOUND' },
						'409': {
							description:
								'SPLICING_NOT_NEGOTIATED (option_splice/option_quiesce missing on either side), FUNDING_PROVIDER_REQUIRED (no wallet UTXO sourcing), or SPLICE_REFUSED (the channel would not start the splice)'
						},
						'503': {
							description:
								'SPLICE_BUSY: the channel is momentarily unable to splice (a previous abort awaiting its echo, a peer-owned quiescence session, another splice request already awaiting quiescence, HTLCs still settling, the peer reconnecting). Retry the same request.'
						}
					}
				}
			},
			'/channel/splice-out': {
				post: {
					summary: 'Splice funds out of a channel',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						amountSats: 'number',
						feeratePerkw: 'number',
						// Optional external destination (issue #534): the splice tx
						// pays this address directly. Omitted, funds go to the wallet.
						address: 'string?'
					}),
					responses: {
						'200': {
							description:
								'Splice started. The negotiation runs on: watch splice:complete / node:error for the outcome.',
							content: jsonContent({
								$ref: '#/components/schemas/SpliceResult'
							})
						},
						'400': {
							description:
								'INVALID_PARAMS: malformed channelId, non-integer amount, a feeratePerkw outside 1..4294967295, an address this network cannot decode, an amount below the channel dust floor, or a fee at or above the amount'
						},
						'403': {
							description:
								'SPENDING_LIMIT_EXCEEDED: an address-targeted splice-out over dailySpendLimitSats'
						},
						'404': { description: 'CHANNEL_NOT_FOUND' },
						'409': {
							description:
								'INSUFFICIENT_BALANCE (amount + fee above what the channel can spare), SPLICING_NOT_NEGOTIATED, or SPLICE_REFUSED (the channel would not start the splice)'
						},
						'503': {
							description:
								'SPLICE_BUSY: the channel is momentarily unable to splice (a previous abort awaiting its echo, a peer-owned quiescence session, another splice request already awaiting quiescence, HTLCs still settling, the peer reconnecting). Retry the same request.'
						}
					}
				}
			},
			'/node/wait-ready': {
				post: {
					summary:
						'Wait for node to be fully operational (peers reconnected, channels restored)',
					tags: ['Node'],
					requestBody: bodyContent({ timeoutMs: 'number?' }),
					responses: {
						'200': {
							description: 'Node ready',
							content: jsonContent({
								type: 'object',
								properties: { ready: { type: 'boolean' } }
							})
						}
					}
				}
			},
			'/channel/wait-ready': {
				post: {
					summary: 'Wait for a channel to become ready (NORMAL state)',
					tags: ['Channels'],
					requestBody: bodyContent({
						channelId: 'string',
						timeoutMs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel ready',
							content: jsonContent({
								type: 'object',
								properties: {
									channelId: { type: 'string' },
									ready: { type: 'boolean' }
								}
							})
						}
					}
				}
			},
			'/payment/wait': {
				post: {
					summary: 'Wait for a payment to settle',
					tags: ['Payments'],
					requestBody: bodyContent({
						paymentHash: 'string',
						timeoutMs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Payment result',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/payment/metadata': {
				post: {
					summary: 'Set metadata on a payment',
					tags: ['Payments'],
					requestBody: bodyContent({
						paymentHash: 'string',
						metadata: 'Record<string,string>'
					}),
					responses: { '200': { description: 'Updated' } }
				}
			},
			'/can-send': {
				get: {
					summary:
						'Check if node can send a given amount (accounts for channel reserves)',
					tags: ['Node'],
					parameters: [
						{ name: 'amountSats', in: 'query', schema: { type: 'integer' } }
					],
					responses: { '200': { description: 'Send capability' } }
				}
			},
			'/can-receive': {
				get: {
					summary:
						'Check if node can receive a given amount (accounts for channel reserves)',
					tags: ['Node'],
					parameters: [
						{ name: 'amountSats', in: 'query', schema: { type: 'integer' } }
					],
					responses: { '200': { description: 'Receive capability' } }
				}
			},
			'/offer/pay': {
				post: {
					summary: 'Pay a BOLT 12 offer',
					tags: ['Offers'],
					requestBody: bodyContent({
						offer: 'string',
						amountSats: 'number?',
						timeoutMs: 'number?'
					}),
					responses: {
						'200': {
							description: 'Payment result',
							content: jsonContent({ $ref: '#/components/schemas/PaymentInfo' })
						}
					}
				}
			},
			'/webhooks/register': {
				post: {
					summary:
						'Register a webhook for event notifications (persistent across restarts)',
					tags: ['Webhooks'],
					requestBody: bodyContent({
						url: 'string',
						events: 'string',
						secret: 'string?'
					}),
					responses: {
						'200': {
							description: 'Webhook registration',
							content: jsonContent({
								$ref: '#/components/schemas/WebhookRegistration'
							})
						}
					}
				}
			},
			'/webhooks/unregister': {
				delete: {
					summary: 'Unregister a webhook by ID',
					tags: ['Webhooks'],
					requestBody: bodyContent({ id: 'string' }),
					responses: {
						'200': { description: 'Webhook unregistered' },
						'404': { description: 'Webhook not found' }
					}
				}
			},
			'/webhooks': {
				get: {
					summary:
						'List all registered webhooks (includes webhooks restored from storage)',
					tags: ['Webhooks'],
					responses: {
						'200': {
							description: 'Webhook list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/WebhookRegistration' }
							})
						}
					}
				}
			},
			'/queue/add': {
				post: {
					summary:
						'Add a payment to the priority queue (persistent — survives restarts)',
					tags: ['Queue'],
					requestBody: bodyContent({
						bolt11: 'string',
						priority: 'number?',
						amountSats: 'number?',
						maxFeeSats: 'number?',
						metadata: 'Record<string,string>?'
					}),
					responses: {
						'200': {
							description: 'Queued payment',
							content: jsonContent({
								$ref: '#/components/schemas/QueuedPayment'
							})
						}
					}
				}
			},
			'/queue': {
				get: {
					summary:
						'List all payments in the queue (includes entries restored after restart)',
					tags: ['Queue'],
					responses: {
						'200': {
							description: 'Queue list',
							content: jsonContent({
								type: 'array',
								items: { $ref: '#/components/schemas/QueuedPayment' }
							})
						}
					}
				}
			},
			'/queue/cancel': {
				post: {
					summary: 'Cancel a queued payment',
					tags: ['Queue'],
					requestBody: bodyContent({ id: 'string' }),
					responses: {
						'200': { description: 'Payment cancelled' },
						'404': {
							description: 'Queued payment not found or already processing'
						}
					}
				}
			},
			'/auth/keys': {
				get: {
					summary: 'List named API keys (admin scope; never returns secrets)',
					tags: ['Auth'],
					responses: {
						'200': {
							description:
								'Key names with their scopes, revoked/expired flags, and expiresAt/rotatedAt when set',
							content: jsonContent({
								type: 'object',
								properties: {
									keys: {
										type: 'array',
										items: {
											type: 'object',
											properties: {
												name: { type: 'string' },
												scopes: {
													type: 'array',
													items: {
														type: 'string',
														enum: ['readonly', 'invoice', 'admin']
													}
												},
												revoked: { type: 'boolean' },
												expired: { type: 'boolean' },
												expiresAt: {
													type: 'string',
													description:
														'ISO 8601 expiry, present only when configured'
												},
												rotatedAt: {
													type: 'string',
													description:
														'ISO 8601 time of the last rotation, present only when the key was ever rotated'
												}
											}
										}
									}
								}
							})
						}
					}
				}
			},
			'/auth/keys/revoke': {
				post: {
					summary:
						'Revoke a named API key, effective immediately (admin scope)',
					description:
						'The revocation is persisted in the node database and survives daemon restarts; removing the key from the config file remains the ultimate cleanup. The legacy apiToken has no name and cannot be revoked here.',
					tags: ['Auth'],
					requestBody: bodyContent({ name: 'string' }),
					responses: {
						'200': { description: 'Key revoked' },
						'404': { description: 'No key with that name' }
					}
				}
			},
			'/auth/keys/rotate': {
				post: {
					summary:
						'Rotate a named API key: mint a new random secret (admin scope)',
					description:
						'Replaces the secret of the named key with a cryptographically random 32-byte hex secret. The old secret stops authenticating immediately; scopes are unchanged. The new secret is returned ONCE in this response and cannot be retrieved again (only its SHA-256 digest is persisted, so the rotation survives restarts). Rotating a revoked key reinstates it under the new secret. Editing the secret of a key in the config file discards the stored rotation on next start (config wins). The legacy apiToken has no name and cannot be rotated; change it in the config and restart.',
					tags: ['Auth'],
					requestBody: bodyContent({ name: 'string' }),
					responses: {
						'200': {
							description: 'New secret, shown only once; store it now',
							content: jsonContent({
								type: 'object',
								properties: {
									name: { type: 'string' },
									key: {
										type: 'string',
										description:
											'The new secret (64 hex chars). Shown only in this response.'
									},
									rotatedAt: { type: 'string' },
									warning: { type: 'string' }
								}
							})
						},
						'404': { description: 'No key with that name' }
					}
				}
			}
		},
		components: {
			securitySchemes: {
				bearerAuth: {
					type: 'http',
					scheme: 'bearer',
					description:
						'Legacy apiToken (implicit admin scope) or the secret of a named scoped API key from the apiKeys config. Routes advertise the scopes they accept via x-accepted-scopes; 401 = bad/absent key, 403 = valid key without a required scope.'
				}
			},
			schemas: {
				ApiEnvelope: {
					type: 'object',
					description: 'All responses use this envelope format',
					properties: {
						ok: {
							type: 'boolean',
							description: 'true on success, false on error'
						},
						result: { description: 'Response payload (present when ok=true)' },
						error: {
							type: 'object',
							properties: {
								code: {
									type: 'string',
									description: 'Machine-readable error code'
								},
								message: {
									type: 'string',
									description: 'Human-readable error message'
								}
							},
							description: 'Error details (present when ok=false)'
						}
					},
					required: ['ok']
				},
				NodeInfo: {
					type: 'object',
					properties: {
						nodeId: { type: 'string' },
						alias: { type: 'string' },
						network: { type: 'string' },
						blockHeight: { type: 'integer' },
						onchainBalanceSats: { type: 'integer' },
						lightningBalanceSats: { type: 'integer' },
						pendingCloseBalanceSats: { type: 'integer' },
						erroredBalanceSats: { type: 'integer' },
						splicingBalanceSats: {
							type: 'integer',
							description:
								'Splice-in-transit funds: for channels paying through their splice, only what is still arriving; for parked mid-splice channels, the whole settle-to balance. Rejoins lightningBalanceSats at splice_locked'
						},
						channelCount: {
							type: 'integer',
							description:
								'Every known channel row, including CLOSED/FORCE_CLOSED ones kept for history. Use openChannelCount for operating channels'
						},
						openChannelCount: {
							type: 'integer',
							description:
								'Channels not in a terminal state (CLOSED, FORCE_CLOSED, ERRORED)'
						},
						peerCount: { type: 'integer' },
						listening: { type: 'boolean' }
					}
				},
				BalanceInfo: {
					type: 'object',
					properties: {
						onchain: { type: 'integer' },
						lightning: { type: 'integer' },
						total: { type: 'integer' },
						unsettledSats: { type: 'integer' },
						splicingSats: {
							type: 'integer',
							description:
								'Splice-in-transit funds (see splicingBalanceSats); rejoins lightning at splice_locked. Excluded from total, which counts only currently spendable funds'
						}
					}
				},
				OnchainTxInfo: {
					type: 'object',
					properties: {
						txid: { type: 'string' },
						type: { type: 'string', enum: ['sent', 'received'] },
						valueSats: { type: 'integer' },
						feeSats: { type: 'integer' },
						satsPerVbyte: { type: 'number' },
						address: { type: 'string' },
						height: { type: 'integer' },
						confirmed: { type: 'boolean' },
						timestamp: { type: 'integer' },
						confirmTimestamp: { type: 'integer' }
					}
				},
				UtxoInfo: {
					type: 'object',
					properties: {
						txid: { type: 'string' },
						vout: { type: 'integer' },
						address: { type: 'string' },
						valueSats: { type: 'integer' },
						height: { type: 'integer' },
						frozen: {
							type: 'boolean',
							description:
								'Frozen UTXOs are excluded from coin selection until unfrozen'
						}
					}
				},
				DescriptorsInfo: {
					type: 'object',
					description:
						'BIP 380 output descriptors (with checksums). Public keys only; private keys are never exported.',
					properties: {
						fingerprint: { type: 'string' },
						network: { type: 'string' },
						account: { type: 'integer' },
						birthdayHeight: { type: 'integer' },
						watchOnly: { type: 'boolean' },
						descriptors: {
							type: 'array',
							items: {
								type: 'object',
								properties: {
									addressType: { type: 'string' },
									external: { type: 'string' },
									internal: { type: 'string' }
								}
							}
						}
					}
				},
				OnchainFees: {
					type: 'object',
					description:
						'Fee rate estimates in sats/vbyte by confirmation target',
					properties: {
						fast: { type: 'number' },
						normal: { type: 'number' },
						slow: { type: 'number' },
						minimum: { type: 'number' },
						timestamp: { type: 'integer' }
					}
				},
				ForwardingEvent: {
					type: 'object',
					description:
						'One settled forward. Msat values are decimal strings (JSON-safe bigint).',
					properties: {
						id: { type: 'integer' },
						settledAt: { type: 'integer' },
						inChannelId: { type: 'string' },
						outChannelId: { type: 'string' },
						inScid: { type: 'string' },
						outScid: { type: 'string' },
						amountInMsat: { type: 'string' },
						amountOutMsat: { type: 'string' },
						feeMsat: { type: 'string' }
					}
				},
				ForwardingSummary: {
					type: 'object',
					properties: {
						count: { type: 'integer' },
						volumeOutMsat: { type: 'string' },
						feesEarnedMsat: { type: 'string' }
					}
				},
				WatchtowerInfo: {
					type: 'object',
					properties: {
						uri: { type: 'string' },
						pubkey: { type: 'string' },
						connected: { type: 'boolean' },
						sessions: { type: 'integer' },
						pendingBacklog: { type: 'integer' },
						lastAck: { type: 'integer', nullable: true }
					}
				},
				HealthInfo: {
					type: 'object',
					properties: {
						status: { type: 'string', enum: ['ready', 'syncing', 'degraded'] },
						uptime: { type: 'integer' },
						blockHeight: { type: 'integer' },
						electrumConnected: { type: 'boolean' },
						peerCount: { type: 'integer' },
						channelCount: { type: 'integer' },
						readyChannelCount: { type: 'integer' },
						graphNodes: { type: 'integer' },
						graphChannels: { type: 'integer' }
					}
				},
				PeerInfo: {
					type: 'object',
					properties: {
						pubkey: { type: 'string' },
						host: { type: 'string' },
						port: { type: 'integer' },
						state: {
							type: 'string',
							enum: ['connected', 'connecting', 'disconnected']
						}
					}
				},
				ChannelInfo: {
					type: 'object',
					properties: {
						channelId: { type: 'string' },
						peerPubkey: { type: 'string' },
						state: {
							type: 'string',
							enum: [
								'NONE',
								'AWAITING_FUNDING_CONFIRMED',
								'AWAITING_CHANNEL_READY',
								'NORMAL',
								'SHUTTING_DOWN',
								'NEGOTIATING_CLOSING',
								'FORCE_CLOSED',
								'AWAITING_REESTABLISH',
								'CLOSED',
								'ERRORED',
								'ANNOUNCEMENT_READY'
							]
						},
						localBalanceSats: { type: 'integer' },
						remoteBalanceSats: { type: 'integer' },
						capacitySats: { type: 'integer' },
						isAnchor: { type: 'boolean' },
						isPrivate: { type: 'boolean' },
						fundingTxid: { type: 'string' },
						shortChannelId: { type: 'string' },
						feeratePerKw: { type: 'integer' },
						htlcCount: { type: 'integer' },
						pendingSpliceLocalBalanceSats: {
							type: 'integer',
							description:
								'Local balance the channel settles to when its in-flight splice locks; present only mid-splice (localBalanceSats stays pre-splice until splice_locked)'
						},
						htlcUsable: {
							type: 'boolean',
							description:
								'Whether the channel will accept a NEW HTLC: usable right now (NORMAL, or paying through its splice) and its state provably current. A channel answering false can still settle the HTLCs it already has'
						},
						restoreRecencyUnproven: {
							type: 'boolean',
							description:
								'The channel was restored from a Recovery Capsule and no channel_reestablish has proven its state current, so it takes no new HTLCs and is offered to no router. Existing HTLCs still settle; a cooperative close is refused in both directions without the acceptStaleStateRisk acknowledgement on /channel/close. Present only while the hold stands'
						},
						fundingUnaccounted: {
							type: 'boolean',
							description:
								'Neither mempool nor chain can account for the funding transaction and this node has no broadcast left to answer with, so the channel is quarantined: no new HTLCs, no router edge, no routing hint. Existing HTLCs still settle and a close still negotiates. Reversible and not a forget decision: it clears by itself when the funding is seen again. Present only while the quarantine stands'
						},
						peerSupportsSplicing: {
							type: 'boolean',
							description:
								'Whether the connected peer negotiated option_splice + option_quiesce. Absent when the peer is disconnected or mid-handshake: absence means unknown, never unsupported'
						},
						payThroughSplice: {
							type: 'boolean',
							description:
								'Present exactly when mid-splice by effective state: true = paying through the splice, false = parked'
						},
						feeBaseMsat: { type: 'integer' },
						feeProportionalMillionths: { type: 'integer' },
						cltvExpiryDelta: { type: 'integer' },
						htlcMinimumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						htlcMaximumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						closeStatus: { $ref: '#/components/schemas/CloseStatus' }
					}
				},
				CloseStatus: {
					type: 'object',
					description:
						'Close progress; present for closing/closed channels (SHUTTING_DOWN, NEGOTIATING_CLOSING, CLOSED, FORCE_CLOSED, and ERRORED with an on-chain funding output)',
					properties: {
						closer: {
							type: 'string',
							enum: ['local', 'remote', 'cooperative', 'unknown'],
							description: 'Who published (or is negotiating) the close'
						},
						reason: {
							type: 'string',
							description:
								'Why we closed: user for an API-initiated close, otherwise the automatic close code (e.g. REESTABLISH_TIMEOUT_FORCE_CLOSED). Absent for a close the peer initiated'
						},
						closingTxid: {
							type: 'string',
							description:
								'Txid of the commitment or mutual close transaction, when known'
						},
						broadcast: {
							type: 'boolean',
							description:
								'Whether the daemon believes the close tx reached the network: the last broadcast attempt succeeded or the spend was observed on chain'
						},
						confirmationHeight: {
							type: 'integer',
							description:
								'Block height the close confirmed at; 0 while unconfirmed'
						},
						resolution: {
							type: 'string',
							enum: ['pending', 'sweeping', 'resolved'],
							description:
								'On-chain resolution progress: pending until the close tx confirms, sweeping while outputs are swept and/or the close waits out its anti-reorg depth, resolved once irrevocable'
						},
						fundsAvailableHeight: {
							type: 'integer',
							description:
								'Height at which the to_local CSV matures and our main balance becomes spendable; only present for our own force close once computable'
						}
					}
				},
				ChannelPolicy: {
					type: 'object',
					properties: {
						channelId: { type: 'string' },
						feeBaseMsat: { type: 'integer' },
						feeProportionalMillionths: { type: 'integer' },
						cltvExpiryDelta: { type: 'integer' },
						htlcMinimumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						htlcMaximumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						source: { type: 'string', enum: ['override', 'default'] }
					}
				},
				PaymentInfo: {
					type: 'object',
					properties: {
						paymentHash: { type: 'string' },
						preimage: { type: 'string' },
						amountSats: { type: 'integer' },
						feeSats: { type: 'integer' },
						status: {
							type: 'string',
							enum: ['PENDING', 'COMPLETED', 'FAILED']
						},
						direction: { type: 'string', enum: ['OUTGOING', 'INCOMING'] },
						failureCode: { type: 'integer' },
						failureDescription: { type: 'string' },
						createdAt: { type: 'integer' },
						completedAt: { type: 'integer' },
						metadata: { type: 'object' },
						route: {
							type: 'object',
							description: 'Route taken for outbound payments',
							properties: {
								hops: {
									type: 'array',
									items: {
										type: 'object',
										properties: {
											pubkey: { type: 'string' },
											shortChannelId: { type: 'string' },
											feeMsat: { type: 'integer' }
										}
									}
								},
								totalFeeMsat: { type: 'integer' },
								hopCount: { type: 'integer' }
							}
						}
					}
				},
				InvoiceInfo: {
					type: 'object',
					properties: {
						bolt11: { type: 'string' },
						paymentHash: { type: 'string' },
						paymentSecret: {
							type: 'string',
							description:
								'Payment secret (hex) for correlating incoming payments'
						},
						amountSats: { type: 'integer' },
						description: { type: 'string' },
						expiry: { type: 'integer' },
						createdAt: { type: 'integer' },
						status: { type: 'string', enum: ['PENDING', 'PAID', 'EXPIRED'] }
					}
				},
				HoldInvoiceInfo: {
					type: 'object',
					properties: {
						paymentHash: { type: 'string' },
						bolt11: { type: 'string' },
						state: {
							type: 'string',
							enum: ['OPEN', 'ACCEPTED', 'SETTLED', 'CANCELLED']
						},
						heldAmountMsat: {
							type: 'string',
							description: 'Total msat currently parked'
						},
						htlcCount: { type: 'integer' },
						amountSats: { type: 'integer' },
						description: { type: 'string' },
						expiry: { type: 'integer' },
						createdAt: { type: 'integer' }
					}
				},
				DirectFundingConfig: {
					type: 'object',
					properties: {
						lspPubkey: {
							type: 'string',
							nullable: true,
							description:
								'The liquidity peer every direct-funded channel is negotiated with. Null means this node serves no offers'
						},
						lspHost: { type: 'string', nullable: true },
						lspPort: { type: 'integer', nullable: true },
						targetInboundSat: {
							type: 'integer',
							description:
								'Inbound the operator would like bought alongside. Recorded and reported; nothing consumes it yet'
						},
						trusted: {
							type: 'boolean',
							description: 'Whether a direct-funded open may go zero-conf'
						},
						minAmountSat: {
							type: 'integer',
							description:
								'Smallest offer served, never below the 5000 sat protocol floor'
						}
					}
				},
				DirectFundingSendResult: {
					type: 'object',
					properties: {
						offerId: { type: 'string' },
						spentTxid: { type: 'string' },
						spentVout: { type: 'integer' },
						amountSat: { type: 'integer' },
						fundingTxid: { type: 'string' },
						attested: {
							type: 'boolean',
							description:
								'True once the receiver node-key attestation over the funding output verified against the node the payment request named'
						},
						receiptPreimageHex: {
							type: 'string',
							nullable: true,
							description:
								'The delivery receipt. Null when it did not arrive in time, which is not a failure: delivery is chain-atomic by then'
						},
						rawTxHex: { type: 'string' },
						broadcastTxHex: { type: 'string' },
						status: {
							type: 'string',
							enum: [
								'CREATED',
								'OFFERED',
								'SIGNED_PENDING',
								'MEMPOOL_SEEN',
								'CONFIRMED',
								'ABORTED',
								'FAILED'
							]
						},
						caveat: {
							type: 'string',
							description:
								'What went wrong AFTER the witness left. The call resolves in that case, so this is the only place a caller learns of it'
						}
					}
				},
				OfferInfo: {
					type: 'object',
					properties: {
						offerId: { type: 'string' },
						description: { type: 'string' },
						encoded: { type: 'string' },
						amountSats: { type: 'integer' },
						issuer: { type: 'string' },
						issuerId: { type: 'string' },
						quantityMax: { type: 'integer' },
						absoluteExpiry: { type: 'integer' }
					}
				},
				NodeStats: {
					type: 'object',
					properties: {
						totalPaymentsSent: { type: 'integer' },
						totalPaymentsReceived: { type: 'integer' },
						totalPaymentsFailed: { type: 'integer' },
						totalSatsSent: { type: 'integer' },
						totalSatsReceived: { type: 'integer' },
						totalFeesPaid: { type: 'integer' },
						successRate: { type: 'number' },
						uptimeMs: { type: 'integer' },
						windowMs: {
							type: 'integer',
							description:
								'Time window in milliseconds (present only when window query param is specified)'
						},
						avgPaymentTimeSec: {
							type: 'number',
							description:
								'Average payment completion time in seconds (present only when completed payments with timing data exist)'
						},
						avgFeePct: {
							type: 'number',
							description:
								'Average fee as percentage of payment amount (present only when completed payments with fee data exist)'
						}
					}
				},
				PaymentProof: {
					type: 'object',
					properties: {
						paymentHash: { type: 'string' },
						preimage: { type: 'string' },
						amountSats: { type: 'number' },
						completedAt: { type: 'number' },
						invoice: { type: 'string' },
						hopCount: { type: 'number' },
						feeSats: { type: 'number' }
					},
					required: ['paymentHash', 'preimage', 'amountSats', 'completedAt']
				},
				PaymentProofVerification: {
					type: 'object',
					properties: {
						valid: {
							type: 'boolean',
							description: 'Whether the preimage matches the payment hash'
						},
						proof: { $ref: '#/components/schemas/PaymentProof' },
						error: {
							type: 'string',
							description: 'Error message if verification failed'
						}
					},
					required: ['valid']
				},
				RouteEstimate: {
					type: 'object',
					properties: {
						feeSats: { type: 'integer' },
						hops: { type: 'integer' },
						cltvDelta: { type: 'integer' }
					}
				},
				GraphInfo: {
					type: 'object',
					properties: {
						nodeCount: { type: 'integer' },
						channelCount: { type: 'integer' },
						lastSyncAt: {
							type: 'integer',
							description:
								'Epoch ms of the last gossip/RGS sync this session, if any'
						}
					}
				},
				GraphChannelPolicy: {
					type: 'object',
					description: "One direction's routing policy from a channel_update",
					properties: {
						feeBaseMsat: { type: 'integer' },
						feeProportionalMillionths: { type: 'integer' },
						cltvExpiryDelta: { type: 'integer' },
						htlcMinimumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						htlcMaximumMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						disabled: { type: 'boolean' },
						lastUpdate: {
							type: 'integer',
							description: 'channel_update timestamp (seconds)'
						}
					}
				},
				GraphChannelInfo: {
					type: 'object',
					properties: {
						shortChannelId: {
							type: 'string',
							description: '<block>x<txIndex>x<outputIndex>'
						},
						node1Pubkey: { type: 'string' },
						node2Pubkey: { type: 'string' },
						capacitySats: {
							type: 'integer',
							description:
								'Best-known lower bound from htlc_maximum_msat (capacity is not gossiped)'
						},
						node1Policy: {
							$ref: '#/components/schemas/GraphChannelPolicy'
						},
						node2Policy: {
							$ref: '#/components/schemas/GraphChannelPolicy'
						}
					}
				},
				GraphNodeInfo: {
					type: 'object',
					properties: {
						pubkey: { type: 'string' },
						alias: { type: 'string' },
						color: { type: 'string' },
						addresses: {
							type: 'array',
							items: {
								type: 'object',
								properties: {
									type: { type: 'integer' },
									host: { type: 'string' },
									port: { type: 'integer' }
								}
							}
						},
						featuresHex: { type: 'string' },
						lastUpdate: {
							type: 'integer',
							description: 'node_announcement timestamp (seconds)'
						},
						channelCount: { type: 'integer' },
						channels: { type: 'array', items: { type: 'string' } }
					}
				},
				RouteHop: {
					type: 'object',
					properties: {
						pubkey: { type: 'string' },
						shortChannelId: {
							type: 'string',
							description:
								'<block>x<txIndex>x<outputIndex> (16-char hex also accepted on input)'
						},
						amountToForwardMsat: {
							type: 'string',
							description: 'Msat as decimal string'
						},
						outgoingCltvValue: {
							type: 'integer',
							description:
								'RELATIVE CLTV delta from pathfinding (absolute height added at send)'
						},
						feeMsat: {
							type: 'string',
							description: 'Fee this hop charges, msat as decimal string'
						},
						cltvExpiryDelta: { type: 'integer' }
					},
					required: [
						'pubkey',
						'shortChannelId',
						'amountToForwardMsat',
						'outgoingCltvValue'
					]
				},
				RouteQueryResult: {
					type: 'object',
					properties: {
						destination: { type: 'string' },
						amountSats: { type: 'integer' },
						hops: {
							type: 'array',
							items: { $ref: '#/components/schemas/RouteHop' }
						},
						totalAmountMsat: { type: 'string' },
						totalFeeMsat: { type: 'string' },
						totalCltvDelta: { type: 'integer' },
						finalCltvExpiry: { type: 'integer' }
					}
				},
				TxInfo: {
					type: 'object',
					properties: {
						txid: { type: 'string' },
						hex: { type: 'string' }
					}
				},
				BoostResult: {
					type: 'object',
					properties: {
						txid: {
							type: 'string',
							description: 'Replacement (RBF) or child (CPFP) txid'
						},
						hex: { type: 'string' },
						boostType: { type: 'string', enum: ['rbf', 'cpfp'] },
						feeSats: { type: 'integer' },
						originalTxid: { type: 'string' }
					}
				},
				BoostableTransactions: {
					type: 'object',
					properties: {
						rbf: {
							type: 'array',
							items: { $ref: '#/components/schemas/OnchainTxInfo' }
						},
						cpfp: {
							type: 'array',
							items: { $ref: '#/components/schemas/OnchainTxInfo' }
						}
					}
				},
				ConsolidateResult: {
					type: 'object',
					properties: {
						txid: { type: 'string' },
						hex: { type: 'string' },
						utxosConsolidated: { type: 'integer' },
						address: {
							type: 'string',
							description: 'Fresh wallet address holding the merged output'
						},
						feeSats: { type: 'integer' }
					}
				},
				SpliceResult: {
					type: 'object',
					description:
						'A started splice. Refusals are answered as failure envelopes with their own status, so `ok` is always true here.',
					properties: {
						ok: { type: 'boolean', enum: [true] }
					}
				},
				BootstrapPeerInfo: {
					type: 'object',
					properties: {
						pubkey: { type: 'string' },
						host: { type: 'string' },
						port: { type: 'integer' }
					}
				},
				TrustedPeerInfo: {
					type: 'object',
					properties: {
						pubkey: { type: 'string' },
						trusted: { type: 'boolean' }
					}
				},
				LiquiditySnapshot: {
					type: 'object',
					properties: {
						totalLocalBalanceSats: {
							type: 'integer',
							description: 'Total outbound capacity in satoshis'
						},
						totalRemoteBalanceSats: {
							type: 'integer',
							description: 'Total inbound capacity in satoshis'
						},
						totalCapacitySats: {
							type: 'integer',
							description: 'Total channel capacity in satoshis'
						},
						channelCount: {
							type: 'integer',
							description: 'Total number of channels'
						},
						activeChannelCount: {
							type: 'integer',
							description: 'Number of NORMAL channels'
						},
						outboundLiquidityPct: {
							type: 'integer',
							description: 'Outbound liquidity percentage (0-100)'
						},
						inboundLiquidityPct: {
							type: 'integer',
							description: 'Inbound liquidity percentage (0-100)'
						},
						reserveSats: {
							type: 'integer',
							description:
								'Total local balance held back as channel reserve, unspendable (sats)'
						},
						sendableSats: {
							type: 'integer',
							description:
								'Local balance above the reserve, i.e. what can actually be sent (sats); zero while below the reserve'
						},
						recommendations: {
							type: 'array',
							items: { $ref: '#/components/schemas/LiquidityRecommendation' },
							description: 'Actionable recommendations'
						}
					}
				},
				RebalancePlan: {
					type: 'object',
					properties: {
						fromChannelId: {
							type: 'string',
							description: 'Channel to push liquidity out of'
						},
						toChannelId: {
							type: 'string',
							description: 'Channel to pull liquidity in on'
						},
						amountSats: { type: 'integer' },
						reason: { type: 'string' }
					},
					required: ['fromChannelId', 'toChannelId', 'amountSats', 'reason']
				},
				AdvisorRecommendations: {
					allOf: [
						{ $ref: '#/components/schemas/LiquiditySnapshot' },
						{
							type: 'object',
							properties: {
								rebalancePlan: {
									type: 'array',
									items: { $ref: '#/components/schemas/RebalancePlan' },
									description:
										'Circular rebalances the executor would run (nothing is executed by this endpoint)'
								}
							}
						}
					]
				},
				RebalanceResult: {
					type: 'object',
					properties: {
						paymentHash: { type: 'string' },
						amountSats: { type: 'integer' },
						feeMsat: {
							type: 'string',
							description: 'Routing fee paid, msat as decimal string'
						},
						feeSats: { type: 'integer' },
						hops: { type: 'integer' }
					},
					required: ['paymentHash', 'amountSats', 'feeMsat', 'feeSats', 'hops']
				},
				RebalanceExecutionSummary: {
					type: 'object',
					properties: {
						attempts: {
							type: 'array',
							items: {
								type: 'object',
								properties: {
									fromChannelId: { type: 'string' },
									toChannelId: { type: 'string' },
									amountSats: { type: 'integer' },
									status: {
										type: 'string',
										enum: ['SUCCEEDED', 'FAILED', 'SKIPPED_BUDGET']
									},
									feeMsat: { type: 'string' },
									error: { type: 'string' }
								}
							}
						},
						succeeded: { type: 'integer' },
						failed: { type: 'integer' },
						skippedBudget: { type: 'integer' },
						feeSpentMsat: {
							type: 'string',
							description: 'Fees spent by this run, msat as decimal string'
						},
						budgetRemainingMsat: {
							type: 'string',
							description: 'Remaining budget for the current UTC day'
						}
					}
				},
				LiquidityRecommendation: {
					type: 'object',
					properties: {
						type: {
							type: 'string',
							enum: ['OPEN_CHANNEL', 'CLOSE_CHANNEL', 'REBALANCE_NEEDED']
						},
						priority: {
							type: 'string',
							enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
						},
						reason: {
							type: 'string',
							description: 'Human-readable explanation'
						},
						channelId: {
							type: 'string',
							description: 'Channel ID (for channel-specific recommendations)'
						}
					},
					required: ['type', 'priority', 'reason']
				},
				WebhookRegistration: {
					type: 'object',
					properties: {
						id: { type: 'string', description: 'Unique webhook ID' },
						url: { type: 'string', description: 'URL to POST events to' },
						events: {
							type: 'array',
							items: { type: 'string' },
							description: 'Subscribed event types'
						},
						secret: {
							type: 'string',
							description: 'Masked secret (if configured)'
						},
						createdAt: {
							type: 'integer',
							description: 'Registration timestamp (ms)'
						}
					},
					required: ['id', 'url', 'events', 'createdAt']
				},
				QueuedPayment: {
					type: 'object',
					properties: {
						id: { type: 'string', description: 'Unique queue entry ID' },
						bolt11: { type: 'string', description: 'BOLT 11 invoice' },
						priority: {
							type: 'integer',
							description: 'Priority 1 (highest) to 10 (lowest)'
						},
						status: {
							type: 'string',
							enum: [
								'queued',
								'dispatching',
								'completed',
								'failed',
								'cancelled'
							]
						},
						amountSats: {
							type: 'integer',
							description: 'Payment amount in satoshis'
						},
						maxFeeSats: {
							type: 'integer',
							description: 'Maximum fee in satoshis'
						},
						metadata: {
							type: 'object',
							additionalProperties: { type: 'string' }
						},
						error: { type: 'string', description: 'Error message if failed' },
						createdAt: {
							type: 'integer',
							description: 'Creation timestamp (ms)'
						},
						completedAt: {
							type: 'integer',
							description: 'Completion timestamp (ms)'
						}
					},
					required: ['id', 'bolt11', 'priority', 'status', 'createdAt']
				},
				ActionLogEntry: {
					type: 'object',
					properties: {
						category: {
							type: 'string',
							enum: ['payment', 'channel', 'htlc', 'fee', 'peer', 'chain'],
							description: 'Log category'
						},
						action: {
							type: 'string',
							description: 'Action name (e.g. sent, received, ready)'
						},
						timestamp: {
							type: 'integer',
							description: 'Timestamp in milliseconds'
						},
						data: { type: 'object', description: 'Structured event data' }
					},
					required: ['category', 'action', 'timestamp', 'data']
				},
				ReadinessCheck: {
					type: 'object',
					properties: {
						name: { type: 'string' },
						status: { type: 'string', enum: ['PASS', 'WARN', 'FAIL'] },
						severity: { type: 'string', enum: ['CRITICAL', 'WARNING', 'INFO'] },
						message: { type: 'string' }
					},
					required: ['name', 'status', 'severity', 'message']
				},
				ReadinessReport: {
					type: 'object',
					properties: {
						score: {
							type: 'number',
							description: 'Weighted pass rate (0-100)'
						},
						ready: {
							type: 'boolean',
							description: 'True if no CRITICAL checks have failed'
						},
						checks: {
							type: 'array',
							items: { $ref: '#/components/schemas/ReadinessCheck' },
							description: 'Individual readiness checks'
						}
					},
					required: ['score', 'ready', 'checks']
				},
				ChannelHealth: {
					type: 'object',
					properties: {
						channelId: { type: 'string' },
						state: { type: 'string' },
						localBalancePct: {
							type: 'number',
							description: 'Local balance as percentage of capacity (0-100)'
						},
						remoteBalancePct: {
							type: 'number',
							description: 'Remote balance as percentage of capacity (0-100)'
						},
						htlcCount: {
							type: 'integer',
							description: 'Number of active HTLCs'
						},
						maxHtlcs: { type: 'integer', description: 'Maximum HTLCs allowed' },
						capacitySats: {
							type: 'integer',
							description: 'Total channel capacity in satoshis'
						},
						warnings: {
							type: 'array',
							items: {
								type: 'string',
								enum: [
									'LOW_OUTBOUND_LIQUIDITY',
									'LOW_INBOUND_LIQUIDITY',
									'HTLC_SLOTS_NEARLY_FULL',
									'AWAITING_REESTABLISH'
								]
							},
							description: 'Active health warnings'
						}
					}
				},
				PaymentEstimate: {
					type: 'object',
					properties: {
						successProbabilityPct: {
							type: 'integer',
							description: 'Estimated success probability (0-100)'
						},
						estimatedTimeMs: {
							type: 'integer',
							description: 'Estimated settlement time in milliseconds'
						},
						routeQuality: {
							type: 'string',
							enum: ['HIGH', 'MEDIUM', 'LOW'],
							description: 'Route quality assessment'
						},
						warning: {
							type: 'string',
							description: 'Warning message (if any)'
						},
						alternativeAvailable: {
							type: 'boolean',
							description: 'Whether multi-path alternatives exist'
						},
						estimatedFeeSats: {
							type: 'integer',
							description: 'Estimated routing fee in satoshis'
						},
						hopCount: {
							type: 'integer',
							description: 'Number of hops in the route'
						}
					},
					required: [
						'successProbabilityPct',
						'estimatedTimeMs',
						'routeQuality',
						'alternativeAvailable',
						'estimatedFeeSats',
						'hopCount'
					]
				},
				RetryPaymentResult: {
					type: 'object',
					properties: {
						paymentHash: { type: 'string' },
						preimage: { type: 'string' },
						amountSats: { type: 'integer' },
						feeSats: { type: 'integer' },
						status: {
							type: 'string',
							enum: ['PENDING', 'COMPLETED', 'FAILED']
						},
						direction: { type: 'string', enum: ['OUTGOING', 'INCOMING'] },
						failureCode: { type: 'integer' },
						failureDescription: { type: 'string' },
						createdAt: { type: 'integer' },
						completedAt: { type: 'integer' },
						metadata: { type: 'object' },
						attempts: {
							type: 'integer',
							description: 'Number of attempts made (1 = first try succeeded)'
						}
					},
					required: [
						'paymentHash',
						'amountSats',
						'status',
						'direction',
						'createdAt',
						'attempts'
					]
				},
				ChannelSuggestion: {
					type: 'object',
					properties: {
						nodeId: {
							type: 'string',
							description: 'Public key of the suggested node'
						},
						alias: { type: 'string', description: 'Node alias (if known)' },
						score: { type: 'integer', description: 'Suggestion score (0-100)' },
						channelCount: {
							type: 'integer',
							description: 'Number of channels the node has'
						},
						totalCapacitySats: {
							type: 'integer',
							description: 'Total capacity in satoshis'
						},
						reason: {
							type: 'string',
							description: 'Human-readable reason for the suggestion'
						}
					},
					required: [
						'nodeId',
						'score',
						'channelCount',
						'totalCapacitySats',
						'reason'
					]
				},
				FeeSnapshot: {
					type: 'object',
					properties: {
						currentSatPerVbyte: {
							type: 'number',
							description: 'Most recent fee rate sample (sat/vByte)'
						},
						trend: {
							type: 'string',
							enum: ['RISING', 'FALLING', 'STABLE'],
							description: 'Fee rate trend over recent samples'
						},
						percentile: {
							type: 'integer',
							description: 'Current rate percentile within buffer (0-100)'
						},
						recommendation: {
							type: 'string',
							enum: ['OPEN_NOW', 'WAIT', 'NEUTRAL'],
							description: 'Channel-open timing recommendation'
						},
						estimatedOpenChannelCostSats: {
							type: 'integer',
							description:
								'Estimated cost to open a channel at current fee rate'
						},
						sampleCount: {
							type: 'integer',
							description: 'Number of fee rate samples in buffer (max 144)'
						},
						minSatPerVbyte: {
							type: 'number',
							description: 'Lowest fee rate in buffer'
						},
						maxSatPerVbyte: {
							type: 'number',
							description: 'Highest fee rate in buffer'
						},
						avgSatPerVbyte: {
							type: 'number',
							description: 'Average fee rate in buffer'
						}
					},
					required: [
						'currentSatPerVbyte',
						'trend',
						'percentile',
						'recommendation',
						'estimatedOpenChannelCostSats',
						'sampleCount',
						'minSatPerVbyte',
						'maxSatPerVbyte',
						'avgSatPerVbyte'
					]
				}
			}
		},
		security: [{ bearerAuth: [] }]
	};

	// Annotate every documented operation with the API key scopes it accepts
	// (from the daemon's route classification). Auth-exempt routes (security:
	// []) have no entry in ROUTE_SCOPES and stay unannotated.
	const paths = spec.paths as Record<string, Record<string, unknown>>;
	for (const [routePath, operations] of Object.entries(paths)) {
		for (const [method, operation] of Object.entries(operations)) {
			const routeKey = `${method.toUpperCase()} ${routePath}`;
			if (!(routeKey in ROUTE_SCOPES)) continue;
			(operation as Record<string, unknown>)['x-accepted-scopes'] = [
				...ROUTE_SCOPES[routeKey],
				'admin'
			];
		}
	}

	return spec;
}

function jsonContent(schema: Record<string, unknown>): Record<string, unknown> {
	return {
		'application/json': {
			schema
		}
	};
}

function bodyContent(fields: Record<string, string>): Record<string, unknown> {
	const properties: Record<string, Record<string, unknown>> = {};
	const required: string[] = [];
	for (const [key, value] of Object.entries(fields)) {
		const isOptional = value.endsWith('?');
		const type = isOptional ? value.slice(0, -1) : value;
		if (type.startsWith('Record<')) {
			properties[key] = {
				type: 'object',
				additionalProperties: { type: 'string' }
			};
		} else {
			properties[key] = { type };
		}
		if (!isOptional) required.push(key);
	}
	return {
		content: {
			'application/json': {
				schema: {
					type: 'object',
					properties,
					...(required.length > 0 ? { required } : {})
				}
			}
		}
	};
}
