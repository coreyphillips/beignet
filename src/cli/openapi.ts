/**
 * OpenAPI 3.0 specification for the Beignet Lightning daemon.
 *
 * Generated from daemon routes. Served at GET /openapi.json.
 */

export function getOpenApiSpec(): Record<string, unknown> {
	return {
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
						'Simple readiness check — true when node has at least one NORMAL channel (auth-exempt)',
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
					summary: 'List channels in NORMAL state',
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
						descriptionHash: 'string?'
					}),
					responses: {
						'200': {
							description: 'Created invoice',
							content: jsonContent({ $ref: '#/components/schemas/InvoiceInfo' })
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
							description: 'Pending payment',
							content: jsonContent({
								type: 'object',
								properties: {
									paymentHash: { type: 'string' },
									status: { type: 'string' }
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
						pushSats: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
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
					summary: 'Cooperatively close a channel',
					tags: ['Channels'],
					requestBody: bodyContent({ channelId: 'string' }),
					responses: { '200': { description: 'Close result' } }
				}
			},
			'/channel/forceclose': {
				post: {
					summary: 'Force close a channel (returns commitment txid)',
					tags: ['Channels'],
					requestBody: bodyContent({ channelId: 'string' }),
					responses: {
						'200': { description: 'Force close result with commitment txid' }
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
						pushSats: 'number?'
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
						'Connect to a peer (omit host+port to resolve the address from the gossip graph / DNS bootstrap)',
					tags: ['Peers'],
					requestBody: bodyContent({
						pubkey: 'string',
						host: 'string?',
						port: 'number?'
					}),
					responses: {
						'200': {
							description: 'Peer info',
							content: jsonContent({ $ref: '#/components/schemas/PeerInfo' })
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
						issuer: 'string?'
					}),
					responses: {
						'200': {
							description: 'Offer info',
							content: jsonContent({ $ref: '#/components/schemas/OfferInfo' })
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
						'400': { description: 'Invalid params or no route' }
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
						'400': { description: 'No route or fee exceeds maximum' }
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
						'Get the newest valid SCB a peer returned via BOLT 1 peer storage (recovery flow: reinstall with the mnemonic, connect to peers, fetch this, then POST /restore/scb with its encoded blob)',
					tags: ['Node'],
					responses: {
						'200': {
							description:
								'Encoded SCB blob, its creation timestamp, and the peer that returned it'
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
						'400': {
							description:
								'NOT_BOOSTABLE (unknown/confirmed/non-RBF tx; try /tx/boost for CPFP) or invalid params'
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
						'400': {
							description: 'NOT_BOOSTABLE or invalid params'
						}
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
						'400': {
							description:
								'NOTHING_TO_CONSOLIDATE (fewer than 2 UTXOs) or invalid params'
						}
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
						'400': { description: 'No fee samples recorded yet' }
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
						'Server-Sent Events stream (payment:received, payment:sent, payment:failed, channel:ready, channel:closed, peer:connect, peer:disconnect, node:ready)',
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
					summary: 'Get daily spending limit info',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'Spending limit info',
							content: jsonContent({
								type: 'object',
								properties: {
									limitSats: { type: 'integer', nullable: true },
									spentSats: { type: 'integer' },
									remainingSats: { type: 'number' },
									resetsAt: { type: 'integer' }
								}
							})
						}
					}
				}
			},
			'/address/new': {
				post: {
					summary: 'Generate a new on-chain receiving address',
					tags: ['Node'],
					responses: {
						'200': {
							description: 'New address',
							content: jsonContent({
								type: 'object',
								properties: { address: { type: 'string' } }
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
						}
					}
				}
			},
			'/channel/open-v2': {
				post: {
					summary: 'Open a dual-funded (v2) channel',
					tags: ['Channels'],
					requestBody: bodyContent({
						pubkey: 'string',
						amountSats: 'number',
						fundingFeeratePerkw: 'number?',
						commitmentFeeratePerkw: 'number?',
						locktime: 'number?'
					}),
					responses: {
						'200': {
							description: 'Channel info',
							content: jsonContent({ $ref: '#/components/schemas/ChannelInfo' })
						}
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
							description: 'Splice result',
							content: jsonContent({
								$ref: '#/components/schemas/SpliceResult'
							})
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
						feeratePerkw: 'number'
					}),
					responses: {
						'200': {
							description: 'Splice result',
							content: jsonContent({
								$ref: '#/components/schemas/SpliceResult'
							})
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
			}
		},
		components: {
			securitySchemes: {
				bearerAuth: {
					type: 'http',
					scheme: 'bearer'
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
						channelCount: { type: 'integer' },
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
						unsettledSats: { type: 'integer' }
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
						height: { type: 'integer' }
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
					properties: {
						ok: { type: 'boolean' },
						error: { type: 'string' }
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
