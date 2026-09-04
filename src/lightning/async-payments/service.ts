/**
 * Async receive service, LSP side (issue #709).
 *
 * The service is the boundary that turns the hold_htlc marker from an
 * instruction anyone can write into a capability this node granted:
 *
 *  - It is DISABLED by default. Off, the node advertises no feature bit,
 *    answers no registration request, and treats the marker as an unknown
 *    odd TLV (the forward proceeds or fails exactly as without it).
 *  - On, it advertises Feature.ASYNC_RECEIVE_SERVICE (odd bit) and answers
 *    ASYNC_REGISTRATION_REQUEST onion messages from channel peers with a
 *    signed grant (receiver-grant.ts) that binds the receiver, this LSP, the
 *    permitted outgoing channel, every per-receiver ceiling, the fee schedule
 *    and an expiry. The registration is a durable ledger row under its own
 *    prefix (the same DurableLedger the held-forward ledger uses).
 *  - Every hold is ADMITTED before it is parked: the marker's registration
 *    id must name an ACTIVE, unexpired registration whose receiver is the
 *    peer on the outgoing channel and whose SCID is the channel the path
 *    forwards onto; then the part, payment, receiver and global limits on
 *    count, value, bytes and CLTV window are judged against the ledger's
 *    current occupancy; then the price. The verdict and the durable hold row
 *    are produced in one synchronous step with no await between them, so two
 *    admissions cannot both pass a check that only one of them fits.
 *
 * Pricing. Two fees, each with one deterministic collection point:
 *
 *  - Admission fee, per part, NON-REFUNDABLE: debited from the receiver's
 *    prepaid credit when the hold row is written. Release, failure, a
 *    disconnect, an expiry at the cutoff: none of them refund it. Credit
 *    spent is derived from the hold rows themselves (every row carries the
 *    fee it was admitted with), so the debit is atomic with the reservation
 *    for free and survives a restart with the row. When the credit cannot
 *    cover another part, admission refuses. This is what prices an
 *    abandoned hold: a receiver that lets holds expire pays the admission
 *    fee for each one and, once its credit is gone, can reserve nothing.
 *  - Holding fee, per block of the reserved window, paid by the SENDER: the
 *    receiver's blinded path adds holdingFeeMsatPerBlock * maxHoldBlocks to
 *    the LSP hop's payment_relay base fee, admission checks the incoming
 *    amount covers it on top of the forwarding policy fee, and the LSP
 *    keeps it at release as the difference between the incoming and
 *    outgoing HTLC, exactly like any forwarding fee. A hold that fails
 *    (expiry, receiver fail, unplaceable release) refunds the sender the
 *    whole HTLC, holding fee included, because the LSP delivered nothing.
 *    The window is priced whole rather than per block actually held: the
 *    capacity is reserved for the whole window at admission, and a sender
 *    cannot price a fee that depends on when the receiver comes back.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import {
	DurableLedger,
	IDurableLedgerStore,
	ILedgerCodec,
	ILedgerRecord
} from '../storage/durable-ledger';
import { Feature } from '../features/flags';
import {
	HeldForwardLedger,
	IHeldForwardRecord,
	isUnresolvedHeldForward
} from './held-forward-ledger';
import {
	FEE_COLLECTION_PREPAID_ADMISSION_SENDER_HOLDING,
	IReceiverGrant,
	IRegistrationReply,
	decodeReceiverGrant,
	decodeRegistrationRequest,
	encodeReceiverGrant,
	holdingFeeForWindowMsat,
	signReceiverGrant
} from './receiver-grant';
import {
	IAsyncReceiveServiceConfig,
	IAsyncReceiveServiceMetrics
} from './types';

export type AsyncRegistrationState = 'ACTIVE' | 'REVOKED';

export interface IAsyncRegistrationRecord extends ILedgerRecord {
	/** registration_id, 32 random bytes as hex. */
	id: string;
	state: AsyncRegistrationState;
	receiverNodeIdHex: string;
	scidHex: string;
	/** The request nonce this registration answered: the replay domain. */
	nonceHex: string;
	/** The signed grant as sent, hex (audit, and re-serving a query). */
	grantHex: string;
	/** Prepaid credit (msat) including operator top-ups. */
	creditMsat: string;
	/** Admission fees of hold rows since forgotten, folded here. */
	spentMsat: string;
	/** Unix seconds. */
	issuedAt: number;
	expiresAt: number;
	revokedReason?: string;
}

export const ASYNC_REGISTRATION_LEDGER_PREFIX = 'async_registration';

export const asyncRegistrationCodec: ILedgerCodec<IAsyncRegistrationRecord> = {
	encode: (record) => JSON.stringify(record),
	decode: (raw) => {
		try {
			const parsed = JSON.parse(raw) as Partial<IAsyncRegistrationRecord>;
			if (
				typeof parsed.id !== 'string' ||
				(parsed.state !== 'ACTIVE' && parsed.state !== 'REVOKED') ||
				typeof parsed.receiverNodeIdHex !== 'string' ||
				typeof parsed.scidHex !== 'string' ||
				typeof parsed.nonceHex !== 'string' ||
				typeof parsed.grantHex !== 'string' ||
				typeof parsed.expiresAt !== 'number'
			) {
				return null;
			}
			return parsed as IAsyncRegistrationRecord;
		} catch {
			return null;
		}
	}
};

/** The resolved service limits (config with defaults applied). */
export interface IAsyncReceiveServiceLimits {
	maxReceivers: number;
	maxPartMsat: bigint;
	maxPaymentMsat: bigint;
	maxPartsPerReceiver: number;
	maxHeldMsatPerReceiver: bigint;
	maxHeldBytesPerReceiver: number;
	maxHolds: number;
	maxHeldMsat: bigint;
	maxHeldBytes: number;
	maxHoldBlocks: number;
	minRemainingCltv: number;
	grantTtlSec: number;
	admissionFeeMsat: bigint;
	holdingFeeMsatPerBlock: bigint;
	initialCreditMsat: bigint;
}

export function resolveServiceLimits(
	cfg: IAsyncReceiveServiceConfig
): IAsyncReceiveServiceLimits {
	return {
		maxReceivers: cfg.maxReceivers ?? 1000,
		maxPartMsat: cfg.maxPartMsat ?? 1_000_000_000n,
		maxPaymentMsat: cfg.maxPaymentMsat ?? 1_000_000_000n,
		maxPartsPerReceiver: cfg.maxPartsPerReceiver ?? 10,
		maxHeldMsatPerReceiver: cfg.maxHeldMsatPerReceiver ?? 1_000_000_000n,
		maxHeldBytesPerReceiver: cfg.maxHeldBytesPerReceiver ?? 64 * 1024,
		maxHolds: cfg.maxHolds ?? 200,
		maxHeldMsat: cfg.maxHeldMsat ?? 10_000_000_000n,
		maxHeldBytes: cfg.maxHeldBytes ?? 1024 * 1024,
		maxHoldBlocks: cfg.maxHoldBlocks ?? 144,
		minRemainingCltv: cfg.minRemainingCltv ?? 6,
		grantTtlSec: cfg.grantTtlSec ?? 30 * 24 * 3600,
		admissionFeeMsat: cfg.admissionFeeMsat ?? 0n,
		holdingFeeMsatPerBlock: cfg.holdingFeeMsatPerBlock ?? 0n,
		initialCreditMsat: cfg.initialCreditMsat ?? 0n
	};
}

export type AdmissionRefusalReason =
	| 'service_disabled'
	| 'unknown_registration'
	| 'registration_revoked'
	| 'registration_expired'
	| 'receiver_mismatch'
	| 'channel_mismatch'
	| 'part_too_large'
	| 'payment_too_large'
	| 'receiver_count'
	| 'receiver_value'
	| 'receiver_bytes'
	| 'global_count'
	| 'global_value'
	| 'global_bytes'
	| 'cltv_too_short'
	| 'fee_insufficient'
	| 'credit_exhausted';

export type RegistrationRefusalReason =
	| 'service_disabled'
	| 'malformed'
	| 'wrong_network'
	| 'wrong_lsp'
	| 'sender_mismatch'
	| 'unknown_channel'
	| 'channel_peer_mismatch'
	| 'nonce_replayed'
	| 'too_many_receivers'
	| 'storage_failed';

/** What the node knows about a candidate hold when it asks for admission. */
export interface IAdmissionCandidate {
	registrationIdHex: string;
	/** Peer on the outgoing channel. */
	receiverNodeIdHex: string;
	/** The SCID the blinded path named, that resolved to the outgoing channel. */
	outgoingScidHex: string;
	paymentHashHex: string;
	incomingAmountMsat: bigint;
	forwardAmountMsat: bigint;
	/** The forwarding fee our policy earns on this forward (before the hold). */
	policyFeeMsat: bigint;
	/** The cutoff the node computed from CLTVs alone; admission may lower it. */
	proposedCutoffHeight: number;
	/** Bytes this hold reserves (onion packet plus its row). */
	heldBytes: number;
}

export type IAdmissionVerdict =
	| {
			ok: true;
			cutoffHeight: number;
			admittedHeight: number;
			admissionFeeMsat: bigint;
			holdingFeeMsat: bigint;
			registration: IAsyncRegistrationRecord;
	  }
	| { ok: false; reason: AdmissionRefusalReason };

export interface IAsyncReceiveServiceDeps {
	nodePrivkey: Buffer;
	nodeId: Buffer;
	chainHash: Buffer;
	currentHeight: () => number;
	/** The channel a SCID (or alias) addresses, and its peer; null if none. */
	channelForScid: (
		scidHex: string
	) => { channelIdHex: string; peerNodeIdHex: string } | null;
	/** Unix milliseconds; injectable for expiry tests. */
	now?: () => number;
}

/**
 * The LSP-side service: registrations, admission, pricing, metrics.
 * Constructed whether or not the service is enabled, so a disabled node has
 * a metrics surface saying so; every serving method refuses while disabled.
 */
export class AsyncReceiveService extends EventEmitter {
	readonly limits: IAsyncReceiveServiceLimits;
	private readonly enabled: boolean;
	private readonly registrations: DurableLedger<IAsyncRegistrationRecord>;
	private refusals = 0;
	private refusalsByReason: Record<string, number> = {};
	private releases = 0;
	private expiries = 0;
	private failures = 0;
	private registrationRefusals = 0;

	constructor(
		config: IAsyncReceiveServiceConfig | undefined,
		store: IDurableLedgerStore<IAsyncRegistrationRecord>,
		private readonly holds: HeldForwardLedger,
		private readonly deps: IAsyncReceiveServiceDeps
	) {
		super();
		this.enabled = config?.enabled === true;
		this.limits = resolveServiceLimits(config ?? { enabled: false });
		this.registrations = new DurableLedger(store);
		this.registrations.rehydrate();
	}

	isEnabled(): boolean {
		return this.enabled;
	}

	private nowSec(): number {
		return Math.floor((this.deps.now ?? Date.now)() / 1000);
	}

	// ─────────────── Registrations ───────────────

	listRegistrations(): IAsyncRegistrationRecord[] {
		return this.registrations.list();
	}

	getRegistration(
		registrationIdHex: string
	): IAsyncRegistrationRecord | undefined {
		return this.registrations.get(registrationIdHex);
	}

	/** ACTIVE and unexpired right now. */
	activeRegistrations(): IAsyncRegistrationRecord[] {
		const now = this.nowSec();
		return this.registrations.find(
			(r) => r.state === 'ACTIVE' && now < r.expiresAt
		);
	}

	/** The grant a registration was issued with (decoded), if the row exists. */
	grantFor(registrationIdHex: string): IReceiverGrant | null {
		const r = this.registrations.get(registrationIdHex);
		return r ? decodeReceiverGrant(Buffer.from(r.grantHex, 'hex')) : null;
	}

	/**
	 * Answer a registration request from the authenticated peer `fromPeer`.
	 * A request from a receiver that already holds an ACTIVE registration on
	 * the same channel supersedes it (renewal): the old row is REVOKED, and
	 * holds already admitted under it resolve on their own terms.
	 */
	handleRegistrationRequest(
		fromPeer: string,
		data: Buffer
	): IRegistrationReply {
		const refuse = (
			reason: RegistrationRefusalReason,
			nonce: Buffer
		): IRegistrationReply => {
			this.registrationRefusals++;
			this.emit('registration-refused', { fromPeer, reason });
			return { granted: false, nonce, reason };
		};
		const req = decodeRegistrationRequest(data);
		if (!req) return refuse('malformed', Buffer.alloc(32));
		if (!this.enabled) return refuse('service_disabled', req.nonce);
		if (!req.chainHash.equals(this.deps.chainHash)) {
			return refuse('wrong_network', req.nonce);
		}
		if (!req.lspNodeId.equals(this.deps.nodeId)) {
			return refuse('wrong_lsp', req.nonce);
		}
		const receiverHex = req.receiverNodeId.toString('hex');
		if (receiverHex !== fromPeer) return refuse('sender_mismatch', req.nonce);
		const scidHex = req.scid.toString('hex');
		const channel = this.deps.channelForScid(scidHex);
		if (!channel) return refuse('unknown_channel', req.nonce);
		if (channel.peerNodeIdHex !== receiverHex) {
			return refuse('channel_peer_mismatch', req.nonce);
		}
		const nonceHex = req.nonce.toString('hex');
		// Replay domain: (this LSP, receiver, nonce). Every registration this
		// node ever issued keeps its nonce, revoked ones included, so a
		// captured request can never mint a second registration.
		if (
			this.registrations.find(
				(r) => r.receiverNodeIdHex === receiverHex && r.nonceHex === nonceHex
			).length > 0
		) {
			return refuse('nonce_replayed', req.nonce);
		}
		const active = this.activeRegistrations();
		const superseded = active.filter(
			(r) => r.receiverNodeIdHex === receiverHex && r.scidHex === scidHex
		);
		const distinctReceivers = new Set(active.map((r) => r.receiverNodeIdHex));
		if (
			!distinctReceivers.has(receiverHex) &&
			distinctReceivers.size >= this.limits.maxReceivers
		) {
			return refuse('too_many_receivers', req.nonce);
		}

		const L = this.limits;
		const maxHoldBlocks =
			req.requestedHoldBlocks > 0
				? Math.min(req.requestedHoldBlocks, L.maxHoldBlocks)
				: L.maxHoldBlocks;
		const issuedAt = this.nowSec();
		const expiresAt = issuedAt + L.grantTtlSec;
		const grant = signReceiverGrant(
			{
				featureBit: Feature.ASYNC_RECEIVE_SERVICE + 1,
				serviceFlags: 0,
				chainHash: this.deps.chainHash,
				receiverNodeId: req.receiverNodeId,
				lspNodeId: this.deps.nodeId,
				registrationId: crypto.randomBytes(32),
				scid: req.scid,
				maxPartMsat: L.maxPartMsat,
				maxPaymentMsat: L.maxPaymentMsat,
				maxParts: Math.min(L.maxPartsPerReceiver, 0xffff),
				maxHeldMsat: L.maxHeldMsatPerReceiver,
				maxHoldBlocks,
				minRemainingCltv: L.minRemainingCltv,
				admissionFeeMsat: L.admissionFeeMsat,
				holdingFeeMsatPerBlock: L.holdingFeeMsatPerBlock,
				feeCollection: FEE_COLLECTION_PREPAID_ADMISSION_SENDER_HOLDING,
				creditMsat: L.initialCreditMsat,
				issuedAt: BigInt(issuedAt),
				expiresAt: BigInt(expiresAt),
				nonce: req.nonce,
				witnessProfile: Buffer.alloc(32)
			},
			this.deps.nodePrivkey
		);
		const record: IAsyncRegistrationRecord = {
			id: grant.registrationId.toString('hex'),
			state: 'ACTIVE',
			receiverNodeIdHex: receiverHex,
			scidHex,
			nonceHex,
			grantHex: encodeReceiverGrant(grant).toString('hex'),
			creditMsat: L.initialCreditMsat.toString(),
			spentMsat: '0',
			issuedAt,
			expiresAt
		};
		const inserted = this.registrations.insert(record);
		if (inserted.outcome !== 'applied') {
			return refuse('storage_failed', req.nonce);
		}
		for (const old of superseded) {
			this.registrations.transition(old.id, ['ACTIVE'], 'REVOKED', {
				revokedReason: 'superseded'
			});
		}
		this.emit('registered', record);
		return { granted: true, grant };
	}

	/** Operator: revoke a registration; new holds under it are refused. */
	revokeRegistration(registrationIdHex: string, reason = 'operator'): boolean {
		const result = this.registrations.transition(
			registrationIdHex,
			['ACTIVE'],
			'REVOKED',
			{ revokedReason: reason }
		);
		return result.outcome === 'applied';
	}

	/**
	 * Operator: add prepaid credit to a registration (after being paid by
	 * whatever means the operator sells it: an invoice, an L402, a plan).
	 */
	creditRegistration(registrationIdHex: string, msat: bigint): boolean {
		if (msat <= 0n) return false;
		const r = this.registrations.get(registrationIdHex);
		if (!r) return false;
		const result = this.registrations.transition(
			registrationIdHex,
			[r.state],
			r.state,
			{ creditMsat: (BigInt(r.creditMsat) + msat).toString() }
		);
		return result.outcome === 'applied';
	}

	/** Admission fees ever charged under a registration (msat). */
	creditSpentMsat(registrationIdHex: string): bigint {
		const r = this.registrations.get(registrationIdHex);
		let spent = r ? BigInt(r.spentMsat) : 0n;
		for (const h of this.holds.forRegistration(registrationIdHex)) {
			if (h.admissionFeeMsat) spent += BigInt(h.admissionFeeMsat);
		}
		return spent;
	}

	/** Prepaid credit still available under a registration (msat). */
	creditRemainingMsat(registrationIdHex: string): bigint {
		const r = this.registrations.get(registrationIdHex);
		if (!r) return 0n;
		return BigInt(r.creditMsat) - this.creditSpentMsat(registrationIdHex);
	}

	// ─────────────── Admission ───────────────

	/**
	 * Judge a candidate hold against its registration, every limit and the
	 * price. Pure with respect to the ledgers: the caller writes the hold row
	 * in the same synchronous step, which is what makes the reservation
	 * atomic (no await can interleave a second admission between this
	 * verdict and that write).
	 */
	admit(c: IAdmissionCandidate): IAdmissionVerdict {
		const refuse = (reason: AdmissionRefusalReason): IAdmissionVerdict => {
			this.refusals++;
			this.refusalsByReason[reason] = (this.refusalsByReason[reason] ?? 0) + 1;
			this.emit('admission-refused', {
				reason,
				registrationIdHex: c.registrationIdHex,
				receiverNodeIdHex: c.receiverNodeIdHex
			});
			return { ok: false, reason };
		};
		if (!this.enabled) return refuse('service_disabled');
		const reg = this.registrations.get(c.registrationIdHex);
		if (!reg) return refuse('unknown_registration');
		if (reg.state !== 'ACTIVE') return refuse('registration_revoked');
		if (this.nowSec() >= reg.expiresAt) return refuse('registration_expired');
		if (reg.receiverNodeIdHex !== c.receiverNodeIdHex) {
			return refuse('receiver_mismatch');
		}
		if (reg.scidHex !== c.outgoingScidHex) return refuse('channel_mismatch');
		const grant = decodeReceiverGrant(Buffer.from(reg.grantHex, 'hex'));
		if (!grant) return refuse('unknown_registration');

		// Value: this part, then the payment it belongs to.
		if (c.incomingAmountMsat > grant.maxPartMsat)
			return refuse('part_too_large');
		const receiverHolds = this.holds.forReceiver(c.receiverNodeIdHex);
		let paymentMsat = 0n;
		for (const h of receiverHolds) {
			if (h.paymentHashHex === c.paymentHashHex) {
				paymentMsat += BigInt(h.incomingAmountMsat);
			}
		}
		if (paymentMsat + c.incomingAmountMsat > grant.maxPaymentMsat) {
			return refuse('payment_too_large');
		}
		// Per receiver: count, value, bytes.
		const mine = HeldForwardLedger.occupancy(receiverHolds);
		const L = this.limits;
		if (mine.count + 1 > grant.maxParts) return refuse('receiver_count');
		if (mine.valueMsat + c.incomingAmountMsat > grant.maxHeldMsat) {
			return refuse('receiver_value');
		}
		if (mine.bytes + c.heldBytes > L.maxHeldBytesPerReceiver) {
			return refuse('receiver_bytes');
		}
		// Global: count, value, bytes.
		const all = HeldForwardLedger.occupancy(this.holds.unresolved());
		if (all.count + 1 > L.maxHolds) return refuse('global_count');
		if (all.valueMsat + c.incomingAmountMsat > L.maxHeldMsat) {
			return refuse('global_value');
		}
		if (all.bytes + c.heldBytes > L.maxHeldBytes) return refuse('global_bytes');
		// CLTV window: clamp to the grant's window, refuse one too short to
		// be worth a slot. Judged only once a height is known, like the
		// cutoff itself.
		const height = this.deps.currentHeight();
		let cutoffHeight = c.proposedCutoffHeight;
		if (height > 0) {
			cutoffHeight = Math.min(cutoffHeight, height + grant.maxHoldBlocks);
			if (cutoffHeight - height < grant.minRemainingCltv) {
				return refuse('cltv_too_short');
			}
		}
		// Price: the sender must have paid the holding fee for the window on
		// top of our forwarding policy, and the receiver's credit must cover
		// the admission fee.
		const holdingFeeMsat = holdingFeeForWindowMsat(grant);
		if (
			c.incomingAmountMsat - c.forwardAmountMsat <
			c.policyFeeMsat + holdingFeeMsat
		) {
			return refuse('fee_insufficient');
		}
		const admissionFeeMsat = grant.admissionFeeMsat;
		if (
			admissionFeeMsat > 0n &&
			this.creditRemainingMsat(reg.id) < admissionFeeMsat
		) {
			return refuse('credit_exhausted');
		}
		return {
			ok: true,
			cutoffHeight,
			admittedHeight: height,
			admissionFeeMsat,
			holdingFeeMsat,
			registration: reg
		};
	}

	// ─────────────── Metrics ───────────────

	/** Count a hold's outcome (wired to the manager's events by the node). */
	noteReleased(): void {
		this.releases++;
	}

	noteFailed(record: IHeldForwardRecord): void {
		if (
			record.failReason === 'cutoff' ||
			record.failReason === 'cutoff_unplaced'
		) {
			this.expiries++;
		} else {
			this.failures++;
		}
	}

	metrics(): IAsyncReceiveServiceMetrics {
		const occ = HeldForwardLedger.occupancy(
			this.holds.list().filter((r) => isUnresolvedHeldForward(r.state))
		);
		return {
			enabled: this.enabled,
			registrations: this.activeRegistrations().length,
			occupiedSlots: occ.count,
			heldValueMsat: occ.valueMsat.toString(),
			heldBytes: occ.bytes,
			oldestHoldAt: occ.oldestAt,
			admissionRefusals: this.refusals,
			admissionRefusalsByReason: { ...this.refusalsByReason },
			releases: this.releases,
			expiries: this.expiries,
			failures: this.failures,
			registrationRefusals: this.registrationRefusals
		};
	}
}
