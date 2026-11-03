import type { BeignetNode } from './beignet-node';
import type { ChannelInfo } from './types';
import type { BeignetErrorCodeValue } from './errors';
import { BeignetError } from './errors';
import {
	OFFLINE_RECEIVE_STEER_CODES,
	relayAddressOf,
	steerReceive
} from './receive-steering';
import type { ISteerCandidate } from './receive-steering';
import { DEFAULT_CHANNEL_CONFIG } from '../lightning/channel/types';

/**
 * Which route a receive request took.
 *
 * 'bolt11' is the FFOR offline-receive lane: a channel that ALREADY exists with
 * the peer carries the payment while this wallet is closed. 'direct-funding' is
 * the fallback for when no such channel exists: the payer's on-chain payment
 * becomes this node's channel funding and the liquidity peer opens the channel
 * to us. Automatic offline receive never opens a channel of its own.
 */
export type OfflineReceiveKind = 'bolt11' | 'direct-funding';

export type OfflineReceiveJob = {
	id: string;
	peer: string;
	amountSats: number;
	/** Absent on jobs written before the two routes existed: those are bolt11. */
	kind?: OfflineReceiveKind;
	/**
	 * Dead field kept only so a job persisted by an older build still loads. The
	 * receiver no longer asks a peer to fund a channel for it.
	 */
	allocationId?: string;
	channelId?: string;
	epochId?: string;
	concurrent?: boolean;
	concurrentVersion?: 1 | 2;
	previousEpochId?: string;
	expiresAt?: number;
	invoice?: any;
	/** direct-funding only: the envelope a payer pays, and its receipt hash. */
	request?: string;
	paymentHash?: string;
	done?: boolean;
};
const live = (e: any) => e && !['CLOSED', 'ABORTED'].includes(e.state);
const fail = (code: BeignetErrorCodeValue, message: string): never => {
	throw new BeignetError(code, message);
};
/**
 * What a direct-funded request answers with. `offlineReceive` is false because
 * nothing is held open on our side while the payer decides: the envelope simply
 * expires.
 */
export type OfflineReceiveResult = {
	kind: 'direct-funding';
	request?: string;
	paymentHash?: string;
	expiresAt?: number;
	amountSats: number;
	peer: string;
	offlineReceive: false;
};
/** A job with no kind predates the split and is a bolt11 job. */
const kindOf = (j: OfflineReceiveJob): OfflineReceiveKind => j.kind ?? 'bolt11';
/** Items by channelId, the first winning as find() would. */
const firstByChannelId = <T extends { channelId?: unknown }>(
	items: T[]
): Map<unknown, T> => {
	const byId = new Map<unknown, T>();
	for (const item of items) {
		if (!byId.has(item.channelId)) byId.set(item.channelId, item);
	}
	return byId;
};
export class OfflineReceive {
	private jobs: OfflineReceiveJob[];
	private creating = false;
	private syncing = false;
	private stopped = false;
	constructor(
		private node: BeignetNode,
		private save: (jobs: OfflineReceiveJob[]) => void,
		initial: OfflineReceiveJob[],
		private now = Date.now
	) {
		if (
			!Array.isArray(initial) ||
			initial.some(
				(j) =>
					!j ||
					typeof j.id !== 'string' ||
					!/^[a-f0-9]{66}$/.test(j.peer) ||
					(j.kind !== undefined &&
						j.kind !== 'bolt11' &&
						j.kind !== 'direct-funding') ||
					// Optional now: a request that never asked a peer to fund a channel
					// has no allocation, but a journal written before that is still read.
					(j.allocationId !== undefined &&
						!/^[a-f0-9]{32}$/.test(j.allocationId)) ||
					!Number.isSafeInteger(j.amountSats) ||
					j.amountSats <= 0 ||
					(j.channelId !== undefined && !/^[a-f0-9]{64}$/.test(j.channelId)) ||
					(j.epochId !== undefined && !/^[a-f0-9]{64}$/.test(j.epochId)) ||
					(j.concurrent !== undefined && typeof j.concurrent !== 'boolean') ||
					(j.concurrent === true
						? j.concurrentVersion !== 1 && j.concurrentVersion !== 2
						: j.concurrentVersion !== undefined) ||
					(j.kind === 'direct-funding' && j.concurrent === true) ||
					(j.request !== undefined && typeof j.request !== 'string') ||
					(j.paymentHash !== undefined && !/^[a-f0-9]{64}$/.test(j.paymentHash))
			)
		)
			throw Error('Invalid receive journal');
		this.jobs = initial;
	}
	stop() {
		this.stopped = true;
	}
	ownsInvoice(hash: string): boolean {
		return this.jobs.some((j) => j.invoice?.paymentHash === hash);
	}
	status() {
		return {
			available: !this.stopped,
			reservedChannelIds: [...this.reservedIds()],
			// kind is filled in on read so a host never has to know that an older
			// journal left it out.
			requests: this.jobs.map((j) => {
				const capacity = j.channelId
					? this.node.listChannels().find((c) => c.channelId === j.channelId)
							?.ffor
					: undefined;
				return {
					...j,
					kind: kindOf(j),
					...(j.concurrent
						? {
								reservedInboundSats: capacity?.reservedInboundSats ?? 0,
								unresolvedSlots: capacity?.unresolvedSlots ?? 0
						  }
						: {})
				};
			})
		};
	}
	private persist() {
		try {
			this.save(this.jobs);
		} catch (error) {
			this.stopped = true;
			throw error;
		}
	}
	reservedIds(): Set<string> {
		return new Set(
			this.jobs
				.filter((j) => kindOf(j) === 'bolt11' && !j.done && j.channelId)
				.map((j) => j.channelId!)
		);
	}
	/**
	 * The one channel this peer could carry the payment on while we are closed.
	 *
	 * A funded channel is eligible when concurrent receive is negotiated.
	 * Never one another request has
	 * already reserved, and never one with a live epoch on it. The same search
	 * decides the quote's mode and the invoice's route, so the two agree.
	 */
	private suitableChannel(
		peer: string,
		amountSats: number,
		concurrent = false
	): string | undefined {
		const reserved = this.reservedIds();
		return this.node
			.listChannels()
			.find(
				(c) =>
					c.peerPubkey === peer &&
					c.state === 'NORMAL' &&
					c.htlcUsable &&
					(concurrent || c.localBalanceSats === 0) &&
					c.remoteBalanceSats >= amountSats + 50000 &&
					!reserved.has(c.channelId) &&
					!live(
						this.node.fforEpochs('R').find((e) => e.channelId === c.channelId)
					)
			)?.channelId;
	}
	/** The smallest direct-funded amount this node serves, never below 5000. */
	private directFundingMinimum(): number {
		return this.node.getDirectFundingConfig().minAmountSat;
	}
	/**
	 * Validate a request and decide which route it takes.
	 *
	 * The amount is measured against the minimum of the route it would actually
	 * take, and that check comes before the connectivity one: a malformed amount
	 * is the caller's to fix either way, and naming the minimum first is more use
	 * than telling them to reconnect a peer that would refuse the amount anyway.
	 *
	 * `reuse` is the channel a half-finished bolt11 request already reserved.
	 * Naming it keeps that request on the bolt11 route, because its own
	 * reservation hides that channel from a fresh search and the request would
	 * otherwise flip routes on retry and strand the reservation.
	 */
	private route(
		peer: string,
		amountSats: number,
		reuse?: string,
		concurrent = false
	): OfflineReceiveKind {
		if (this.stopped)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Reopen the wallet before creating another request.'
			);
		if (!/^(02|03)[a-f0-9]{64}$/.test(peer))
			fail('INVALID_PARAMS', 'A primary node public key is required.');
		if (!Number.isSafeInteger(amountSats) || amountSats <= 0)
			fail('AMOUNT_REQUIRED', 'Enter an amount for this payment request.');
		const mode: OfflineReceiveKind =
			reuse !== undefined || this.suitableChannel(peer, amountSats, concurrent)
				? 'bolt11'
				: 'direct-funding';
		const minimum =
			mode === 'bolt11'
				? Number(DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis)
				: this.directFundingMinimum();
		if (amountSats < minimum)
			fail(
				'AMOUNT_TOO_SMALL',
				`Enter at least ${minimum} sats for this payment request.`
			);
		// 'ready' is the state a peer reaches once init is exchanged, which is
		// what the custom messages below need; 'connected' is the transport-up
		// state the connect route reports first.
		if (!this.connected(peer))
			fail(
				'RECEIVE_UNAVAILABLE',
				'Connect to your node before creating this payment request.'
			);
		return mode;
	}
	/**
	 * The sender fee terms this peer charges, checked into range. A steered
	 * quote passes what its budget allows for this one round trip.
	 */
	private async terms(
		peer: string,
		timeoutMs = 15000
	): Promise<{
		feeBaseMsat: number;
		feePpm: number;
		concurrentVersion?: 1 | 2;
	}> {
		const terms = await this.node
			.getFforReceiveService()
			.request(peer, { op: 'quote' }, timeoutMs);
		if (
			terms?.version !== 1 ||
			!Number.isSafeInteger(terms.feeBaseMsat) ||
			terms.feeBaseMsat < 0 ||
			terms.feeBaseMsat > 1000000 ||
			!Number.isSafeInteger(terms.feePpm) ||
			terms.feePpm < 0 ||
			terms.feePpm > 100000
		)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Your node returned unsupported receive terms.'
			);
		const concurrentVersion =
			terms.concurrent === true && this.node.fforConcurrentNegotiated(peer)
				? terms.concurrentVersion ?? 1
				: undefined;
		if (
			concurrentVersion !== undefined &&
			concurrentVersion !== 1 &&
			concurrentVersion !== 2
		)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Your node returned unsupported concurrent receive terms.'
			);
		return {
			feeBaseMsat: terms.feeBaseMsat,
			feePpm: terms.feePpm,
			...(concurrentVersion ? { concurrentVersion } : {})
		};
	}
	/**
	 * Quote a receive. With no `peer` the ranked primaries choose (issue
	 * #1922): a request already under way keeps its own peer, otherwise the
	 * primaries are tried in `listPrimaries` selection order and the first
	 * one that is connected, serves the amount on the route it would take,
	 * and could be created against is the answer. The quote carries that
	 * `peer`, and create binds to it. A peer that is named is quoted as
	 * before, with no fallback.
	 */
	async quote(
		peer: string | undefined,
		amountSats: number,
		requestId?: string
	): Promise<any> {
		if (requestId !== undefined && !/^[a-zA-Z0-9_-]{16,160}$/.test(requestId))
			fail('INVALID_PARAMS', 'A valid requestId is required.');
		const job = requestId
			? this.jobs.find((entry) => entry.id === requestId)
			: undefined;
		// An interrupted request stays with the peer it was reviewed at: a
		// changed rank must not rebind it.
		if (peer === undefined && job) peer = job.peer;
		if (peer === undefined) return this.steeredQuote(amountSats);
		return this.quoteAt(peer, amountSats, job);
	}

	/** Checks that do not depend on the peer, run once before a candidate walk. */
	private preflight(amountSats: number): void {
		if (this.stopped)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Reopen the wallet before creating another request.'
			);
		if (!Number.isSafeInteger(amountSats) || amountSats <= 0)
			fail('AMOUNT_REQUIRED', 'Enter an amount for this payment request.');
	}

	/** The ranked primaries in the order a receive tries them. */
	private candidates(): ISteerCandidate[] {
		return [...this.node.listPrimaries().primaries]
			.sort((a, b) => a.selectionOrder - b.selectionOrder)
			.map((p) => ({
				pubkey: p.pubkey,
				rank: p.rank,
				balanceSat: p.balanceSat,
				...(p.host !== null ? { host: p.host } : {}),
				...(p.port !== null ? { port: p.port } : {}),
				...(p.uri !== null ? { uri: p.uri } : {})
			}));
	}

	/**
	 * Whether a direct-funded request could be created at this peer. The peer
	 * must be one the operator configured, a primary or the policy's own, or
	 * with no policy yet the one this request configures it for, since the
	 * mint takes a named peer from nowhere else. And the payer has to be told
	 * where to reach the peer's relay, so an address must be known for it,
	 * from the primaries list, from the direct-funding policy when it names
	 * this peer, or from the TCP dial this node last reached it by. The
	 * address a peer that dialed us is up on is no use: its port is the
	 * ephemeral source port of its socket. The create-time rule of
	 * `directFunding`, applied before a steered quote binds a peer the create
	 * would then refuse. The coordinator never dials, so a candidate that is
	 * not connected is passed over by `route`.
	 */
	private directFundingEligible(peer: string): void {
		const config = this.node.getDirectFundingConfig();
		const policyPeer = config.lspPubkey?.toLowerCase();
		if (policyPeer === peer && config.lspHost && config.lspPort) return;
		const stored = this.node
			.listPrimaries()
			.primaries.find((p) => p.pubkey === peer);
		if (policyPeer !== undefined && policyPeer !== peer && !stored)
			fail(
				'RECEIVE_UNAVAILABLE',
				'This peer is neither a configured primary nor the direct-funding liquidity peer. Add it to the primaries before creating this payment request.'
			);
		const address = relayAddressOf(
			stored
				? {
						...(stored.host !== null ? { host: stored.host } : {}),
						...(stored.port !== null ? { port: stored.port } : {}),
						...(stored.uri !== null ? { uri: stored.uri } : {})
				  }
				: undefined,
			this.node.getPeerAddress(peer)
		);
		if (!address)
			fail(
				'RECEIVE_UNAVAILABLE',
				'No address is known for this peer. Dial it over TCP, or store its host and port with the primaries, before creating this payment request.'
			);
	}

	private async steeredQuote(amountSats: number): Promise<any> {
		this.preflight(amountSats);
		const candidates = this.candidates();
		if (candidates.length === 0)
			fail(
				'INVALID_PARAMS',
				'A primary node public key is required, or configure primaries.'
			);
		const { value, skipped } = await steerReceive({
			candidates,
			isConnected: (pubkey) => this.connected(pubkey),
			attempt: async (candidate, timeoutMs) => {
				const quote = await this.quoteAt(
					candidate.pubkey,
					amountSats,
					undefined,
					timeoutMs
				);
				if (quote.mode === 'direct-funding')
					this.directFundingEligible(candidate.pubkey);
				return quote;
			},
			candidateCodes: OFFLINE_RECEIVE_STEER_CODES,
			lastAttemptCapMs: 15000
		});
		return skipped.length ? { ...value, skipped } : value;
	}

	private connected(peer: string): boolean {
		return this.node
			.listPeers()
			.some(
				(p) =>
					p.pubkey === peer && (p.state === 'ready' || p.state === 'connected')
			);
	}

	private async quoteAt(
		peer: string,
		amountSats: number,
		job: OfflineReceiveJob | undefined,
		termsTimeoutMs?: number
	): Promise<any> {
		if (job && (job.peer !== peer || job.amountSats !== amountSats))
			fail('INVALID_REVIEW', 'This payment request changed.');
		let mode = this.route(
			peer,
			amountSats,
			job?.channelId,
			job ? job.concurrent === true : this.node.fforConcurrentNegotiated(peer)
		);
		const terms =
			mode === 'bolt11' ? await this.terms(peer, termsTimeoutMs) : undefined;
		if (
			job &&
			kindOf(job) === 'bolt11' &&
			(!terms || job.concurrentVersion !== terms.concurrentVersion)
		)
			fail(
				'RECEIVE_UNAVAILABLE',
				'The receive profile for this request is not currently available.'
			);
		if (terms)
			mode = this.route(
				peer,
				amountSats,
				job?.channelId,
				terms.concurrentVersion !== undefined
			);
		const expiresAt = this.now() + 60000;
		// A direct-funded request is paid on chain and carries no FFOR sender fee,
		// so there is nothing to ask the peer for and no round trip to wait on.
		if (mode === 'direct-funding')
			return {
				available: true,
				mode,
				peer,
				amountSats,
				feeSats: 0,
				minAmountSat: this.directFundingMinimum(),
				expiresAt
			};
		return {
			available: true,
			mode,
			peer,
			amountSats,
			feeSats: 0,
			terms,
			...(terms?.concurrentVersion
				? { concurrent: true, concurrentVersion: terms.concurrentVersion }
				: {}),
			expiresAt
		};
	}
	private async wait(check: () => any, timeout = 60000): Promise<any> {
		const end = this.now() + timeout;
		while (!this.stopped && this.now() < end) {
			const value = check();
			if (value) return value;
			await new Promise((r) => setTimeout(r, 200));
		}
		fail(
			'RECEIVE_PENDING',
			'Your payment request is still being prepared. Check Activity before trying again.'
		);
	}
	/**
	 * The direct-funding fallback: mint a request bound to this peer.
	 *
	 * No epoch, no reservation and no channel of our own. The request carries
	 * the peer it was quoted at (issue #1922): its relay descriptors name that
	 * peer and the receiver negotiates the funding with it, so the node's
	 * direct-funding policy is neither consulted for the peer nor retargeted.
	 * An existing policy, for this peer or another, is left exactly as the
	 * operator set it, because moving the inbound target, the zero-conf trust,
	 * the splice switches or the liquidity relationship behind their back is a
	 * change nobody asked for. With no policy yet, the first request still
	 * configures one for its peer, at the TCP address this node dialed it at
	 * when there is one: that is the peer a request naming no peer and no
	 * primaries falls back to.
	 */
	private directFunding(
		body: { requestId: string; amountSats: number },
		peer: string,
		existing?: OfflineReceiveJob
	): OfflineReceiveResult {
		this.directFundingEligible(peer);
		if (!this.node.getDirectFundingConfig().lspPubkey) {
			// The policy outlives this request and a later unbound request takes
			// its relay from it, so only an address a payer could dial is
			// written: the one the request itself uses when the primaries store
			// none, and nothing at all for a peer up over ws or iroh, or one that
			// dialed us, whose listed port is its socket's source port.
			const dialed = relayAddressOf(undefined, this.node.getPeerAddress(peer));
			if (dialed)
				this.node.configureDirectFunding({
					lspPubkey: peer,
					lspHost: dialed.host,
					lspPort: dialed.port
				});
		}
		const minted = this.node.createDirectFundingRequest({
			amountSats: body.amountSats,
			lspPubkey: peer
		});
		const job: OfflineReceiveJob =
			existing ??
			({
				id: body.requestId,
				peer,
				amountSats: body.amountSats
			} as OfflineReceiveJob);
		job.kind = 'direct-funding';
		job.request = minted.request;
		job.paymentHash = minted.paymentHash;
		job.expiresAt = minted.expiresAt;
		if (!existing) this.jobs.push(job);
		this.persist();
		return this.directFundingResult(job);
	}
	/** What a direct-funding request answers with, minted now or replayed. */
	private directFundingResult(job: OfflineReceiveJob): OfflineReceiveResult {
		return {
			kind: 'direct-funding',
			request: job.request,
			paymentHash: job.paymentHash,
			expiresAt: job.expiresAt,
			amountSats: job.amountSats,
			peer: job.peer,
			offlineReceive: false
		};
	}
	/**
	 * Create the reviewed request. With no `peer` the one the reviewed quote
	 * named is used (issue #1922): the review bound it, and create never
	 * chooses another, so a changed rank between review and create cannot
	 * move the request.
	 */
	async create(body: any, peer?: string): Promise<any> {
		if (this.creating)
			fail('RECEIVE_BUSY', 'A payment request is already being prepared.');
		const bound: unknown = peer ?? body?.quote?.peer;
		if (
			this.stopped ||
			typeof body.requestId !== 'string' ||
			!/^[a-zA-Z0-9_-]{16,160}$/.test(body.requestId) ||
			body.requestId.length > 160 ||
			!body.quote ||
			typeof bound !== 'string' ||
			body.quote.peer !== bound ||
			body.quote.amountSats !== body.amountSats ||
			!Number.isFinite(body.quote.expiresAt)
		)
			fail('INVALID_REVIEW', 'Review this payment request again.');
		peer = bound as string;
		this.creating = true;
		try {
			let job = this.jobs.find((j) => j.id === body.requestId);
			if (job && (job.peer !== peer || job.amountSats !== body.amountSats))
				fail('INVALID_REVIEW', 'This payment request changed.');
			if (job?.invoice) return { kind: 'bolt11', ...job.invoice };
			// A retry inside the request's lifetime gets the same envelope back. An
			// expired one is worthless to a payer, so it is replaced under the same
			// id rather than handed out again.
			if (
				job &&
				kindOf(job) === 'direct-funding' &&
				job.request &&
				(job.expiresAt ?? 0) > this.now()
			)
				return this.directFundingResult(job);
			if (job?.done) {
				job.done = false;
				this.persist();
			}
			if (body.quote.expiresAt <= this.now())
				fail('QUOTE_EXPIRED', 'Review this payment request again.');
			const requestedVersion = job
				? job.concurrentVersion
				: body.quote.terms?.concurrentVersion;
			if (job && requestedVersion !== body.quote.terms?.concurrentVersion)
				fail('INVALID_REVIEW', 'The receive profile for this request changed.');
			const concurrent =
				(requestedVersion === 1 || requestedVersion === 2) &&
				this.node.fforConcurrentNegotiated(peer);
			if (requestedVersion !== undefined && !concurrent)
				fail(
					'RECEIVE_PENDING',
					'Reconnect your node before preparing this concurrent payment request.'
				);
			const mode = this.route(
				peer,
				body.amountSats,
				job?.channelId,
				concurrent
			);
			if (mode === 'direct-funding') {
				if (job && kindOf(job) === 'bolt11')
					fail(
						'RECEIVE_UNAVAILABLE',
						'The receive channel is no longer available. Retry this request when its capacity is available.'
					);
				return this.directFunding(body, peer, job);
			}
			// Recheck terms before changing a channel. A peer cannot increase the
			// authorized sender fee between the review and the reservation.
			const fresh = await this.terms(peer);
			if (JSON.stringify(fresh) !== JSON.stringify(body.quote.terms))
				fail(
					'FEE_CHANGED',
					'Receive terms changed. Review the payment request again.'
				);
			if (!job) {
				job = {
					id: body.requestId,
					peer,
					amountSats: body.amountSats,
					kind: 'bolt11',
					...(concurrent
						? { concurrent: true, concurrentVersion: fresh.concurrentVersion }
						: {})
				};
				this.jobs.push(job);
				this.persist();
			}
			await this.wait(() => this.node.getInfo().blockHeight > 0);
			if (!job.channelId) {
				// Already established by `route`: reaching here without a channel
				// would mean opening one, which this flow never does.
				const channelId = this.suitableChannel(
					peer,
					job.amountSats,
					concurrent
				);
				if (!channelId)
					fail(
						'RECEIVE_UNAVAILABLE',
						'The receive channel is no longer available.'
					);
				job.channelId = channelId;
				this.persist();
			}
			const channelId = job.channelId!;
			const channel = await this.wait(() =>
				this.node
					.listChannels()
					.find(
						(c) =>
							c.channelId === channelId &&
							c.peerPubkey === peer &&
							c.state === 'NORMAL'
					)
			);
			if (!concurrent && channel.localBalanceSats !== 0)
				fail(
					'RECEIVE_UNAVAILABLE',
					'The receive channel is no longer available.'
				);
			let epoch: any = this.node
				.fforEpochs('R')
				.find((e) => e.channelId === channelId);
			if (!live(epoch)) {
				if ((channel.htlcCount ?? 0) > 0)
					fail(
						'RECEIVE_PENDING',
						'Wait for the current channel payments to finish before preparing this request.'
					);
				job.previousEpochId = epoch?.epochId;
				this.persist();
				const height = this.node.getInfo().blockHeight;
				epoch = this.node.fforStartEpoch({
					channelId,
					voucherAmountsMsat: [String(BigInt(job.amountSats) * 1000n)],
					settlementDeadline: height + 144,
					voucherExpiry: height + 144 + 1152,
					feeBaseMsat: body.quote.terms.feeBaseMsat,
					feeProportionalMillionths: body.quote.terms.feePpm,
					...(concurrent
						? { concurrent: true, concurrentVersion: fresh.concurrentVersion }
						: {})
				});
				job.epochId = epoch.epochId;
				this.persist();
			}
			if (job.epochId && job.epochId !== epoch.epochId)
				fail('RECEIVE_UNAVAILABLE', 'The receive reservation changed.');
			if (
				epoch.epochId === job.previousEpochId ||
				epoch.slots.length !== 1 ||
				epoch.slots[0].amountMsat !== String(BigInt(job.amountSats) * 1000n)
			)
				fail(
					'RECEIVE_UNAVAILABLE',
					'The receive reservation could not be verified.'
				);
			job.epochId = epoch.epochId;
			this.persist();
			epoch = await this.wait(() => {
				const e: any = this.node.fforEpoch(channelId);
				if (e.state === 'ABORTED')
					fail(
						'RECEIVE_UNAVAILABLE',
						'Your node could not prepare this payment request.'
					);
				return e.state === 'ACTIVE' ? e : null;
			});
			if ((epoch.concurrentVersion ?? 0) !== (fresh.concurrentVersion ?? 0))
				fail('RECEIVE_UNAVAILABLE', 'The receive profile changed.');
			const invoice = epoch.slots[0].bolt11
				? {
						bolt11: epoch.slots[0].bolt11,
						paymentHash: epoch.slots[0].paymentHash
				  }
				: this.node.fforCreateInvoice({
						channelId,
						k: 1,
						description: body.description ?? '',
						expirySecs: 600
				  });
			if (
				!this.node
					.getStorageBackend()
					.loadAllInvoices()
					.some((i) => i.paymentHashHex === invoice.paymentHash)
			)
				fail(
					'DURABILITY_FAILED',
					'Your payment request could not be saved. Reopen the wallet.'
				);
			const decoded = this.node.decodeInvoice(String(invoice.bolt11));
			job.expiresAt =
				(Number(decoded.timestamp) + Number(decoded.expiry)) * 1000;
			job.invoice = {
				kind: 'bolt11',
				...invoice,
				amountSats: job.amountSats,
				...(job.concurrent
					? { concurrent: true, concurrentVersion: job.concurrentVersion }
					: {}),
				expiresAt: job.expiresAt,
				offlineReceive: true
			};
			this.persist();
			return job.invoice;
		} finally {
			this.creating = false;
		}
	}
	async sync(): Promise<void> {
		if (this.syncing || this.creating || this.stopped) return;
		this.syncing = true;
		try {
			// One view of the channels and receive epochs per tick, taken again
			// after a job has run, since the awaits below let either move.
			let view: {
				channels: Map<unknown, ChannelInfo>;
				epochs: Map<unknown, Record<string, unknown>>;
			} | null = null;
			for (const job of this.jobs) {
				if (this.stopped) return;
				// A direct-funded request has no epoch and no reservation: there is
				// nothing here to reconcile or release.
				if (kindOf(job) === 'direct-funding') continue;
				if (job.done || !job.channelId) continue;
				view ??= {
					channels: firstByChannelId(this.node.listChannels()),
					epochs: firstByChannelId(this.node.fforEpochs('R'))
				};
				const channel = view.channels.get(job.channelId);
				if (!channel || channel.state !== 'NORMAL') continue;
				const epoch: any = view.epochs.get(job.channelId);
				if (!epoch) continue;
				if (job.epochId && job.epochId !== epoch.epochId) continue;
				if (!job.epochId) {
					if (
						epoch.epochId === job.previousEpochId ||
						epoch.slots.length !== 1 ||
						epoch.slots[0].amountMsat !== String(BigInt(job.amountSats) * 1000n)
					)
						continue;
					job.epochId = epoch.epochId;
					this.persist();
				}
				if (['CLOSED', 'ABORTED'].includes(epoch.state)) {
					job.done = true;
					this.persist();
					continue;
				}
				if (job.concurrentVersion !== epoch.concurrentVersion) continue;
				if (epoch.state !== 'ACTIVE') continue;
				// Recover an invoice saved by the engine immediately before a crash in
				// our metadata write. No new invoice or replacement hash is created.
				if (!job.expiresAt && epoch.slots[0]?.bolt11) {
					const d = this.node.decodeInvoice(epoch.slots[0].bolt11);
					job.expiresAt = (Number(d.timestamp) + Number(d.expiry)) * 1000;
					this.persist();
				}
				view = null;
				try {
					if (epoch.concurrentVersion) this.node.fforSync(job.channelId);
					else await this.node.getFforReceiveService().receipts(job.channelId);
				} catch {
					continue;
				}
				if (this.stopped) return;
				const current: any = this.node.fforEpoch(job.channelId);
				const paid = current.slots.every((s: any) =>
					current.concurrentVersion
						? s.state === 'redeemed' || s.state === 'cancelled'
						: s.state === 'settled'
				);
				const expired =
					job.expiresAt != null && this.now() >= job.expiresAt + 120000;
				const unused =
					!job.expiresAt &&
					current.slots.every((s: any) => s.state === 'unissued');
				if (
					current.epochId === epoch.epochId &&
					current.state === 'ACTIVE' &&
					(paid || expired || unused)
				) {
					if (current.concurrentVersion)
						this.node.fforCloseEpoch(job.channelId);
					else await this.node.fforRecover({ channelId: job.channelId });
				}
			}
		} finally {
			this.syncing = false;
		}
	}
}
