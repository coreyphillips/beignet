import type { BeignetNode } from './beignet-node';
import { BeignetError } from './errors';
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
	previousEpochId?: string;
	expiresAt?: number;
	invoice?: any;
	/** direct-funding only: the envelope a payer pays, and its receipt hash. */
	request?: string;
	paymentHash?: string;
	done?: boolean;
};
const live = (e: any) => e && !['CLOSED', 'ABORTED'].includes(e.state);
const fail = (code: string, message: string): never => {
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
			requests: this.jobs.map((j) => ({ ...j, kind: kindOf(j) }))
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
	 * Never a channel holding spendable local money: that money stays available
	 * to the ordinary send and channelize paths. Never one another request has
	 * already reserved, and never one with a live epoch on it. The same search
	 * decides the quote's mode and the invoice's route, so the two agree.
	 */
	private suitableChannel(
		peer: string,
		amountSats: number
	): string | undefined {
		const reserved = this.reservedIds();
		return this.node
			.listChannels()
			.find(
				(c) =>
					c.peerPubkey === peer &&
					c.state === 'NORMAL' &&
					c.htlcUsable &&
					c.localBalanceSats === 0 &&
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
		reuse?: string
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
			reuse !== undefined || this.suitableChannel(peer, amountSats)
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
		if (
			!this.node
				.listPeers()
				.some((p) => p.pubkey === peer && p.state === 'connected')
		)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Connect to your node before creating this payment request.'
			);
		return mode;
	}
	/** The sender fee terms this peer charges, checked into range. */
	private async terms(
		peer: string
	): Promise<{ feeBaseMsat: number; feePpm: number }> {
		const terms = await this.node
			.getFforReceiveService()
			.request(peer, { op: 'quote' }, 15000);
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
		return { feeBaseMsat: terms.feeBaseMsat, feePpm: terms.feePpm };
	}
	async quote(peer: string, amountSats: number): Promise<any> {
		const mode = this.route(peer, amountSats);
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
			terms: await this.terms(peer),
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
	 * The direct-funding fallback: point the node at this peer and mint a request.
	 *
	 * No epoch, no reservation and no channel of our own. An existing config for
	 * the SAME peer is left exactly as the operator set it, because retargeting
	 * inbound target, zero-conf trust or the splice switches behind their back is
	 * a policy change nobody asked for. A config naming a DIFFERENT peer refuses
	 * rather than silently moving the node's liquidity relationship.
	 */
	private directFunding(
		body: { requestId: string; amountSats: number },
		peer: string,
		existing?: OfflineReceiveJob
	): OfflineReceiveResult {
		const config = this.node.getDirectFundingConfig();
		const configured = config.lspPubkey?.toLowerCase();
		if (configured && configured !== peer)
			fail(
				'RECEIVE_UNAVAILABLE',
				'Direct funding is configured for another peer. Change that setting before receiving from this one.'
			);
		if (!configured) {
			const entry = this.node.listPeers().find((p) => p.pubkey === peer);
			if (!entry?.host || !entry.port)
				fail(
					'RECEIVE_UNAVAILABLE',
					'Connect to your node before creating this payment request.'
				);
			this.node.configureDirectFunding({
				lspPubkey: peer,
				lspHost: entry!.host,
				lspPort: entry!.port
			});
		}
		const minted = this.node.createDirectFundingRequest({
			amountSats: body.amountSats
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
	async create(body: any, peer: string): Promise<any> {
		if (this.creating)
			fail('RECEIVE_BUSY', 'A payment request is already being prepared.');
		if (
			this.stopped ||
			typeof body.requestId !== 'string' ||
			!/^[a-zA-Z0-9_-]{16,160}$/.test(body.requestId) ||
			body.requestId.length > 160 ||
			!body.quote ||
			body.quote.peer !== peer ||
			body.quote.amountSats !== body.amountSats ||
			!Number.isFinite(body.quote.expiresAt)
		)
			fail('INVALID_REVIEW', 'Review this payment request again.');
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
			const mode = this.route(peer, body.amountSats, job?.channelId);
			if (mode === 'direct-funding') return this.directFunding(body, peer, job);
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
					kind: 'bolt11'
				};
				this.jobs.push(job);
				this.persist();
			}
			await this.wait(() => this.node.getInfo().blockHeight > 0);
			if (!job.channelId) {
				// Already established by `route`: reaching here without a channel
				// would mean opening one, which this flow never does.
				const channelId = this.suitableChannel(peer, job.amountSats);
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
			if (channel.localBalanceSats !== 0)
				fail(
					'RECEIVE_UNAVAILABLE',
					'The receive channel is no longer available.'
				);
			let epoch: any = this.node
				.fforEpochs('R')
				.find((e) => e.channelId === channelId);
			if (!live(epoch)) {
				job.previousEpochId = epoch?.epochId;
				this.persist();
				const height = this.node.getInfo().blockHeight;
				epoch = this.node.fforStartEpoch({
					channelId,
					voucherAmountsMsat: [String(BigInt(job.amountSats) * 1000n)],
					settlementDeadline: height + 144,
					voucherExpiry: height + 144 + 1152,
					feeBaseMsat: body.quote.terms.feeBaseMsat,
					feeProportionalMillionths: body.quote.terms.feePpm
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
					.getStorage()
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
			for (const job of this.jobs) {
				if (this.stopped) return;
				// A direct-funded request has no epoch and no reservation: there is
				// nothing here to reconcile or release.
				if (kindOf(job) === 'direct-funding') continue;
				if (job.done || !job.channelId) continue;
				const channel = this.node
					.listChannels()
					.find((c) => c.channelId === job.channelId);
				if (!channel || channel.state !== 'NORMAL') continue;
				const epoch: any = this.node
					.fforEpochs('R')
					.find((e) => e.channelId === job.channelId);
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
				if (epoch.state !== 'ACTIVE') continue;
				// Recover an invoice saved by the engine immediately before a crash in
				// our metadata write. No new invoice or replacement hash is created.
				if (!job.expiresAt && epoch.slots[0]?.bolt11) {
					const d = this.node.decodeInvoice(epoch.slots[0].bolt11);
					job.expiresAt = (Number(d.timestamp) + Number(d.expiry)) * 1000;
					this.persist();
				}
				try {
					await this.node.getFforReceiveService().receipts(job.channelId);
				} catch {
					continue;
				}
				if (this.stopped) return;
				const current: any = this.node.fforEpoch(job.channelId);
				const paid = current.slots.every((s: any) => s.state === 'settled');
				const expired =
					job.expiresAt != null && this.now() >= job.expiresAt + 120000;
				const unused =
					!job.expiresAt &&
					current.slots.every((s: any) => s.state === 'unissued');
				if (
					current.epochId === epoch.epochId &&
					current.state === 'ACTIVE' &&
					(paid || expired || unused)
				)
					await this.node.fforRecover({ channelId: job.channelId });
			}
		} finally {
			this.syncing = false;
		}
	}
}
