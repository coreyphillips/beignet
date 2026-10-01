import crypto from 'crypto';
import type { BeignetNode } from './beignet-node';
import { BeignetError } from './errors';
import { FforSlotState, FforState } from '../lightning/ffor/types';
import { BeignetCustomSubtype } from '../lightning/message/custom';

/** Operator-funded receive lanes. Both caps are lifetime allocation limits,
 * persisted before opening, so retries and restarts cannot multiply spending. */
export interface FforReceiveFunding {
	enabled: boolean;
	maxChannels: number;
	maxChannelsPerPeer: number;
	maxChannelSats: number;
	maxTotalSats: number;
}
const REQUEST = BeignetCustomSubtype.FFOR_RECEIVE_REQUEST;
const RESPONSE = BeignetCustomSubtype.FFOR_RECEIVE_RESPONSE;
const KEY = 'ffor_receive_allocations_v1';
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{32}$/;
const fail = (code: string, message: string): never => {
	throw new BeignetError(code, message);
};
/** The longest refusal a settlement peer may put in front of the wallet. */
const MAX_REFUSAL_LENGTH = 500;
/**
 * A settlement peer's refusal, in its own words, for the wallet to show (issue
 * #920). It is remote text bound for an HTTP body, so only a bounded,
 * non-blank string passes; anything else reads as the generic refusal.
 */
const refusal = (error: unknown): string =>
	typeof error === 'string' &&
	error.trim().length > 0 &&
	error.length <= MAX_REFUSAL_LENGTH
		? error
		: 'Receiving is unavailable.';
type Allocation = {
	peer: string;
	id: string;
	amount: number;
	channelId?: string;
	temporaryId?: string;
};
type Message = {
	peerPubkey: string;
	version: number;
	subtype: number;
	payload: Buffer;
};
export class FforReceiveService {
	private allocations: Allocation[];
	private opening = false;
	private stopped = false;
	private pending = new Map<
		string,
		{
			peer: string;
			resolve(v: any): void;
			reject(e: Error): void;
			timer: ReturnType<typeof setTimeout>;
		}
	>();
	private listener = (m: Message): void => {
		void this.handle(m).catch(() => {
			// A disconnected peer cannot receive an error reply.
		});
	};
	constructor(
		private host: BeignetNode,
		private settle:
			| { enabled: boolean; feeBaseMsat?: number; feePpm?: number }
			| undefined,
		private funding?: FforReceiveFunding
	) {
		if (funding?.enabled)
			for (const k of [
				'maxChannels',
				'maxChannelsPerPeer',
				'maxChannelSats',
				'maxTotalSats'
			] as const)
				if (!Number.isSafeInteger(funding[k]) || funding[k] <= 0)
					throw Error(`fforReceiveFunding.${k} must be positive`);
		const raw = host.getStorage().loadWalletData(KEY);
		this.allocations = raw ? JSON.parse(raw) : [];
		if (
			!Array.isArray(this.allocations) ||
			this.allocations.some(
				(a) =>
					!a ||
					!ID.test(a.id) ||
					!Number.isSafeInteger(a.amount) ||
					a.amount <= 0
			)
		)
			throw Error('Invalid receive allocation journal');
		host.getNode().on('custom-message', this.listener);
	}
	stop(): void {
		this.stopped = true;
		this.host.getNode().removeListener('custom-message', this.listener);
		for (const p of this.pending.values()) {
			clearTimeout(p.timer);
			p.reject(new BeignetError('RECEIVE_UNAVAILABLE', 'Wallet stopped'));
		}
		this.pending.clear();
	}
	async request(
		peer: string,
		body: Record<string, unknown>,
		timeout = 15000
	): Promise<any> {
		// Every refusal below is a BeignetError, so the daemon answers it with
		// its mapped 409 instead of scrubbing it to a 500 (issue #920).
		if (this.stopped) return fail('RECEIVE_UNAVAILABLE', 'Wallet stopped');
		if (this.pending.size >= 32)
			return fail('RECEIVE_BUSY', 'Receiving is busy. Try again shortly.');
		const id = crypto.randomBytes(16).toString('hex');
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(
					new BeignetError(
						'RECEIVE_UNAVAILABLE',
						'Your node did not answer the receive request.'
					)
				);
			}, timeout);
			timer.unref?.();
			this.pending.set(id, { peer, resolve, reject, timer });
			try {
				this.host
					.getNode()
					.sendCustomMessage(
						peer,
						REQUEST,
						Buffer.from(JSON.stringify({ ...body, id }))
					);
			} catch (e) {
				clearTimeout(timer);
				this.pending.delete(id);
				// The transport's own text (not connected, gate or lane refused)
				// is not the wallet's to act on; the peer being unreachable is.
				reject(
					e instanceof BeignetError
						? e
						: new BeignetError(
								'RECEIVE_UNAVAILABLE',
								'Connect to your node before creating this payment request.'
						  )
				);
			}
		});
	}
	private async handle(m: Message): Promise<void> {
		if (
			this.stopped ||
			m.version !== 1 ||
			![REQUEST, RESPONSE].includes(m.subtype) ||
			m.payload.length > 60000
		)
			return;
		let b: any;
		try {
			b = JSON.parse(m.payload.toString('utf8'));
		} catch {
			return;
		}
		if (!b || !ID.test(b.id)) return;
		if (m.subtype === RESPONSE) {
			const p = this.pending.get(b.id);
			if (!p || p.peer !== m.peerPubkey) return;
			clearTimeout(p.timer);
			this.pending.delete(b.id);
			if (b.ok === true) p.resolve(b.result);
			else p.reject(new BeignetError('RECEIVE_UNAVAILABLE', refusal(b.error)));
			return;
		}
		let reply: any;
		try {
			reply = { ok: true, result: await this.serve(m.peerPubkey, b) };
		} catch (e) {
			reply = { ok: false, error: (e as Error).message };
		}
		if (!this.stopped)
			this.host
				.getNode()
				.sendCustomMessage(
					m.peerPubkey,
					RESPONSE,
					Buffer.from(JSON.stringify({ id: b.id, ...reply }))
				);
	}
	private async serve(peer: string, b: any): Promise<any> {
		if (b.op === 'receipts') {
			if (!HEX.test(b.channelId) || !HEX.test(b.epochId))
				throw Error('Invalid receive reservation');
			const f = this.host.getNode().getFforEpoch(b.channelId);
			if (
				!f ||
				f.role !== 'S' ||
				f.remoteNodeId.toString('hex') !== peer ||
				f.epochId.toString('hex') !== b.epochId
			)
				throw Error('Unknown receive reservation');
			// Read only. Never reveal a preimage merely because S generated it. Only
			// durable SETTLED slots prove the upstream fulfil has been committed.
			const durable = this.host.getStorage().loadChannel(b.channelId)?.state
				.ffor;
			if (
				!durable ||
				durable.role !== 'S' ||
				durable.remoteNodeId.toString('hex') !== peer ||
				durable.epochId.toString('hex') !== b.epochId
			)
				throw Error('Receive reservation is not durable');
			return {
				channelId: b.channelId,
				epochId: b.epochId,
				receipts: durable.slotStates.flatMap((s, i) =>
					s === FforSlotState.SETTLED
						? [{ k: i + 1, preimage: durable.preimages[i].toString('hex') }]
						: []
				)
			};
		}
		if (!this.settle?.enabled)
			throw Error('Your node does not provide offline receiving.');
		if (b.op === 'quote')
			return {
				version: 1,
				feeBaseMsat: this.settle.feeBaseMsat ?? 0,
				feePpm: this.settle.feePpm ?? 0,
				canFund: this.funding?.enabled === true
			};
		if (
			b.op !== 'allocate' ||
			!ID.test(b.allocationId) ||
			!Number.isSafeInteger(b.amountSats) ||
			b.amountSats <= 0
		)
			throw Error('Invalid receive request');
		const old = this.allocations.find(
			(a) => a.peer === peer && a.id === b.allocationId
		);
		if (old) {
			if (old.amount !== b.amountSats + 50000)
				throw Error('Receive request changed');
			const channels = this.host
				.getNode()
				.getChannelManager()
				.getChannelsByPeer(peer);
			const channel = channels.find(
				(c) =>
					c.getCurrentChannelId().toString('hex') === old.channelId ||
					(old.temporaryId &&
						c.getTemporaryChannelId().toString('hex') === old.temporaryId)
			);
			if (
				!channel ||
				!this.host
					.listChannels()
					.some(
						(c) =>
							c.channelId === channel.getCurrentChannelId().toString('hex') &&
							c.state === 'NORMAL'
					)
			)
				throw Error('The receive channel is still being prepared.');
			old.channelId = channel.getCurrentChannelId().toString('hex');
			this.host
				.getStorage()
				.saveWalletData(KEY, JSON.stringify(this.allocations));
			return { channelId: old.channelId };
		}
		const policy = this.funding;
		const amount = b.amountSats + 50000;
		if (
			!policy?.enabled ||
			!Number.isSafeInteger(amount) ||
			amount > policy.maxChannelSats ||
			this.allocations.length >= policy.maxChannels ||
			this.allocations.filter((a) => a.peer === peer).length >=
				policy.maxChannelsPerPeer ||
			this.allocations.reduce((n, a) => n + a.amount, 0) + amount >
				policy.maxTotalSats
		)
			throw Error('Your node has no receive capacity available.');
		if (this.opening)
			throw Error(
				'Your node is preparing another receive channel. Try again shortly.'
			);
		this.opening = true;
		try {
			const allocation: Allocation = { peer, id: b.allocationId, amount };
			this.allocations.push(allocation);
			this.host
				.getStorage()
				.saveWalletData(KEY, JSON.stringify(this.allocations));
			// Zero-conf only where the OPERATOR said so. This used to pass a
			// hardcoded trusted=true and grant itself the authorization to match,
			// so enabling receive funding silently proposed a zero_conf channel
			// type to every client, past the operator's trusted-peer set and past
			// the daemon's own trusted=false default for opens. A plain daemon on
			// the far side then refuses the open outright ("Proposed zero_conf
			// channel type requires a trusted peer"), so the bypass was not even
			// buying the availability it cost. An untrusted client gets an
			// ordinary confirmed open instead.
			const trusted = this.host
				.getNode()
				.getChannelManager()
				.isTrustedPeer(peer);
			const opened = this.host.openChannel(peer, amount, 0, 2, false, trusted);
			allocation.channelId = opened.channelId;
			allocation.temporaryId = opened.channelId;
			this.host
				.getStorage()
				.saveWalletData(KEY, JSON.stringify(this.allocations));
			const raw = this.host
				.getNode()
				.getChannelManager()
				.getChannel(Buffer.from(opened.channelId, 'hex'));
			if (!raw) throw Error('The receive channel could not be located.');
			const until = Date.now() + 60000;
			while (!this.stopped && Date.now() < until) {
				const id = raw.getCurrentChannelId().toString('hex');
				if (id !== allocation.channelId) {
					allocation.channelId = id;
					this.host
						.getStorage()
						.saveWalletData(KEY, JSON.stringify(this.allocations));
				}
				const channel = this.host
					.listChannels()
					.find((c) => c.channelId === id);
				if (channel?.state === 'NORMAL') return { channelId: id };
				await new Promise((r) => setTimeout(r, 250));
			}
			throw Error('The receive channel is still being prepared.');
		} finally {
			this.opening = false;
		}
	}
	async receipts(channelId: string): Promise<void> {
		const node = this.host.getNode();
		const f = node.getFforEpoch(channelId);
		if (!f || f.role !== 'R' || f.state !== FforState.ACTIVE) return;
		const result = await this.request(f.remoteNodeId.toString('hex'), {
			op: 'receipts',
			channelId,
			epochId: f.epochId.toString('hex')
		});
		if (
			result?.channelId !== channelId ||
			result.epochId !== f.epochId.toString('hex') ||
			!Array.isArray(result.receipts) ||
			result.receipts.length > f.params.maxPayments
		)
			throw Error('Invalid receive receipt response');
		for (const r of result.receipts) {
			if (
				!Number.isInteger(r.k) ||
				r.k < 1 ||
				r.k > f.params.maxPayments ||
				!HEX.test(r.preimage)
			)
				throw Error('Invalid receive receipt');
			const p = Buffer.from(r.preimage, 'hex');
			if (
				!crypto
					.createHash('sha256')
					.update(p)
					.digest()
					.equals(f.paymentHashes[r.k - 1])
			)
				throw Error('Receive receipt does not match its invoice');
		}
		const current = node.getFforEpoch(channelId);
		if (current !== f || current.state !== FforState.ACTIVE)
			throw Error('Receive reservation changed while checking receipts');
		for (const r of result.receipts)
			if (!f.knownPreimages[r.k - 1]) {
				const added = node.fforAddPreimage(
					channelId,
					Buffer.from(r.preimage, 'hex')
				);
				if (!added.ok) throw Error('Receive receipt could not be saved');
			}
	}
}
