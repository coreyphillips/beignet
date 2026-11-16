/**
 * One life of an ordinary channel, under a counter in place of randomness,
 * reduced to digests (issue #2093): open, six HTLC adds, two fee updates, a
 * fulfil and a fail in each direction, and a force close. The digests cover
 * every message on the wire, every row either side stored, the final rows,
 * the key indexes and what the force close returned.
 *
 * The engine is handed in rather than imported, so the same file measures
 * the source of the previous release and of this one: the digests a test
 * pins are the ones the previous release produces.
 */

import crypto from 'crypto';
import type {
	ChannelManager,
	IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import type {
	IChannelPersistRequest,
	IChannelPersistResult
} from '../../../src/lightning/channel/channel-actions';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';
import type { ISigner } from '../../../src/lightning/keys/signer';

export type OrdinaryKind = 'static_remotekey' | 'anchors' | 'taproot';

export interface IOrdinaryRoundsEngine {
	ChannelManager: new (config: IChannelManagerConfig) => ChannelManager;
	configOf(seed: Buffer, preferTaproot: boolean): IChannelManagerConfig;
	seedFor(id: number): Buffer;
	signRemoteCommitment(
		state: IChannelState,
		signer: ISigner,
		remotePerCommitmentPoint: Buffer
	): { signature: Buffer };
	isTaprootChannel(channelType: Buffer | null | undefined): boolean;
	serializeChannelState(state: IChannelState): unknown;
	/** The engine's own randomBytes, drawn once before the counter starts. */
	randomBytes(size: number): Buffer;
}

export interface IOrdinaryRoundsDigests {
	/** Message types in order, `a` for the opener and `b` for the acceptor. */
	types: string;
	messages: number;
	wire: string;
	rowsStored: number;
	rows: string;
	finalRows: string;
	keyIndexes: string;
	forceClose: string;
}

const sha = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

/** JSON with every bigint, Buffer and Map spelled out. */
function stable(value: unknown): string {
	return JSON.stringify(value, (_key, item: unknown) => {
		if (typeof item === 'bigint') return `${item}n`;
		if (item instanceof Map) return { map: [...item] };
		if (item instanceof Set) return { set: [...item] };
		if (item instanceof Uint8Array) return Buffer.from(item).toString('hex');
		if (
			item &&
			typeof item === 'object' &&
			(item as { type?: unknown }).type === 'Buffer' &&
			Array.isArray((item as { data?: unknown }).data)
		) {
			return Buffer.from((item as { data: number[] }).data).toString('hex');
		}
		return item;
	});
}

export function ordinaryRounds(
	engine: IOrdinaryRoundsEngine,
	kind: OrdinaryKind,
	closer: 'alice' | 'bob',
	extraConfig: Partial<IChannelManagerConfig> = {}
): IOrdinaryRoundsDigests {
	const realRandomBytes = crypto.randomBytes;
	engine.randomBytes(1);
	let counter = 0;
	(crypto as unknown as { randomBytes: unknown }).randomBytes = (
		size: number
	): Buffer => {
		const out = Buffer.alloc(size);
		const n = counter++;
		for (let i = 0; i < size; i += 32) {
			sha(`ordinary-rounds:${kind}:${n}:${i}`).copy(out, i);
		}
		return out;
	};
	try {
		const rows: string[] = [];
		const config = (name: 'alice' | 'bob'): IChannelManagerConfig => ({
			...engine.configOf(
				engine.seedFor(name === 'alice' ? 4100 : 4101),
				kind === 'taproot' && name === 'alice'
			),
			...(kind === 'anchors' ? { preferAnchors: true } : {}),
			persistence: {
				persist: (request: IChannelPersistRequest): IChannelPersistResult => {
					rows.push(
						`${name}:${stable(
							engine.serializeChannelState(request.channel.getFullState())
						)}`
					);
					return {
						committed: true,
						outboxIds:
							request.outbox?.outbound.map((_message, index) => index + 1) ?? []
					};
				}
			},
			...extraConfig
		});
		const aliceConfig = config('alice');
		const bobConfig = config('bob');
		const alice = new engine.ChannelManager(aliceConfig);
		const bob = new engine.ChannelManager(bobConfig);
		const alicePubkey =
			aliceConfig.localBasepoints.fundingPubkey.toString('hex');
		const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');
		const wire: string[] = [];
		const types: string[] = [];
		const errors: string[] = [];
		const link = (
			tag: 'a' | 'b',
			source: ChannelManager,
			sourcePubkey: string,
			target: ChannelManager,
			targetPubkey: string
		): void => {
			source.on('error', (_id: unknown, message: unknown) => {
				errors.push(`${tag}: ${String(message)}`);
			});
			source.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== targetPubkey) return;
					types.push(`${tag}${type}`);
					wire.push(`${tag}:${type}:${payload.toString('hex')}`);
					target.handleMessage(sourcePubkey, type, payload);
				}
			);
		};
		link('a', alice, alicePubkey, bob, bobPubkey);
		link('b', bob, bobPubkey, alice, alicePubkey);
		const must = (
			what: string,
			result: { ok: boolean; error?: string }
		): void => {
			if (!result.ok) {
				throw new Error(`${kind}: ${what} failed: ${result.error ?? ''}`);
			}
		};

		// Open, with a push so that both sides can pay.
		const channel = alice.openChannel(bobPubkey, 3_000_000n, 1_000_000_000n);
		const fundingTxid = sha(`ordinary rounds funding ${kind}`);
		const state = channel.getFullState();
		let signature: Buffer = Buffer.alloc(64, 1);
		if (!engine.isTaprootChannel(state.channelType)) {
			channel.setFundingOutpoint(fundingTxid, 0);
			signature = engine.signRemoteCommitment(
				state as IChannelState,
				channel.getSigner()!,
				state.remoteCurrentPerCommitmentPoint!
			).signature;
		}
		const id = alice.createFunding(channel, fundingTxid, 0, signature);
		if (!id) throw new Error(`${kind}: funding failed: ${errors.join('; ')}`);
		alice.handleFundingConfirmed(id);
		bob.handleFundingConfirmed(id);

		// Six adds: four from the opener, two from the acceptor. One is small
		// enough to be trimmed where HTLC transactions pay their own fee.
		const preimage = (label: string): Buffer => sha(`ordinary rounds ${label}`);
		const add = (
			from: ChannelManager,
			label: string,
			amountMsat: bigint,
			cltv: number
		): void =>
			must(
				`add ${label}`,
				from.addHtlc(
					id,
					amountMsat,
					sha(preimage(label)),
					cltv,
					Buffer.alloc(1366, cltv % 251)
				)
			);
		add(alice, 'a0', 60_000_000n, 500);
		add(alice, 'a1', 45_000_000n, 501);
		add(bob, 'b0', 30_000_000n, 502);
		add(alice, 'a2', 600_000n, 503);
		add(bob, 'b1', 25_000_000n, 504);
		add(alice, 'a3', 20_000_000n, 505);

		// Two fee updates, up and down.
		must('fee up', alice.updateChannelFee(id, 3000));
		must('fee down', alice.updateChannelFee(id, 1800));

		// A fulfil and a fail in each direction; the rest stay in flight.
		must('fulfil a0', bob.fulfillHtlc(id, 0n, preimage('a0')));
		must('fulfil b0', alice.fulfillHtlc(id, 0n, preimage('b0')));
		must('fail a1', bob.failHtlc(id, 1n, Buffer.alloc(32, 7)));
		must('fail b1', alice.failHtlc(id, 1n, Buffer.alloc(32, 8)));
		if (errors.length > 0) {
			throw new Error(`${kind}: ${errors.join('; ')}`);
		}

		const finalRows = stable([
			engine.serializeChannelState(
				alice.getChannel(id)!.getFullState() as IChannelState
			),
			engine.serializeChannelState(
				bob.getChannel(id)!.getFullState() as IChannelState
			)
		]);
		const destination = Buffer.concat([
			Buffer.from('0014', 'hex'),
			Buffer.alloc(20, 0x42)
		]);
		const closed = (closer === 'alice' ? alice : bob).forceClose(
			id,
			destination,
			10
		);
		return {
			types: types.join(' '),
			messages: wire.length,
			wire: sha(wire.join('\n')).toString('hex'),
			rowsStored: rows.length,
			rows: sha(rows.join('\n')).toString('hex'),
			finalRows: sha(finalRows).toString('hex'),
			keyIndexes: `${alice.nextChannelIndex},${bob.nextChannelIndex}`,
			forceClose: sha(
				stable({ ok: closed.ok, error: closed.error, actions: closed.actions })
			).toString('hex')
		};
	} finally {
		(crypto as unknown as { randomBytes: unknown }).randomBytes =
			realRandomBytes;
	}
}
