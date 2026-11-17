/**
 * The cooperative close of an ordinary channel, reduced to digests (issue
 * #2093): open, an HTLC each way, a shutdown while one of them is still in
 * flight, the drain, the fee negotiation and the closing transaction either
 * side hands on to be published.
 *
 * Like ordinary-rounds, this runs against any source tree that offers the
 * engine below, under a counter in place of randomness, so the digests of
 * the previous release's source can be pinned and compared with this one's.
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
import type { IOrdinaryRoundsEngine, OrdinaryKind } from './ordinary-rounds';

export interface IOrdinaryCloseDigests {
	/** Message types in order of sending, `a` for the opener, `b` for the acceptor. */
	types: string;
	wire: string;
	rowsStored: number;
	rows: string;
	finalRows: string;
	/** The closing transactions handed on to be published, `a:` or `b:` and the hex. */
	published: string[];
	errors: string[];
}

const sha = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

const stable = (value: unknown): string =>
	JSON.stringify(value, (_key, item) =>
		typeof item === 'bigint'
			? `${item}n`
			: Buffer.isBuffer(item)
			? item.toString('hex')
			: item instanceof Map
			? [...item.entries()]
			: item
	);

export function ordinaryClose(
	engine: IOrdinaryRoundsEngine,
	kind: OrdinaryKind,
	closer: 'alice' | 'bob',
	extraConfig: Partial<IChannelManagerConfig> = {}
): IOrdinaryCloseDigests {
	const realRandomBytes = crypto.randomBytes;
	engine.randomBytes(1);
	let counter = 0;
	(crypto as unknown as { randomBytes: unknown }).randomBytes = (
		size: number
	): Buffer => {
		const out = Buffer.alloc(size);
		const n = counter++;
		for (let i = 0; i < size; i += 32) {
			sha(`ordinary-close:${kind}:${n}:${i}`).copy(out, i);
		}
		return out;
	};
	try {
		const rows: string[] = [];
		const config = (name: 'alice' | 'bob'): IChannelManagerConfig => ({
			...engine.configOf(
				engine.seedFor(name === 'alice' ? 4200 : 4201),
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
		const published: string[] = [];
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
			source.on('broadcast:tx', (tx: Buffer) => {
				published.push(`${tag}:${tx.toString('hex')}`);
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

		const channel = alice.openChannel(bobPubkey, 3_000_000n, 1_000_000_000n);
		const fundingTxid = sha(`ordinary close funding ${kind}`);
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

		const preimage = (label: string): Buffer => sha(`ordinary close ${label}`);
		must(
			'add a0',
			alice.addHtlc(
				id,
				60_000_000n,
				sha(preimage('a0')),
				500,
				Buffer.alloc(1366, 1)
			)
		);
		must(
			'add b0',
			bob.addHtlc(
				id,
				30_000_000n,
				sha(preimage('b0')),
				502,
				Buffer.alloc(1366, 2)
			)
		);
		must('fulfil a0', bob.fulfillHtlc(id, 0n, preimage('a0')));

		// The shutdown goes out while b0 is still in flight; the channel
		// negotiates its close once b0 is settled.
		const destination = Buffer.concat([
			Buffer.from('0014', 'hex'),
			Buffer.alloc(20, 0x42)
		]);
		must(
			'shutdown',
			(closer === 'alice' ? alice : bob).initiateShutdown(id, destination)
		);
		must('fulfil b0', alice.fulfillHtlc(id, 0n, preimage('b0')));

		const finalRows = stable(
			[alice, bob].map((manager) => {
				const closed = manager.getChannel(id);
				return closed
					? engine.serializeChannelState(closed.getFullState() as IChannelState)
					: 'gone';
			})
		);
		return {
			types: types.join(' '),
			wire: sha(wire.join('\n')).toString('hex'),
			rowsStored: rows.length,
			rows: sha(rows.join('\n')).toString('hex'),
			finalRows: sha(finalRows).toString('hex'),
			published,
			errors
		};
	} finally {
		(crypto as unknown as { randomBytes: unknown }).randomBytes =
			realRandomBytes;
	}
}
