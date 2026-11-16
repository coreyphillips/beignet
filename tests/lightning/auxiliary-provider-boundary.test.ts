/**
 * The asset provider at the edge of a commitment round (issue #2093 step 6).
 *
 * The provider is asked once about a commitment, what it answers is checked
 * where it comes in, an update it cannot answer for is refused before
 * anything is sent or stored, and a channel's row holds the asset side of
 * the commitments that can still be broadcast, not of every one it signed.
 */

import { markAuxiliaryRevokedViewsStored } from '../../src/lightning/channel/auxiliary-revoked';
import { serializeAuxiliaryCommitmentView } from '../../src/lightning/storage/auxiliary-serialization';
import { expect } from 'chai';
import type { Channel } from '../../src/lightning/channel/channel';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import { AuxiliaryProviderError } from '../../src/lightning/channel/auxiliary';
import {
	ChannelActionType,
	ChannelErrorCode
} from '../../src/lightning/channel/channel-actions';
import type { ChannelResult } from '../../src/lightning/channel/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { sha256 } from '../../src/lightning/crypto/provider';
import { MessageType } from '../../src/lightning/message/types';
import { encodeFrame } from '../../src/lightning/recovery/frame-codec';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import type { IAssetPair } from './helpers/auxiliary-pair';
import { amountRecord, leafFor, taprootPair } from './helpers/auxiliary-pair';
import { channelStateFrame } from './helpers/auxiliary-state-fixture';
import { writableState } from './helpers/writable-state';

const row = (channel: Channel): string =>
	JSON.stringify(serializeChannelState(channel.getFullState()));

const kinds = (pair: IAssetPair, from = 0): string =>
	pair.wire
		.slice(from)
		.map((message) => `${message.from}:${message.type}`)
		.join(' ');

/** Count what a provider is asked, by side and commitment number. */
function counted(provider: IChannelAuxiliaryProvider): Map<string, number> {
	const asked = new Map<string, number>();
	const inner = provider.buildCommitment;
	provider.buildCommitment = (context) => {
		const key = `${context.side}:${context.commitmentNumber}`;
		asked.set(key, (asked.get(key) ?? 0) + 1);
		const data = inner(context);
		// Every call answers with data of its own, so a test can tell which
		// answer was kept.
		data.customData = Buffer.from(`${key} answer ${asked.get(key)}`);
		return data;
	};
	return asked;
}

const down = (): never => {
	throw new Error('asset store is down');
};

describe('the asset provider at the edge of a commitment round (issue #2093 step 6)', function () {
	this.timeout(60_000);

	/** Alice pays Bob one HTLC and the round completes. */
	function addHtlc(
		pair: IAssetPair,
		label: string,
		amountMsat = 50_000_000n
	): Buffer {
		const preimage = sha256(Buffer.from(`boundary preimage ${label}`));
		// An asset channel offers only HTLCs that carry asset units.
		const carriesAssets =
			pair.aliceChannel.getFullState().auxiliaryState !== undefined;
		const result = pair.alice.addHtlc(
			pair.id,
			amountMsat,
			sha256(preimage),
			500,
			Buffer.alloc(1366),
			undefined,
			undefined,
			carriesAssets ? { customRecords: amountRecord(1n) } : undefined
		);
		expect(result.ok, result.error).to.equal(true);
		return preimage;
	}

	/** The call refused by name, with nothing sent and neither row changed. */
	function refusedCleanly(
		pair: IAssetPair,
		operation: string,
		act: () => ChannelResult
	): void {
		const sent = pair.wire.length;
		const rows = [row(pair.aliceChannel), row(pair.bobChannel)];
		const errors = pair.errors.length;
		const result = act();
		const hex = pair.id.toString('hex');
		expect(result.ok).to.equal(false);
		expect(result.error).to.equal(
			`The asset provider refused ${operation} (channel ${hex}): asset store is down`
		);
		expect((result as { code?: string }).code).to.equal(
			ChannelErrorCode.ASSET_PROVIDER_REFUSED
		);
		expect(kinds(pair, sent), 'nothing went on the wire').to.equal('');
		expect([row(pair.aliceChannel), row(pair.bobChannel)]).to.deep.equal(rows);
		// The refusal is reported, by name.
		expect(pair.errors.slice(errors).join('\n')).to.include(
			`The asset provider refused ${operation} (channel ${hex})`
		);
	}

	it('asks the provider once about each commitment, and keeps the answer the signature was verified against', () => {
		const pair = taprootPair(7001);
		const alice = counted(pair.aliceProvider);
		const bob = counted(pair.bobProvider);
		expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);
		addHtlc(pair, 'once');
		expect(pair.errors).to.deep.equal([]);
		for (const asked of [alice, bob]) {
			expect([...asked.entries()].sort()).to.deep.equal([
				['local:1', 1],
				['local:2', 1],
				['remote:1', 1],
				['remote:2', 1]
			]);
		}
		for (const channel of [pair.aliceChannel, pair.bobChannel]) {
			const auxiliary = channel.getFullState().auxiliaryState!;
			expect(
				auxiliary.localCommitments.get(2n)!.customData.toString()
			).to.equal('local:2 answer 1');
			expect(
				auxiliary.remoteCommitments.get(2n)!.customData.toString()
			).to.equal('remote:2 answer 1');
		}
		// The answers are not stored: a restart asks again.
		expect(row(pair.aliceChannel)).not.to.include('auxiliaryAnswers');
	});

	describe('an update the provider cannot answer for is refused before anything is sent or stored', () => {
		it('an HTLC', () => {
			const pair = taprootPair(7010);
			const healthy = pair.aliceProvider.buildCommitment;
			pair.aliceProvider.buildCommitment = down;
			refusedCleanly(pair, 'an HTLC', () =>
				pair.alice.addHtlc(
					pair.id,
					50_000_000n,
					sha256(Buffer.from('refused')),
					500,
					Buffer.alloc(1366),
					undefined,
					undefined,
					{ customRecords: amountRecord(1n) }
				)
			);
			expect(pair.aliceChannel.getFullState().localHtlcCounter).to.equal(0n);
			pair.aliceProvider.buildCommitment = healthy;
			addHtlc(pair, 'after the provider came back');
			expect(pair.bobChannel.getFullState().htlcs.size).to.equal(1);
		});

		it('a fee update', () => {
			const pair = taprootPair(7020);
			const healthy = pair.aliceProvider.buildCommitment;
			pair.aliceProvider.buildCommitment = down;
			refusedCleanly(pair, 'a fee update', () =>
				pair.alice.updateChannelFee(pair.id, 700)
			);
			expect(pair.aliceChannel.getFullState().pendingFeeratePerKw).to.equal(
				undefined
			);
			pair.aliceProvider.buildCommitment = healthy;
			expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);
			expect(
				pair.aliceChannel.getFullState().localConfig.feeratePerKw
			).to.equal(700);
			expect(pair.bobChannel.getFullState().remoteConfig.feeratePerKw).to.equal(
				700
			);
		});

		it('the settlement of an HTLC', () => {
			const pair = taprootPair(7030);
			const preimage = addHtlc(pair, 'to settle');
			const healthy = pair.bobProvider.buildCommitment;
			pair.bobProvider.buildCommitment = down;
			refusedCleanly(pair, 'the settlement of an HTLC', () =>
				pair.bob.fulfillHtlc(pair.id, 0n, preimage)
			);
			pair.bobProvider.buildCommitment = healthy;
			expect(pair.bob.fulfillHtlc(pair.id, 0n, preimage).ok).to.equal(true);
			expect(pair.aliceChannel.getFullState().htlcs.size).to.equal(0);
			expect(pair.bobChannel.getFullState().htlcs.size).to.equal(0);
			expect(pair.errors).to.have.length(1);
		});

		it('the failure of an HTLC', () => {
			const pair = taprootPair(7040);
			addHtlc(pair, 'to fail');
			const healthy = pair.bobProvider.buildCommitment;
			pair.bobProvider.buildCommitment = down;
			refusedCleanly(pair, 'the failure of an HTLC', () =>
				pair.bob.failHtlc(pair.id, 0n, Buffer.alloc(32, 2))
			);
			pair.bobProvider.buildCommitment = healthy;
			expect(pair.bob.failHtlc(pair.id, 0n, Buffer.alloc(32, 2)).ok).to.equal(
				true
			);
			expect(pair.aliceChannel.getFullState().htlcs.size).to.equal(0);
		});
	});

	it('refuses a commitment it owes, at once and again after a reconnect, without throwing, and signs when the provider is back', () => {
		const pair = taprootPair(7050);
		const hex = pair.id.toString('hex');
		// The update is made and reaches the peer; the node then loses its
		// provider before it has signed, as a restart with the asset store
		// unavailable would leave it.
		const staged = pair.aliceChannel.updateFee(700);
		for (const action of staged) {
			if (action.type !== ChannelActionType.SEND_MESSAGE) continue;
			pair.bob.handleMessage(
				pair.alicePubkey,
				action.messageType,
				action.payload
			);
		}
		const healthy = pair.aliceProvider.buildCommitment;
		pair.aliceProvider.buildCommitment = down;
		delete writableState(pair.aliceChannel).auxiliaryAnswers;

		const before = row(pair.aliceChannel);
		const refused = pair.alice.autoSignAndSendCommitment(pair.id);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.equal(
			`The asset provider refused a commitment (channel ${hex}): asset store is down`
		);
		expect((refused as { code?: string }).code).to.equal(
			ChannelErrorCode.ASSET_PROVIDER_REFUSED
		);
		expect(kinds(pair)).to.equal('');
		expect(row(pair.aliceChannel)).to.equal(before);
		expect(pair.errors.join('\n')).to.include(
			`The asset provider refused a commitment (channel ${hex})`
		);

		// A reconnect: each side's channel_reestablish is held until both
		// are made, then delivered.
		const held: Array<{ from: 'alice' | 'bob'; payload: Buffer }> = [];
		pair.intercept.fn = (from, type, payload): Buffer | null => {
			if (type !== MessageType.CHANNEL_REESTABLISH) return payload;
			held.push({ from, payload });
			return null;
		};
		pair.alice.handlePeerDisconnected(pair.bobPubkey);
		pair.bob.handlePeerDisconnected(pair.alicePubkey);
		pair.alice.handlePeerReconnected(pair.bobPubkey);
		pair.bob.handlePeerReconnected(pair.alicePubkey);
		pair.intercept.fn = undefined;
		expect(held.map((message) => message.from).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		const reported = pair.errors.length;
		expect(() => {
			for (const message of held) {
				(message.from === 'alice' ? pair.bob : pair.alice).handleMessage(
					message.from === 'alice' ? pair.alicePubkey : pair.bobPubkey,
					MessageType.CHANNEL_REESTABLISH,
					message.payload
				);
			}
		}).not.to.throw();
		expect(kinds(pair)).not.to.include(
			`alice:${MessageType.COMMITMENT_SIGNED}`
		);
		expect(pair.errors.slice(reported).join('\n')).to.include(
			`The asset provider refused a commitment (channel ${hex})`
		);
		expect(pair.aliceChannel.getFullState().state).to.equal(
			ChannelState.NORMAL
		);

		// The provider is back: the same call signs, and the round completes.
		pair.aliceProvider.buildCommitment = healthy;
		const sent = pair.wire.length;
		const signed = pair.alice.autoSignAndSendCommitment(pair.id);
		expect(signed.ok, signed.error).to.equal(true);
		expect(kinds(pair, sent)).to.match(/^alice:132 bob:133/);
		expect(pair.aliceChannel.getFullState().needsCommitment).to.equal(false);
	});

	describe('what the provider answers is checked before anything is signed on it', () => {
		const cases: Array<
			[
				string,
				(
					data: ReturnType<IChannelAuxiliaryProvider['buildCommitment']>
				) => void,
				RegExp
			]
		> = [
			[
				'a second-level leaf under a key that names no HTLC',
				(data): void => {
					data.secondLevelLeaves.set('BOGUS', leafFor('child'));
				},
				/Malformed asset commitment from the provider: Malformed serialized asset HTLC identity/
			],
			[
				'a second-level leaf for an HTLC the commitment does not have',
				(data): void => {
					data.secondLevelLeaves.set('OFFERED:99', leafFor('child'));
				},
				/second-level leaf for no HTLC output of the commitment/
			],
			[
				'a leaf that is not a leaf',
				(data): void => {
					data.outputLeaves.set(0, { version: 0xc0 } as never);
				},
				/Malformed asset commitment from the provider/
			],
			[
				'no answer at all',
				(data): void => {
					(data as { outputLeaves?: unknown }).outputLeaves = undefined;
				},
				/Malformed asset commitment from the provider/
			]
		];
		for (const [name, damage, reason] of cases) {
			it(name, () => {
				const pair = taprootPair(7060);
				const inner = pair.aliceProvider.buildCommitment;
				pair.aliceProvider.buildCommitment = (context) => {
					const data = inner(context);
					damage(data);
					return data;
				};
				const sent = pair.wire.length;
				const before = row(pair.aliceChannel);
				const result = pair.alice.updateChannelFee(pair.id, 700);
				expect(result.ok).to.equal(false);
				expect(result.error).to.match(reason);
				expect(result.error).to.include(`(channel ${pair.id.toString('hex')})`);
				expect(kinds(pair, sent)).to.equal('');
				expect(row(pair.aliceChannel)).to.equal(before);
				// The row is still one the writer can write.
				pair.aliceProvider.buildCommitment = inner;
				expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);
				expect(() => row(pair.aliceChannel)).not.to.throw();
			});
		}

		it('and what the peer provider answers wrongly fails the commitment it was asked about, not a later write', () => {
			const pair = taprootPair(7070);
			const inner = pair.bobProvider.buildCommitment;
			pair.bobProvider.buildCommitment = (context) => {
				const data = inner(context);
				data.secondLevelLeaves.set('BOGUS', leafFor('child'));
				return data;
			};
			pair.alice.updateChannelFee(pair.id, 700);
			expect(pair.errors.join('\n')).to.include(
				'Invalid asset commitment metadata'
			);
			expect(() => row(pair.bobChannel)).not.to.throw();
			expect(
				pair.bobChannel.getFullState().auxiliaryState!.localCommitments.size
			).to.equal(0);
		});
	});

	it('keeps the asset side of the row and of its recovery frame bounded over a long life', function () {
		this.timeout(180_000);
		// The same life lived by an asset channel and by an ordinary taproot
		// channel: fee updates and payments, settled and failed, each a full
		// round on both sides. What an ordinary channel's row gains over that
		// life is its own; the asset channel may not gain more.
		const asset = taprootPair(7080);
		const plain = taprootPair(7082, { asset: false });
		const sizes = (
			channel: Channel
		): { row: number; frame: number; assets: number } => {
			const serialized = serializeChannelState(channel.getFullState());
			return {
				row: JSON.stringify(serialized).length,
				frame: encodeFrame(channelStateFrame(channel.getFullState(), 5)).length,
				assets: JSON.stringify(
					(serialized as { auxiliaryState?: unknown }).auxiliaryState ?? null
				).length
			};
		};
		const round = (pair: IAssetPair, index: number): void => {
			if (index % 3 === 0) {
				expect(
					pair.alice.updateChannelFee(pair.id, 600 + (index % 200)).ok
				).to.equal(true);
				return;
			}
			const preimage = addHtlc(pair, `round ${index}`, 2_000_000n);
			const id = pair.aliceChannel.getFullState().localHtlcCounter - 1n;
			const settled =
				index % 3 === 1
					? pair.bob.fulfillHtlc(pair.id, id, preimage)
					: pair.bob.failHtlc(pair.id, id, Buffer.alloc(32, 3));
			expect(settled.ok, settled.error).to.equal(true);
		};
		const measure = (): Record<string, ReturnType<typeof sizes>> => ({
			assetAlice: sizes(asset.aliceChannel),
			assetBob: sizes(asset.bobChannel),
			plainAlice: sizes(plain.aliceChannel),
			plainBob: sizes(plain.bobChannel)
		});
		// The view of each revoked commitment of the peer leaves the row for
		// the store of revoked views, which the storage of a node writes with
		// the row and from which it is let go once that has committed
		// (auxiliary-revoked-store.test.ts). Here the store is a list of the
		// sizes of what it was handed.
		const store: Record<'Alice' | 'Bob', number[]> = { Alice: [], Bob: [] };
		const keep = (): void => {
			for (const who of ['Alice', 'Bob'] as const) {
				const state = (
					who === 'Alice' ? asset.aliceChannel : asset.bobChannel
				).getFullState();
				const views = state.auxiliaryState!.revokedCommitments;
				if (!views) continue;
				for (const view of views.values()) {
					store[who].push(serializeAuxiliaryCommitmentView(view).length);
				}
				markAuxiliaryRevokedViewsStored(state, [...views.keys()]);
			}
		};
		for (let index = 0; index < 9; index++) {
			round(asset, index);
			keep();
			round(plain, index);
		}
		const early = measure();
		for (let index = 9; index < 42; index++) {
			round(asset, index);
			keep();
			round(plain, index);
		}
		const late = measure();
		expect(asset.errors).to.deep.equal([]);
		expect(plain.errors).to.deep.equal([]);
		for (const who of ['Alice', 'Bob'] as const) {
			const auxiliary = (
				who === 'Alice' ? asset.aliceChannel : asset.bobChannel
			).getFullState().auxiliaryState!;
			expect(auxiliary.localCommitments.size).to.be.at.most(2);
			expect(auxiliary.remoteCommitments.size).to.be.at.most(2);
			// The store was handed one view for each revoked commitment whose
			// view left the row, each of a size that does not grow: the life
			// repeats every three rounds, so eighteen entries early weigh
			// what eighteen entries late do, give or take the digits of the
			// counters in each.
			expect(auxiliary.revokedCommitments).to.equal(undefined);
			const entries = store[who];
			const revoked = Number(
				(who === 'Alice' ? asset.aliceChannel : asset.bobChannel).getFullState()
					.remoteCommitmentNumber
			);
			expect(revoked - entries.length).to.be.within(0, 3);
			expect(entries.length).to.be.greaterThan(60);
			const weigh = (part: number[]): number =>
				part.reduce((sum, bytes) => sum + bytes, 0);
			expect(
				Math.abs(weigh(entries.slice(6, 24)) - weigh(entries.slice(-18)))
			).to.be.below(18 * 16);
			expect(Math.max(...entries)).to.be.below(2048);
			const a = `asset${who}`;
			const p = `plain${who}`;
			// The asset state itself is the size it was thirty rounds earlier,
			// give or take the digits of a counter.
			expect(late[a].assets - early[a].assets).to.be.below(64);
			expect(late[a].assets).to.be.below(4096);
			// And the row and the frame gained no more than an ordinary
			// channel's did.
			for (const part of ['row', 'frame'] as const) {
				const gained = late[a][part] - early[a][part];
				const ordinary = late[p][part] - early[p][part];
				expect(gained - ordinary, `${who} ${part}`).to.be.below(256);
			}
		}
	});

	it('names the channel in a typed error', () => {
		const error = new AuxiliaryProviderError('ab'.repeat(32), 'an HTLC', 'no');
		expect(error.code).to.equal('ASSET_PROVIDER_REFUSED');
		expect(error.channelId).to.equal('ab'.repeat(32));
		expect(error.message).to.equal(
			`The asset provider refused an HTLC (channel ${'ab'.repeat(32)}): no`
		);
	});
});
