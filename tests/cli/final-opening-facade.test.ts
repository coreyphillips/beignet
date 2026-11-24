import { rejects } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	alice,
	bob,
	signingFixture
} from '../lightning/helpers/final-opening-signing';
import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import {
	finalOpeningChannelType,
	finalOpeningNegotiated
} from '../../src/lightning/features/final-opening';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';

const peer = '02' + 'ab'.repeat(32);

describe('Final opening public options', () => {
	it('passes the explicit option and normal fee arguments while refusing unsupported financial terms before the engine', () => {
		const calls: Record<string, unknown>[] = [];
		const facade: BeignetNode = Object.assign(
			Object.create(BeignetNode.prototype),
			{
				node: {
					openChannelV2: (_peer: string, params: Record<string, unknown>) => {
						calls.push(params);
						return {
							getFullState: () => ({
								temporaryChannelId: Buffer.alloc(32, 1),
								channelType: finalOpeningChannelType(),
								commitmentProfile: 'simple-taproot-final',
								state: 'WAIT_FOR_ACCEPT_CHANNEL2'
							}),
							getBalances: () => ({ localMsat: 80_000_000n, remoteMsat: 0n })
						};
					}
				},
				_bootOpts: { finalTaprootWallet: true }
			}
		);
		const request = {
			amountSats: 80_000,
			finalTaproot: true,
			fundingFeeratePerkw: 253,
			commitmentFeeratePerkw: 300,
			locktime: 5
		};
		const result = facade.openChannelV2(peer, request);
		expect(result.isAnchor).to.equal(true);
		expect(calls[0]).to.include({
			finalTaproot: true,
			fundingSatoshis: 80_000n,
			locktime: 5,
			fundingFeeratePerkw: 253,
			commitmentFeeratePerkw: 300
		});
		for (const extra of [
			{ finalTaproot: 'true' },
			{ pushSats: 1 },
			{ requestFunds: { requestedSats: 500, blockheight: 100 } },
			{ channelFlags: 1 },
			{ trusted: true }
		]) {
			expect(() =>
				facade.openChannelV2(peer, { ...request, ...extra } as typeof request)
			).to.throw(BeignetError);
		}
		expect(calls).to.have.length(1);
		facade.openChannelV2(peer, { amountSats: 80_000 });
		expect(calls[1]).not.to.have.property('finalTaproot');
	});

	it('requires both init vectors to agree on the exact proposed type and dependencies', () => {
		const required = [
			Feature.OPTION_SIMPLE_TAPROOT,
			Feature.CHANNEL_TYPE,
			Feature.SHUTDOWN_ANY_SEGWIT,
			Feature.SIMPLE_CLOSE,
			Feature.DUAL_FUND
		];
		const features = (): FeatureFlags => {
			const flags = FeatureFlags.empty();
			for (const feature of required) flags.setOptional(feature);
			return flags;
		};
		const base = finalOpeningChannelType();
		for (const feature of required) {
			const missing = features();
			missing.clearBit(feature + 1);
			expect(finalOpeningNegotiated(missing, features(), base)).to.equal(false);
			expect(finalOpeningNegotiated(features(), missing, base)).to.equal(false);
		}
		const aliased = FeatureFlags.fromBuffer(base);
		aliased.setCompulsory(Feature.SCID_ALIAS);
		const local = features(),
			remote = features();
		expect(finalOpeningNegotiated(local, remote, base)).to.equal(true);
		local.setOptional(Feature.SCID_ALIAS);
		expect(finalOpeningNegotiated(local, remote, aliased.toBuffer())).to.equal(
			false
		);
		remote.setOptional(Feature.SCID_ALIAS);
		expect(finalOpeningNegotiated(local, remote, aliased.toBuffer())).to.equal(
			true
		);
		aliased.setOptional(Feature.OPTION_SIMPLE_TAPROOT);
		expect(finalOpeningNegotiated(local, remote, aliased.toBuffer())).to.equal(
			false
		);
	});
});

describe('Public final opening input reservations', () => {
	it('unfreezes an unrelated coin and retains the original wallet input across restart', async () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-final-unfreeze-')
		);
		const file = path.join(dir, 'regtest.db');
		const { binding } = generateFinalDaemonWallet();
		const { candidate, terms, funding } = signingFixture();
		const index = candidate.inputs.findIndex((input) => input.isLocal);
		const input = funding.ins[index];
		const txid = Buffer.from(input.hash).reverse().toString('hex');
		const unrelated = '98'.repeat(32);
		const released: string[] = [];
		let store: SqliteStorage | undefined;
		try {
			store = SqliteStorage.createFinalWallet(file, binding);
			store.allocateFinalChannelKeyIndex(alice.index);
			store.rememberFinalOpeningSession(
				candidate,
				bob.binding.nodeId,
				terms,
				alice.index
			);
			store.close();
			store = SqliteStorage.openFinalWallet(file, binding);
			store.assertFinalDaemonIdentity(binding.nodeId);
			const facade: BeignetNode = Object.assign(
				Object.create(BeignetNode.prototype),
				{
					storage: store,
					networkName: 'regtest',
					_bootOpts: { finalTaprootWallet: true },
					_onchainSendLock: Promise.resolve(),
					wallet: {
						unfreezeUtxo: async (out: { txid: string; vout: number }) => {
							released.push(out.txid + ':' + out.vout);
							return { isErr: () => false };
						}
					}
				}
			);
			expect(await facade.unfreezeUtxo(unrelated, 0)).to.deep.equal({
				unfrozen: unrelated + ':0'
			});
			await rejects(() => facade.unfreezeUtxo(txid, input.index));
			expect(released).to.deep.equal([unrelated + ':0']);
		} finally {
			store?.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
