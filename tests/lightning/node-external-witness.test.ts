/**
 * LightningNode surface for v2 external funding inputs (issue #572):
 *
 *  - the channel:txsigs-needed relay passes the externalInputIndices fifth
 *    argument through to the node event (it was silently dropped before);
 *  - provideV2ExternalWitness validates its inputs, delegates to the
 *    manager, and surfaces failures as PROVIDE_EXTERNAL_WITNESS_FAILED;
 *  - getRawChannel resolves both permanent-map channels and temp-resident
 *    channels looked up by their derived permanent id;
 *  - IChannelInfo.fundingOutputIndex is present exactly when fundingTxid is.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ILightningError } from '../../src/lightning/node/types';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function createTestNode(): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('external-witness-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('external-witness-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

interface IInjected {
	channelId: Buffer;
	channel: Channel;
}

/** Inject a synthetic channel directly into the node's manager. */
function injectChannel(
	node: LightningNode,
	opts: { funded: boolean; tempResident?: boolean }
): IInjected {
	const seed = crypto.randomBytes(32);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	if (opts.funded) {
		state.fundingTxid = crypto.randomBytes(32);
		state.fundingOutputIndex = 1;
	}
	state.localBalanceMsat = 1_000_000_000n;
	state.remoteBalanceMsat = 0n;
	const channel = new Channel(state);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = (node as any).channelManager;
	const peer = '02'.padEnd(66, 'ab');
	if (opts.tempResident) {
		// The live v2 exchange keeps the channel keyed by its TEMPORARY id
		// while the derived permanent id is already set on the state.
		const tempHex = state.temporaryChannelId.toString('hex');
		manager.tempChannels.set(tempHex, channel);
		manager.channelPeers.set(tempHex, peer);
	} else {
		manager.channels.set(state.channelId!.toString('hex'), channel);
		manager.channelPeers.set(state.channelId!.toString('hex'), peer);
	}
	return { channelId: state.channelId!, channel };
}

describe('LightningNode external-witness surface (issue #572)', function () {
	it('relays externalInputIndices on channel:txsigs-needed', function () {
		const node = createTestNode();
		const seen: Array<{
			inputIndices: number[];
			externalInputIndices?: number[];
		}> = [];
		node.on(
			'channel:txsigs-needed',
			(data: { inputIndices: number[]; externalInputIndices?: number[] }) => {
				seen.push(data);
			}
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = (node as any).channelManager;
		manager.emit(
			'channel:txsigs-needed',
			crypto.randomBytes(32),
			crypto.randomBytes(32),
			0,
			[0, 1, 2],
			[2]
		);
		manager.emit(
			'channel:txsigs-needed',
			crypto.randomBytes(32),
			crypto.randomBytes(32),
			0,
			[0]
		);
		expect(seen).to.have.length(2);
		expect(seen[0].inputIndices).to.deep.equal([0, 1, 2]);
		expect(seen[0].externalInputIndices).to.deep.equal([2]);
		expect(seen[1].externalInputIndices).to.equal(undefined);
		node.destroy();
	});

	it('provideV2ExternalWitness validates shapes and surfaces failures', function () {
		const node = createTestNode();
		const errors: ILightningError[] = [];
		node.on('node:error', (err: ILightningError) => errors.push(err));

		// Shape validation throws (API misuse, not a channel failure).
		expect(() =>
			node.provideV2ExternalWitness(Buffer.alloc(16), Buffer.alloc(32), 0, [])
		).to.throw(/channelId/);
		expect(() =>
			node.provideV2ExternalWitness(Buffer.alloc(32), Buffer.alloc(16), 0, [])
		).to.throw(/prevTxid/);
		expect(() =>
			node.provideV2ExternalWitness(Buffer.alloc(32), Buffer.alloc(32), -1, [])
		).to.throw(/prevOutputIndex/);
		expect(() =>
			node.provideV2ExternalWitness(Buffer.alloc(32), Buffer.alloc(32), 0, [
				'nope' as unknown as Buffer
			])
		).to.throw(/witness/);
		expect(errors, 'validation throws are not node errors').to.have.length(0);

		// An unknown channel is a failed delivery: refused result plus a
		// PROVIDE_EXTERNAL_WITNESS_FAILED node error naming the channel.
		const unknown = crypto.randomBytes(32);
		const result = node.provideV2ExternalWitness(
			unknown,
			crypto.randomBytes(32),
			0,
			[crypto.randomBytes(71)]
		);
		expect(result.ok).to.equal(false);
		expect(result.error).to.match(/Channel not found/);
		// The manager's lookup miss also relays as a CHANNEL_ERROR; the
		// dedicated code is what a Phase 4 caller keys on.
		const failed = errors.filter(
			(e) => e.code === 'PROVIDE_EXTERNAL_WITNESS_FAILED'
		);
		expect(failed).to.have.length(1);
		expect(failed[0].channelId?.equals(unknown)).to.equal(true);
		node.destroy();
	});

	it('getRawChannel resolves permanent and temp-resident channels', function () {
		const node = createTestNode();
		const permanent = injectChannel(node, { funded: true });
		const tempResident = injectChannel(node, {
			funded: false,
			tempResident: true
		});

		expect(node.getRawChannel(permanent.channelId)).to.equal(permanent.channel);
		// The temp-resident channel is found by its DERIVED permanent id,
		// which the plain map lookup alone cannot resolve.
		expect(node.getRawChannel(tempResident.channelId)).to.equal(
			tempResident.channel
		);
		expect(node.getRawChannel(crypto.randomBytes(32))).to.equal(null);
		node.destroy();
	});

	it('reports fundingOutputIndex exactly when fundingTxid is present', function () {
		const node = createTestNode();
		const funded = injectChannel(node, { funded: true });
		const unfunded = injectChannel(node, { funded: false });

		const fundedInfo = node.getChannel(funded.channelId)!;
		expect(fundedInfo.fundingTxid).to.be.a('string');
		expect(fundedInfo.fundingOutputIndex).to.equal(1);

		// The state field defaults to 0 before any funding exists; the info
		// must not report that fake outpoint.
		const unfundedInfo = node.getChannel(unfunded.channelId)!;
		expect(unfundedInfo.fundingTxid).to.equal(undefined);
		expect(unfundedInfo.fundingOutputIndex).to.equal(undefined);
		node.destroy();
	});
});
