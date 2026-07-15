/**
 * Regression: simple-taproot channels must have their funding output watched
 * under the real P2TR (MuSig2 key-spend) scriptPubKey, NOT the witness-v0
 * 2-of-2 P2WSH script.
 *
 * The funding spend is detected by subscribing an Electrum backend to the
 * SHA256 script hash of the funding scriptPubKey. A taproot channel funds a
 * P2TR output, so watching the P2WSH script hash never matches: the funding
 * spend (breach or force-close) goes forever undetected and no justice / sweep
 * is ever built. This drives the real `watch:funding` handler on ChainWatcher
 * and asserts it subscribes to the P2TR script hash.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

/** Chain backend that records every script hash it is asked to subscribe to. */
class RecordingBackend implements IChainBackend {
	subscribedScriptHashes: string[] = [];

	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(
		scriptHash: string,
		_onChange: () => void
	): Promise<void> {
		this.subscribedScriptHashes.push(scriptHash);
	}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		return Buffer.alloc(0);
	}
	async broadcastTransaction(): Promise<string> {
		return '';
	}
}

function taprootChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

describe('FS-2: taproot funding output watch', () => {
	let backend: RecordingBackend;
	let channelManager: ChannelManager;
	let watcher: ChainWatcher;

	beforeEach(async () => {
		const seed = crypto.randomBytes(32);
		backend = new RecordingBackend();
		channelManager = new ChannelManager({
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		channelManager.on('error', () => {});
		watcher = new ChainWatcher({ backend, channelManager });
		await watcher.start();
	});

	afterEach(() => {
		watcher.stop();
	});

	function registerTaprootChannel(): {
		fundingTxid: Buffer;
		p2trScriptHash: string;
		p2wshScriptHash: string;
	} {
		const localBasepoints = makeBasepoints(crypto.randomBytes(32));
		const remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints,
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.fundingTxid = crypto.randomBytes(32);
		state.fundingOutputIndex = 0;
		state.remoteBasepoints = remoteBasepoints;
		state.channelType = taprootChannelType();
		const channel = new Channel(state);
		channelManager.restoreChannel(channel, 'ab'.repeat(33));

		const p2trScriptHash = computeScriptHash(
			createTaprootFundingScript(
				localBasepoints.fundingPubkey,
				remoteBasepoints.fundingPubkey
			).p2trOutput
		);
		const p2wshScriptHash = computeScriptHash(
			createFundingScript(
				localBasepoints.fundingPubkey,
				remoteBasepoints.fundingPubkey
			).p2wshOutput
		);
		return { fundingTxid: state.fundingTxid, p2trScriptHash, p2wshScriptHash };
	}

	it('subscribes to the P2TR script hash, not the P2WSH one', async () => {
		const { fundingTxid, p2trScriptHash, p2wshScriptHash } =
			registerTaprootChannel();
		// Sanity: the two encodings differ, so watching the wrong one never matches.
		expect(p2trScriptHash).to.not.equal(p2wshScriptHash);

		channelManager.emit('watch:funding', fundingTxid, 0, 3);
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(
			backend.subscribedScriptHashes,
			'watched the real P2TR funding output'
		).to.include(p2trScriptHash);
		expect(
			backend.subscribedScriptHashes,
			'did NOT watch the wrong P2WSH script hash'
		).to.not.include(p2wshScriptHash);
	});
});
