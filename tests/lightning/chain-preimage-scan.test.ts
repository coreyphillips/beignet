import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChainActionType, OutputType } from '../../src/lightning/chain/types';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';

bitcoin.initEccLib(ecc);
const network = bitcoin.networks.regtest;

function priv(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}
function bps(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(priv(seed, 0)),
		revocationBasepoint: getPublicKey(priv(seed, 1)),
		paymentBasepoint: getPublicKey(priv(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(priv(seed, 3)),
		htlcBasepoint: getPublicKey(priv(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}
function point(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

describe('ChainMonitor preimage scanning (defense-in-depth)', function () {
	it('learns every preimage a single counterparty tx reveals, across multiple HTLCs', function () {
		const openerSeed = crypto.createHash('sha256').update('o').digest();
		const acceptorSeed = crypto.createHash('sha256').update('a').digest();
		const commitSeed = crypto.createHash('sha256').update('c').digest();
		const ob = bps(openerSeed),
			ab = bps(acceptorSeed);
		ob.firstPerCommitmentPoint = point(commitSeed, 0n);

		const fundingTxid = crypto.createHash('sha256').update('f').digest();
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: ob,
			localPerCommitmentSeed: commitSeed
		});
		state.remoteBasepoints = ab;
		state.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
		state.fundingTxid = fundingTxid;
		state.fundingOutputIndex = 0;
		state.channelId = deriveChannelId(fundingTxid, 0);
		state.remoteCurrentPerCommitmentPoint = ab.firstPerCommitmentPoint;
		state.localBalanceMsat = 800_000_000n;
		state.remoteBalanceMsat = 200_000_000n;

		// Two outbound (offered) HTLCs — we do NOT yet know their preimages.
		const pre1 = crypto.randomBytes(32),
			pre2 = crypto.randomBytes(32);
		const h1 = crypto.createHash('sha256').update(pre1).digest();
		const h2 = crypto.createHash('sha256').update(pre2).digest();
		state.htlcs.set('a', {
			id: 0n,
			amountMsat: 60_000_000n,
			paymentHash: h1,
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		});
		state.htlcs.set('b', {
			id: 1n,
			amountMsat: 70_000_000n,
			paymentHash: h2,
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		});

		const destScript = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			Buffer.alloc(20)
		]);
		const monitor = new ChainMonitor(
			state,
			destScript,
			10,
			priv(openerSeed, 1),
			priv(openerSeed, 2),
			network,
			priv(openerSeed, 3),
			priv(openerSeed, 4)
		);

		// Force-close on our own commitment.
		const built = buildLocalCommitment(state, point(commitSeed, 0n));
		monitor.handleFundingSpent(built.result.tx, 100);

		const htlcOutputs = monitor
			.getTrackedOutputs()
			.filter((o) => o.outputType === OutputType.OFFERED_HTLC);
		expect(htlcOutputs.length, 'two offered HTLC outputs tracked').to.equal(2);

		// The counterparty sweeps BOTH HTLC outputs with their preimages in one tx.
		const spendTx = new bitcoin.Transaction();
		spendTx.version = 2;
		const cTxid = Buffer.from(built.result.tx.getId(), 'hex').reverse();
		spendTx.addInput(cTxid, htlcOutputs[0].outputIndex, 0xffffffff);
		spendTx.addInput(cTxid, htlcOutputs[1].outputIndex, 0xffffffff);
		spendTx.addOutput(destScript, 1000);
		// HTLC-success witness on offered HTLC reveals the preimage (last-but-one element).
		spendTx.setWitness(0, [
			Buffer.alloc(64),
			Buffer.alloc(33),
			pre1,
			Buffer.alloc(40)
		]);
		spendTx.setWitness(1, [
			Buffer.alloc(64),
			Buffer.alloc(33),
			pre2,
			Buffer.alloc(40)
		]);

		const actions = monitor.handleOutputSpent(
			htlcOutputs[0].txid,
			htlcOutputs[0].outputIndex,
			spendTx,
			101
		);

		const learned = actions
			.filter((a) => a.type === ChainActionType.PREIMAGE_LEARNED)
			.map((a: any) => a.paymentHash.toString('hex'))
			.sort();
		expect(learned).to.deep.equal(
			[h1.toString('hex'), h2.toString('hex')].sort()
		);
	});
});
