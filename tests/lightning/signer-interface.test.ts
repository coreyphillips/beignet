/**
 * M6: remote/external signer interface (ISigner).
 *
 * Two guarantees, gated here:
 *  1. Byte-identity: the refactored ChannelSigner (now implementing ISigner)
 *     reproduces the EXACT signatures the pre-refactor ChannelSigner produced.
 *     Every hex vector below was pinned by running the pre-refactor code with
 *     these fixed keys/transactions — any drift is a fund-critical regression.
 *  2. Injection: a custom ISigner supplied via config (signerFactory) is the
 *     signer the channel actually uses, end to end through a real
 *     open_channel -> funding_signed -> channel_ready loopback flow.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelSigner,
	ISigner,
	verifyCommitmentSignature
} from '../../src/lightning/keys/signer';
import { SessionKey, generateNonce } from '../../src/lightning/crypto/musig';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelBasepoints,
	derivePrivateKey
} from '../../src/lightning/keys/derivation';
import { createFundingScript } from '../../src/lightning/script/funding';
import { startCommitmentSigningSession } from '../../src/lightning/channel/commitment-musig';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';

// ─── Fixed key material (vectors pinned against these exact values) ─────────

function b(hex: string): Buffer {
	return Buffer.from(hex, 'hex');
}

const FUNDING_PRIV = b('01'.repeat(32));
const HTLC_SECRET = b('02'.repeat(32));
const REMOTE_PRIV = b('03'.repeat(32));

/** Deterministic tx signed by the commitment/closing/HTLC vectors. */
function makeFixedTx(): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(b('11'.repeat(32)), 0, 0xfffffffd);
	tx.addOutput(b('0014' + '22'.repeat(20)), 99000);
	tx.locktime = 543210000;
	return tx;
}

// ─── Byte-identity vectors (pinned from the pre-refactor ChannelSigner) ─────

describe('ISigner refactor - byte identity with pre-refactor ChannelSigner', function () {
	const signer = new ChannelSigner(FUNDING_PRIV, HTLC_SECRET);
	const remotePub = getPublicKey(REMOTE_PRIV);
	const funding = createFundingScript(signer.fundingPubkey, remotePub);
	const perCommitmentPoint = getPublicKey(b('04'.repeat(32)));
	const htlcBasepoint = getPublicKey(HTLC_SECRET);
	const htlcScript = b('0020' + '33'.repeat(32));

	it('fundingPubkey is unchanged', function () {
		expect(signer.fundingPubkey.toString('hex')).to.equal(
			'031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'
		);
	});

	it('signFundingDigest reproduces the pinned signature', function () {
		expect(
			signer.signFundingDigest(b('aa'.repeat(32))).toString('hex')
		).to.equal(
			'2b3bc1430342aac2bcce687aaf5db4b8e0440421616fa3af77c3cba12832f4ea' +
				'7f3d773f75cfc3733877a842ff0781696f477629c58817b9c61af96876473383'
		);
	});

	it('signCommitmentTx and signClosingTx reproduce the pinned signature', function () {
		const expected =
			'f46374e8b01319cb79f7294d57b5da76fd1aa03333b9db1da8e4c6a79ee1a273' +
			'61066580e592a60fa3392517a03afdd2237b0f98dc54f84531e6cd78a7e665e1';
		expect(
			signer
				.signCommitmentTx(makeFixedTx(), funding.witnessScript, 100000)
				.toString('hex')
		).to.equal(expected);
		expect(
			signer
				.signClosingTx(makeFixedTx(), funding.witnessScript, 100000)
				.toString('hex')
		).to.equal(expected);
	});

	it('signHtlcTx (raw-key path) reproduces the pinned signatures', function () {
		const htlcPriv = derivePrivateKey(
			HTLC_SECRET,
			perCommitmentPoint,
			htlcBasepoint
		);
		expect(htlcPriv.toString('hex')).to.equal(
			'c598b203d5db3fbc32a324fa4f28a3e7a081da832586439ef7fe5f98c96b16af'
		);
		expect(
			signer
				.signHtlcTx(makeFixedTx(), htlcScript, 50000, htlcPriv)
				.toString('hex')
		).to.equal(
			'98db861b4e1e2704dca05564fa9f03437c0f676edba116d396ad00020ad72609' +
				'6c62a1cf17644b5497cc24d9e0c07ea9ae6cd7d084b87cf6543a352b49359f0e'
		);
		expect(
			signer
				.signHtlcTx(makeFixedTx(), htlcScript, 50000, htlcPriv, true)
				.toString('hex')
		).to.equal(
			'71c387784cc0d2e0fbca2add09fbe37c60746c6aff244b035358b9feeda779b5' +
				'0bac8d23dc8cfd57af5babae7ebccb36c87f4587527b8fca2170da6fc9e76212'
		);
	});

	it('signHtlcTxForCommitment matches the old derive-then-sign path exactly', function () {
		// Same pinned vector as the raw-key path above: the new interface
		// method derives the per-commitment HTLC key internally and must
		// produce the identical bytes.
		expect(
			signer
				.signHtlcTxForCommitment(
					makeFixedTx(),
					htlcScript,
					50000,
					perCommitmentPoint,
					htlcBasepoint
				)
				.toString('hex')
		).to.equal(
			'98db861b4e1e2704dca05564fa9f03437c0f676edba116d396ad00020ad72609' +
				'6c62a1cf17644b5497cc24d9e0c07ea9ae6cd7d084b87cf6543a352b49359f0e'
		);
		expect(
			signer
				.signHtlcTxForCommitment(
					makeFixedTx(),
					htlcScript,
					50000,
					perCommitmentPoint,
					htlcBasepoint,
					true
				)
				.toString('hex')
		).to.equal(
			'71c387784cc0d2e0fbca2add09fbe37c60746c6aff244b035358b9feeda779b5' +
				'0bac8d23dc8cfd57af5babae7ebccb36c87f4587527b8fca2170da6fc9e76212'
		);
	});

	it('signHtlcTxForCommitment derives with the PASSED basepoint (wire parity)', function () {
		// A basepoint that does not match the secret: commitment-builder always
		// passed state.localBasepoints.htlcBasepoint into the derivation, so the
		// signer must honor the passed basepoint rather than recompute it from
		// the secret. Pinned from the pre-refactor derive-then-sign path.
		const otherBasepoint = getPublicKey(b('05'.repeat(32)));
		expect(
			signer
				.signHtlcTxForCommitment(
					makeFixedTx(),
					htlcScript,
					50000,
					perCommitmentPoint,
					otherBasepoint
				)
				.toString('hex')
		).to.equal(
			'a67bae5cf392b21c401035b67578577f456fdd97a3390215dc039d416ead0825' +
				'15844ad1b9a1f48c7c9c9a2a984b2c5ca550def88f139546abb9db6280a28872'
		);
	});

	it('signTaprootHtlcForCommitment reproduces the pinned Schnorr signature', function () {
		expect(
			signer
				.signTaprootHtlcForCommitment(
					b('bb'.repeat(32)),
					perCommitmentPoint,
					htlcBasepoint
				)
				.toString('hex')
		).to.equal(
			'c6b20f4e6a013262dbaa381074c006e3050290885af667e929328313d03ef466' +
				'cc5dd94d13b8a4c53f8869f8bd1d6e1731432d152b672617e5fce4c1c594051f'
		);
	});

	it('signCommitmentPartial reproduces the pinned MuSig2 partial', function () {
		const ourNonce = generateNonce({
			publicKey: signer.fundingPubkey,
			sessionId: b('06'.repeat(32))
		});
		const theirNonce = Buffer.from(
			generateNonce({ publicKey: remotePub, sessionId: b('07'.repeat(32)) })
		);
		const session = startCommitmentSigningSession(
			b('cc'.repeat(32)),
			signer.fundingPubkey,
			remotePub,
			ourNonce,
			theirNonce
		);
		expect(
			signer.signCommitmentPartial(session, ourNonce).toString('hex')
		).to.equal(
			'29b9196774e23d0b3152e7b74fcc1c0a5d07e726e74bfb75666c066f768c10fb'
		);
	});

	it('buildFundingWitness reproduces the pinned witness stack', function () {
		const sigA = Buffer.concat([b('20'.repeat(32)), b('30'.repeat(32))]);
		const sigB = Buffer.concat([b('40'.repeat(32)), b('50'.repeat(32))]);
		const witness = ChannelSigner.buildFundingWitness(
			sigA,
			sigB,
			signer.fundingPubkey,
			remotePub,
			funding.witnessScript
		);
		expect(witness.map((w) => w.toString('hex'))).to.deep.equal([
			'',
			'304402204040404040404040404040404040404040404040404040404040404040404040' +
				'0220505050505050505050505050505050505050505050505050505050505050505001',
			'304402202020202020202020202020202020202020202020202020202020202020202020' +
				'0220303030303030303030303030303030303030303030303030303030303030303001',
			'522102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337' +
				'21031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f52ae'
		]);
	});

	it('verifyCommitmentSig accepts its own signature and rejects a tampered one', function () {
		const tx = makeFixedTx();
		const sig = signer.signCommitmentTx(tx, funding.witnessScript, 100000);
		expect(
			signer.verifyCommitmentSig(
				tx,
				sig,
				signer.fundingPubkey,
				funding.witnessScript,
				100000
			)
		).to.equal(true);
		// Standalone helper (for custom ISigner implementations) agrees.
		expect(
			verifyCommitmentSignature(
				tx,
				sig,
				signer.fundingPubkey,
				funding.witnessScript,
				100000
			)
		).to.equal(true);
		const bad = Buffer.from(sig);
		bad[10] ^= 0x01;
		expect(
			signer.verifyCommitmentSig(
				tx,
				bad,
				signer.fundingPubkey,
				funding.witnessScript,
				100000
			)
		).to.equal(false);
	});

	it('hasHtlcKeys reflects HTLC key material; ForCommitment methods throw without it', function () {
		expect(signer.hasHtlcKeys).to.equal(true);
		const bare = new ChannelSigner(FUNDING_PRIV);
		expect(bare.hasHtlcKeys).to.equal(false);
		expect(() =>
			bare.signHtlcTxForCommitment(
				makeFixedTx(),
				htlcScript,
				50000,
				perCommitmentPoint,
				htlcBasepoint
			)
		).to.throw('HTLC basepoint secret');
		expect(() =>
			bare.signTaprootHtlcForCommitment(
				b('bb'.repeat(32)),
				perCommitmentPoint,
				htlcBasepoint
			)
		).to.throw('HTLC basepoint secret');
	});
});

// ─── Custom ISigner injection ────────────────────────────────────────────────

/**
 * Counting wrapper: a custom ISigner that delegates to an in-process
 * ChannelSigner (so signatures stay byte-identical) while recording every
 * call — the pattern a remote-signer proxy would follow.
 */
class CountingSigner implements ISigner {
	readonly calls: Record<string, number> = {};
	private readonly inner: ChannelSigner;

	constructor(fundingPrivkey: Buffer, htlcBasepointSecret?: Buffer) {
		this.inner = new ChannelSigner(fundingPrivkey, htlcBasepointSecret);
	}

	private count(method: string): void {
		this.calls[method] = (this.calls[method] ?? 0) + 1;
	}

	get fundingPubkey(): Buffer {
		return this.inner.fundingPubkey;
	}

	get hasHtlcKeys(): boolean {
		return this.inner.hasHtlcKeys;
	}

	signFundingDigest(digest: Buffer): Buffer {
		this.count('signFundingDigest');
		return this.inner.signFundingDigest(digest);
	}

	signCommitmentTx(
		tx: bitcoin.Transaction,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): Buffer {
		this.count('signCommitmentTx');
		return this.inner.signCommitmentTx(tx, fundingWitnessScript, fundingAmount);
	}

	signClosingTx(
		tx: bitcoin.Transaction,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): Buffer {
		this.count('signClosingTx');
		return this.inner.signClosingTx(tx, fundingWitnessScript, fundingAmount);
	}

	signCommitmentPartial(
		session: SessionKey,
		ourPublicNonce: Uint8Array
	): Buffer {
		this.count('signCommitmentPartial');
		return this.inner.signCommitmentPartial(session, ourPublicNonce);
	}

	signHtlcTxForCommitment(
		tx: bitcoin.Transaction,
		htlcWitnessScript: Buffer,
		htlcAmount: number,
		perCommitmentPoint: Buffer,
		htlcBasepoint: Buffer,
		useAnchorSighash?: boolean
	): Buffer {
		this.count('signHtlcTxForCommitment');
		return this.inner.signHtlcTxForCommitment(
			tx,
			htlcWitnessScript,
			htlcAmount,
			perCommitmentPoint,
			htlcBasepoint,
			useAnchorSighash
		);
	}

	signTaprootHtlcForCommitment(
		sighash: Buffer,
		perCommitmentPoint: Buffer,
		htlcBasepoint: Buffer
	): Buffer {
		this.count('signTaprootHtlcForCommitment');
		return this.inner.signTaprootHtlcForCommitment(
			sighash,
			perCommitmentPoint,
			htlcBasepoint
		);
	}

	verifyCommitmentSig(
		tx: bitcoin.Transaction,
		signature: Buffer,
		remoteFundingPubkey: Buffer,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): boolean {
		this.count('verifyCommitmentSig');
		return verifyCommitmentSignature(
			tx,
			signature,
			remoteFundingPubkey,
			fundingWitnessScript,
			fundingAmount
		);
	}
}

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`isigner-seed-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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

function makeManagerConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4)
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);
	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

describe('ISigner injection via signerFactory', function () {
	it('ChannelManager.openChannel uses the injected signer', function () {
		const cfg = makeManagerConfig(1);
		const injected: CountingSigner[] = [];
		const indices: number[] = [];
		const mgr = new ChannelManager({
			...cfg,
			signerFactory: (channelKeyIndex: number): ISigner => {
				indices.push(channelKeyIndex);
				const s = new CountingSigner(
					cfg.localFundingPrivkey,
					cfg.htlcBasepointSecret
				);
				injected.push(s);
				return s;
			}
		});
		mgr.on('error', () => {});

		const channel = mgr.openChannel('02' + '11'.repeat(32), 100_000n);
		expect(injected).to.have.length(1);
		expect(indices).to.deep.equal([0]);
		expect(channel.getSigner()).to.equal(injected[0]);
	});

	it('full open flow signs through the injected signer with identical results', function () {
		const aliceCfg = makeManagerConfig(2);
		const bobCfg = makeManagerConfig(3);
		const alicePub = aliceCfg.localBasepoints.fundingPubkey.toString('hex');
		const bobPub = bobCfg.localBasepoints.fundingPubkey.toString('hex');

		const injected: CountingSigner[] = [];
		const alice = new ChannelManager({
			...aliceCfg,
			signerFactory: (): ISigner => {
				const s = new CountingSigner(
					aliceCfg.localFundingPrivkey,
					aliceCfg.htlcBasepointSecret
				);
				injected.push(s);
				return s;
			}
		});
		const bob = new ChannelManager(bobCfg);
		alice.on('error', () => {});
		bob.on('error', () => {});
		connectManagers(alice, alicePub, bob, bobPub);

		const channel = alice.openChannel(bobPub, 1_000_000n);
		expect(injected).to.have.length(1);
		expect(channel.getSigner()).to.equal(injected[0]);

		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			channel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		)!;
		expect(channelId).to.exist;

		// funding_created -> funding_signed round trip succeeded: bob VERIFIED
		// the initial commitment signature the injected signer produced, and
		// alice verified bob's — the custom signer output is byte-identical to
		// a plain ChannelSigner or this handshake would have failed.
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(injected[0].calls.signCommitmentTx ?? 0).to.be.greaterThan(0);

		// Channel becomes fully operational with the injected signer.
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		expect(alice.getChannel(channelId)!.getState()).to.equal(
			ChannelState.NORMAL
		);
	});

	it('restoreChannel builds the signer via the factory (with key index)', function () {
		const cfg = makeManagerConfig(4);
		const indices: number[] = [];
		const injected: CountingSigner[] = [];
		const mgr = new ChannelManager({
			...cfg,
			channelKeyDeriver: (channelIndex: number) => {
				const seed = makeSeed(400 + channelIndex);
				const fundingPrivkey = derivePrivkey(seed, 0);
				return {
					fundingPrivkey,
					basepoints: {
						...makeBasepoints(seed),
						fundingPubkey: getPublicKey(fundingPrivkey)
					},
					perCommitmentSeed: makeSeed(500 + channelIndex),
					htlcBasepointSecret: derivePrivkey(seed, 4)
				};
			},
			signerFactory: (channelKeyIndex: number): ISigner => {
				indices.push(channelKeyIndex);
				const s = new CountingSigner(cfg.localFundingPrivkey);
				injected.push(s);
				return s;
			}
		});
		mgr.on('error', () => {});

		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 100_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(405)),
			localPerCommitmentSeed: makeSeed(505)
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		const channel = new Channel(state);

		mgr.restoreChannel(channel, '02' + 'ff'.repeat(32), 5);
		expect(indices).to.deep.equal([5]);
		expect(channel.getSigner()).to.equal(injected[0]);
	});

	it('LightningNode passes signerFactory through to its channels', function () {
		const seed = makeSeed(6);
		const injected: CountingSigner[] = [];
		const config: INodeConfig = {
			nodePrivateKey: derivePrivkey(seed, 9),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: makeBasepoints(seed),
			perCommitmentSeed: makeSeed(106),
			fundingPrivkey: derivePrivkey(seed, 0),
			htlcBasepointSecret: derivePrivkey(seed, 4),
			signerFactory: (): ISigner => {
				const s = new CountingSigner(
					derivePrivkey(seed, 0),
					derivePrivkey(seed, 4)
				);
				injected.push(s);
				return s;
			}
		};
		const node = new LightningNode(config);
		node.on('error', () => {});

		const channel = node.openChannel('02' + '66'.repeat(32), 100_000n);
		expect(injected).to.have.length(1);
		expect(channel.getSigner()).to.equal(injected[0]);
	});

	it('without a signerFactory the default ChannelSigner path is unchanged', function () {
		const mgr = new ChannelManager(makeManagerConfig(7));
		mgr.on('error', () => {});
		const channel = mgr.openChannel('02' + '77'.repeat(32), 100_000n);
		expect(channel.getSigner()).to.be.an.instanceOf(ChannelSigner);
	});
});
