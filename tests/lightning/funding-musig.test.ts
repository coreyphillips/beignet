import {
	encodeSpliceMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	decodeSpliceAckMessage
} from '../../src/lightning/message/splice';
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import {
	createTaprootFundingScript,
	taprootKeySpendSighash
} from '../../src/lightning/script/funding-taproot';
import {
	fundingNonceDomain,
	deriveFundingNonce,
	bindFundingPeerNonces,
	signFundingSharedInput,
	verifyFundingSharedInput,
	finalizeFundingSharedInput,
	ITaprootFundingRound
} from '../../src/lightning/channel/funding-musig';
import {
	encodeTxCompleteMessage,
	decodeTxCompleteMessage,
	encodeTxSignaturesMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
bitcoin.initEccLib(ecc);
const secret = (n: number): Buffer => {
	const b = Buffer.alloc(32);
	b[31] = n;
	return b;
};
const pub = (n: number): Buffer =>
	Buffer.from(ecc.pointFromScalar(secret(n), true)!);
function setup() {
	const root = Buffer.alloc(32, 17),
		funding = createTaprootFundingScript(pub(1), pub(2), undefined, root);
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.alloc(32, 9), 3, 0xfffffffd);
	tx.addInput(Buffer.alloc(32, 7), 0);
	tx.addOutput(funding.p2trOutput, 110000);
	const domain = fundingNonceDomain(tx);
	const rounds = [1, 2].map(
		(n) =>
			({
				domain,
				localVerificationNonce: Buffer.from(
					deriveFundingNonce(secret(n + 10), pub(n), domain, 'commitment', 7n)
				),
				localSharedNonce: Buffer.from(
					deriveFundingNonce(secret(n + 10), pub(n), domain, 'shared')
				)
			}) as ITaprootFundingRound
	);
	bindFundingPeerNonces(
		rounds[0],
		rounds[1].localVerificationNonce,
		rounds[1].localSharedNonce
	);
	bindFundingPeerNonces(
		rounds[1],
		rounds[0].localVerificationNonce,
		rounds[0].localSharedNonce
	);
	const input = {
		transaction: tx,
		inputIndex: 0,
		prevoutScripts: [
			funding.p2trOutput,
			Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, 3)])
		],
		prevoutValues: [100000, 20000],
		localFundingPubkey: pub(1),
		remoteFundingPubkey: pub(2),
		fundingMerkleRoot: root
	};
	return { tx, rounds, input, funding };
}
describe('native Taproot interactive funding transcript', () => {
	it('co-signs the exact shared funding input and restores public evidence without signing again', () => {
		const { tx, rounds, input, funding } = setup();
		const left = signFundingSharedInput(
			rounds[0],
			input,
			secret(11),
			new ChannelSigner(secret(1))
		);
		const right = signFundingSharedInput(
			rounds[1],
			{ ...input, localFundingPubkey: pub(2), remoteFundingPubkey: pub(1) },
			secret(12),
			new ChannelSigner(secret(2))
		);
		expect(verifyFundingSharedInput(rounds[0], input, right)).to.equal(true);
		const signature = finalizeFundingSharedInput(rounds[0], input, right);
		expect(
			ecc.verifySchnorr(
				taprootKeySpendSighash(
					tx,
					0,
					input.prevoutScripts,
					input.prevoutValues
				),
				funding.outputKey,
				signature
			)
		).to.equal(true);
		const restored = Object.fromEntries(
			Object.entries(rounds[0]).map(([name, value]) => [
				name,
				Buffer.from(value)
			])
		) as unknown as ITaprootFundingRound;
		const signer = new ChannelSigner(secret(1));
		signer.signCommitmentPartial = () => {
			throw new Error('must retransmit');
		};
		expect(
			signFundingSharedInput(restored, input, secret(11), signer)
		).to.deep.equal(left);
		expect(() =>
			bindFundingPeerNonces(
				restored,
				rounds[1].localVerificationNonce,
				Buffer.alloc(66, 1)
			)
		).to.throw('changed a committed nonce');
		const altered = tx.clone();
		altered.outs[0].value--;
		expect(() =>
			signFundingSharedInput(
				restored,
				{ ...input, transaction: altered },
				secret(11),
				signer
			)
		).to.throw('transcript');
		expect(() =>
			signFundingSharedInput(
				restored,
				{ ...input, prevoutValues: [100001, 20000] },
				secret(11),
				signer
			)
		).to.throw('transcript changed');
	});
	it('separates funding attempts, commitment heights and shared-input nonce roles', () => {
		const { tx, input } = setup(),
			domain = fundingNonceDomain(tx);
		const base = Buffer.from(
			deriveFundingNonce(secret(11), pub(1), domain, 'commitment', 0n)
		);
		tx.locktime++;
		expect(
			Buffer.from(
				deriveFundingNonce(
					secret(11),
					pub(1),
					fundingNonceDomain(tx),
					'commitment',
					0n
				)
			)
		).not.to.deep.equal(base);
		expect(
			Buffer.from(
				deriveFundingNonce(secret(11), pub(1), domain, 'commitment', 1n)
			)
		).not.to.deep.equal(base);
		expect(
			Buffer.from(
				deriveFundingNonce(
					secret(11),
					input.localFundingPubkey,
					domain,
					'shared',
					0n
				)
			)
		).not.to.deep.equal(base);
	});
	it('round trips native nonce and partial records and rejects ambiguous signatures', () => {
		const { rounds, input } = setup(),
			record = rounds[0];
		const msg = {
			channelId: Buffer.alloc(32, 6),
			taprootFunding: {
				domain: record.domain,
				verificationNonce: record.localVerificationNonce,
				sharedNonce: record.localSharedNonce,
				nextVerificationNonce: record.localVerificationNonce
			}
		};
		expect(decodeTxCompleteMessage(encodeTxCompleteMessage(msg))).to.deep.equal(
			msg
		);
		const shared = signFundingSharedInput(
			record,
			input,
			secret(11),
			new ChannelSigner(secret(1))
		);
		const signatures = {
			channelId: msg.channelId,
			txid: input.transaction.getHash(),
			witnesses: [],
			sharedInputPartialSignatureWithNonce: shared
		};
		expect(
			decodeTxSignaturesMessage(encodeTxSignaturesMessage(signatures))
		).to.deep.equal(signatures);
		expect(() =>
			encodeTxSignaturesMessage({
				...signatures,
				sharedInputSignature: Buffer.alloc(64)
			})
		).to.throw('Invalid shared funding partial');
	});
	it('retains the bound asset session in both splice negotiation messages', () => {
		const common = {
			channelId: Buffer.alloc(32, 1),
			fundingPubkey: pub(1),
			relativeSatoshis: 1000n,
			interactiveFundingSessionId: Buffer.alloc(32, 3),
			lockDepth: 3
		};
		const init = { ...common, locktime: 0, fundingFeeratePerkw: 253 };
		expect(
			decodeSpliceMessage(encodeSpliceMessage(init)).interactiveFundingSessionId
		).deep.equal(common.interactiveFundingSessionId);
		expect(
			decodeSpliceAckMessage(encodeSpliceAckMessage(common))
				.interactiveFundingSessionId
		).deep.equal(common.interactiveFundingSessionId);
		expect(() =>
			encodeSpliceMessage({
				...init,
				interactiveFundingSessionId: Buffer.alloc(31)
			})
		).to.throw('session ID');
	});
});
