import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { randomBytes } from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateNonce } from '../../src/lightning/crypto/musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import {
	decodeClosingCompleteMessage,
	encodeClosingCompleteMessage,
	decodeClosingSigMessage,
	encodeClosingSigMessage
} from '../../src/lightning/message/channel-close';
import {
	type IFinalSimpleCloseParams,
	finalSimpleCloseProposalTxids,
	acceptFinalSimpleClose,
	completeFinalSimpleClose,
	proposeFinalSimpleClose
} from '../../src/lightning/channel/final-simple-close';

const a = Buffer.alloc(32, 1);
const b = Buffer.alloc(32, 2);
const aPub = getPublicKey(a);
const bPub = getPublicKey(b);
const fund = createTaprootFundingScript(aPub, bPub);
const funding = new Transaction();
funding.addInput(Buffer.alloc(32, 3), 3);
funding.addOutput(fund.p2trOutput, 100_000);
const opt = { finalTaproot: true };
function nonce(key: Buffer): Uint8Array {
	return generateNonce({
		publicKey: getPublicKey(key),
		secretKey: key,
		sessionId: randomBytes(32)
	});
}
function pair(
	closerSats: number,
	fee = 500n
): {
	closer: IFinalSimpleCloseParams;
	closee: IFinalSimpleCloseParams;
	current: Uint8Array;
	next: Buffer;
	proposal: Buffer;
} {
	const closer = {
		channelId: Buffer.alloc(32, 9),
		fundingTx: funding.toBuffer(),
		fundingOutputIndex: 0,
		localFundingPrivkey: a,
		remoteFundingPubkey: bPub,
		localBalanceMsat: BigInt(closerSats) * 1000n,
		remoteBalanceMsat: BigInt(100_000 - closerSats) * 1000n,
		localScriptPubkey: Buffer.from('0014' + '11'.repeat(20), 'hex'),
		remoteScriptPubkey: Buffer.from('0014' + '22'.repeat(20), 'hex'),
		localIsCloser: true,
		blockHeight: 200,
		locktime: 200,
		feeSatoshis: fee
	};
	const closee = {
		...closer,
		localIsCloser: false,
		localFundingPrivkey: b,
		remoteFundingPubkey: aPub,
		localBalanceMsat: closer.remoteBalanceMsat,
		remoteBalanceMsat: closer.localBalanceMsat,
		localScriptPubkey: closer.remoteScriptPubkey,
		remoteScriptPubkey: closer.localScriptPubkey
	};
	const current = nonce(b),
		next = Buffer.from(nonce(b));
	const { proposal } = proposeFinalSimpleClose(
		closer,
		Buffer.from(current),
		() => nonce(a)
	);
	return { closer, closee, current, next, proposal };
}

describe('final Taproot simple close', () => {
	for (const [closerSats, payouts] of [
		[75_000, [25_000, 74_500]],
		[30_000, [29_500, 70_000]],
		[99_900, [99_400]],
		[600, [99_400]]
	] as const) {
		it('settles both copies with closer balance ' + closerSats, () => {
			const { closer, closee, current, next, proposal } = pair(closerSats);
			const { reply, transaction } = acceptFinalSimpleClose(
				closee,
				proposal,
				current,
				next
			);
			const result = completeFinalSimpleClose(
				closer,
				proposal,
				reply,
				Buffer.from(current)
			);
			expect(result.equals(transaction)).to.equal(true);
			const tx = Transaction.fromBuffer(result);
			const ids = finalSimpleCloseProposalTxids(closer, proposal);
			expect(ids).to.include(tx.getId());
			expect(new Set(ids).size).to.equal(closerSats === 75_000 ? 2 : 1);
			expect(tx.ins[0].hash.equals(funding.getHash())).to.equal(true);
			expect(tx.ins[0].sequence).to.equal(0xfffffffd);
			expect(tx.ins[0].witness.map((w) => w.length)).to.deep.equal([64]);
			expect(tx.outs.map((o) => o.value)).to.deep.equal(payouts);
		});
	}
	it('validates the peer before consuming the advertised nonce', () => {
		const { closee, current, next, proposal } = pair(75_000);
		const message = decodeClosingCompleteMessage(proposal, opt);
		message.closerAndCloseePartialSig = Buffer.from(
			message.closerAndCloseePartialSig!
		);
		message.closerAndCloseePartialSig[0] ^= 1;
		expect(() =>
			acceptFinalSimpleClose(
				closee,
				encodeClosingCompleteMessage(message, opt),
				current,
				next
			)
		).to.throw(/signature/i);
		expect(() =>
			acceptFinalSimpleClose(closee, proposal, current, next)
		).not.to.throw();
	});
	it('protects the agreed payout, fee, nonce rotation and replayed reply', () => {
		const { closer, closee, current, next, proposal } = pair(75_000);
		const message = decodeClosingCompleteMessage(proposal, opt);
		delete message.closerAndCloseePartialSig;
		expect(() =>
			acceptFinalSimpleClose(
				closee,
				encodeClosingCompleteMessage(message, opt),
				current,
				next
			)
		).to.throw();
		expect(() =>
			acceptFinalSimpleClose(
				{ ...closee, localScriptPubkey: closer.localScriptPubkey },
				proposal,
				current,
				next
			)
		).to.throw();
		expect(() =>
			acceptFinalSimpleClose(closee, proposal, current, Buffer.from(current))
		).to.throw();
		const { reply } = acceptFinalSimpleClose(closee, proposal, current, next);
		const decoded = decodeClosingSigMessage(reply, opt);
		expect(() =>
			completeFinalSimpleClose(
				closer,
				proposal,
				encodeClosingSigMessage({ ...decoded, feeSatoshis: 1n }, opt),
				Buffer.from(current)
			)
		).to.throw();
		expect(() =>
			completeFinalSimpleClose(
				closer,
				proposal,
				encodeClosingSigMessage(
					{ ...decoded, nextCloseeNonce: Buffer.from(current) },
					opt
				),
				Buffer.from(current)
			)
		).to.throw();
	});
	it('rejects unsigned terms that cannot safely produce a closing transaction', () => {
		const { closer, current } = pair(75_000);
		for (const change of [
			{ localBalanceMsat: 1n },
			{ fundingOutputIndex: 1 },
			{ locktime: 210 },
			{ locktime: 500_000_000 },
			{ feeSatoshis: -1n },
			{ feeSatoshis: 30n },
			{ feeSatoshis: 75_000n },
			{ localIsCloser: false },
			{ remoteFundingPubkey: aPub }
		]) {
			expect(() =>
				proposeFinalSimpleClose(
					{ ...closer, ...change },
					Buffer.from(current),
					() => nonce(a)
				)
			).to.throw();
		}
		const reused = nonce(a);
		expect(() =>
			proposeFinalSimpleClose(closer, Buffer.from(current), () => reused)
		).to.throw(/nonce/i);
	});
});
