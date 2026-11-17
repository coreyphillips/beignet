/**
 * The daemon keeps an asset channel out of a rebalance, and says on a
 * payment proof when asset HTLCs carried the payment (issue #2093).
 *
 * A rebalance is refused before its fee cap is charged, with the parameter
 * named. A proof of an asset payment carries `auxiliary: true` and what the
 * payment was worth, since its amount and fee are the bitcoin that carried
 * it; a proof of any other payment is the object it was.
 *
 * The node is faked here, at the one place the daemon reads it.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import type { IPaymentInfo } from '../../src/lightning/node/payment-types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/payment-types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

const ASSET = Buffer.alloc(32, 7);
const ORDINARY = Buffer.alloc(32, 8);

describe('The daemon and an asset channel: rebalance and payment proof (#2093)', () => {
	it('refuses a rebalance that names an asset channel, from or to, before anything is charged or sent', async () => {
		const seen = { charged: 0, sent: 0 };
		const daemon = {
			isGraphRestoring: (): boolean => false,
			assetChannelMark: methods.assetChannelMark,
			_checkDraining: (): void => undefined,
			_checkSpendLimit: (): void => undefined,
			_recordSpend: (): void => {
				seen.charged++;
			},
			node: {
				getAuxiliaryChannelInfo: (channelId: Buffer): unknown =>
					channelId.equals(ASSET) ? { localAssetBalance: 1n } : undefined,
				rebalanceChannel: (): never => {
					seen.sent++;
					throw new Error('the engine was asked');
				}
			}
		};
		for (const [from, to, name] of [
			[ASSET, ORDINARY, 'fromChannelId'],
			[ORDINARY, ASSET, 'toChannelId']
		] as const) {
			const refusal = await (
				methods.rebalanceChannel.call(
					daemon,
					from.toString('hex'),
					to.toString('hex'),
					1000,
					10
				) as Promise<unknown>
			).then(
				() => undefined,
				(err: unknown) => err
			);
			expect(refusal, name).to.be.instanceOf(BeignetError);
			expect((refusal as BeignetError).code, name).to.equal('INVALID_PARAMS');
			expect((refusal as BeignetError).message, name).to.equal(
				`${name} is an asset channel, and an asset channel is not rebalanced`
			);
		}
		expect(seen).to.deep.equal({ charged: 0, sent: 0 });
	});

	it('marks the proof of an asset payment and says what it was worth, and answers any other proof as it did', () => {
		const record = (extra: Partial<IPaymentInfo>): IPaymentInfo => ({
			paymentHash: Buffer.alloc(32, 1),
			preimage: Buffer.alloc(32, 2),
			amountMsat: 354_000n,
			sentMsat: 355_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: 1_700_000_000_000,
			completedAt: 1_700_000_001_000,
			...extra
		});
		const proofOf = (payment: IPaymentInfo): Record<string, unknown> =>
			methods.getPaymentProof.call(
				{
					node: {
						getPaymentProof: (): unknown => ({
							paymentHash: payment.paymentHash,
							preimage: payment.preimage,
							completedAt: payment.completedAt
						}),
						getPayment: (): IPaymentInfo => payment
					}
				},
				'01'.repeat(32)
			) as Record<string, unknown>;

		const ordinary = proofOf(record({}));
		expect(ordinary).to.deep.equal({
			paymentHash: '01'.repeat(32),
			preimage: '02'.repeat(32),
			amountSats: 355,
			completedAt: 1_700_000_001_000,
			invoice: undefined,
			hopCount: undefined,
			feeSats: 1
		});
		expect(ordinary).to.not.have.property('auxiliary');
		expect(ordinary).to.not.have.property('auxiliaryValueSats');

		const asset = proofOf(
			record({ auxiliary: true, auxiliaryValueMsat: 25_000_000n })
		);
		expect(asset).to.deep.equal({
			...ordinary,
			auxiliary: true,
			auxiliaryValueSats: 25_000
		});
		// A value without the mark is not an asset payment's.
		expect(proofOf(record({ auxiliaryValueMsat: 25_000_000n }))).to.deep.equal(
			ordinary
		);
	});
});
