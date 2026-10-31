import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { attachFeeInputsToAuxiliarySweepTx } from '../../src/lightning/chain/sweep';
import {
	ChainActionType,
	IAuxiliarySweepFeeAttachment,
	IFeeBumpAndBroadcastChainAction
} from '../../src/lightning/chain/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import type { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import type { IFundingProvider } from '../../src/lightning/node/types';
import { COMMIT_ALL } from './helpers/channel-persistence';

bitcoin.initEccLib(ecc);
const secret = Buffer.alloc(32, 7);
const publicKey = Buffer.from(ecc.pointFromScalar(secret, true)!);
const assetScript = Buffer.concat([
	Buffer.from([0x51, 0x20]),
	publicKey.subarray(1)
]);
const changeScript = bitcoin.payments.p2wpkh({ pubkey: publicKey }).output!;
const destination = Buffer.concat([
	Buffer.from([0x51, 0x20]),
	Buffer.from(ecc.pointFromScalar(Buffer.alloc(32, 8), true)!).subarray(1)
]);
const proofData = Buffer.from('final auxiliary proof payload');

function fixture(inputCount = 1): {
	sweepTx: bitcoin.Transaction;
	walletInput: ISpliceWalletInput;
	attachment: IAuxiliarySweepFeeAttachment;
} {
	const sweepTx = new bitcoin.Transaction();
	sweepTx.version = 2;
	const assetScripts = Array.from({ length: inputCount }, () => assetScript);
	const assetValues = Array.from({ length: inputCount }, () => 355);
	for (let index = 0; index < inputCount; index++)
		sweepTx.addInput(Buffer.alloc(32, index + 1), 0, 144);
	sweepTx.addOutput(assetScript, 355 * inputCount);
	for (let index = 0; index < inputCount; index++)
		sweepTx.setWitness(index, [
			Buffer.from(
				ecc.signSchnorr(
					sweepTx.hashForWitnessV1(index, assetScripts, assetValues, 0),
					secret
				)
			)
		]);
	const previous = new bitcoin.Transaction();
	previous.addInput(Buffer.alloc(32, 2), 0);
	previous.addOutput(changeScript, 20_000);
	const walletInput: ISpliceWalletInput = {
		prevTx: previous.toBuffer(),
		prevOutputIndex: 0,
		value: 20_000n,
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, index, value) => {
			const scriptCode = bitcoin.payments.p2pkh({ pubkey: publicKey }).output!;
			const signature = ecc.sign(
				tx.hashForWitnessV0(
					index,
					scriptCode,
					Number(value),
					bitcoin.Transaction.SIGHASH_ALL
				),
				secret
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(signature),
					bitcoin.Transaction.SIGHASH_ALL
				),
				publicKey
			];
		}
	};
	return {
		sweepTx,
		walletInput,
		attachment: {
			prevoutScripts: assetScripts,
			prevoutValues: assetValues.map(BigInt),
			sign: (transaction, scripts, values) => {
				const tx = bitcoin.Transaction.fromBuffer(transaction);
				tx.outs[0].script = destination;
				for (let index = 0; index < inputCount; index++)
					tx.setWitness(index, [
						Buffer.from(
							ecc.signSchnorr(
								tx.hashForWitnessV1(index, scripts, values.map(Number), 0),
								secret
							)
						)
					]);
				return { transaction: tx.toBuffer(), auxiliaryData: proofData };
			},
			finalize: () => true
		}
	};
}

function fund(
	value = fixture()
): ReturnType<typeof attachFeeInputsToAuxiliarySweepTx> {
	return attachFeeInputsToAuxiliarySweepTx({
		sweepTx: value.sweepTx,
		walletInputs: [value.walletInput],
		changeScript,
		feeratePerVbyte: 2,
		attachment: value.attachment
	});
}

describe('Wallet funded auxiliary carrier sweeps', () => {
	it('re-signs every original input in a combined asset sweep', () => {
		const { tx } = fund(fixture(2));
		expect(tx.outs[0].value).to.equal(710);
		for (let index = 0; index < 2; index++) {
			expect(
				ecc.verifySchnorr(
					tx.hashForWitnessV1(
						index,
						[assetScript, assetScript, changeScript],
						[355, 355, 20_000],
						0
					),
					publicKey.subarray(1),
					tx.ins[index].witness[0]
				)
			).to.equal(true);
		}
		const decoded = bitcoin.script.signature.decode(tx.ins[2].witness[0]);
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: publicKey }).output!;
		expect(
			ecc.verify(
				tx.hashForWitnessV0(
					2,
					scriptCode,
					20_000,
					bitcoin.Transaction.SIGHASH_ALL
				),
				publicKey,
				decoded.signature
			)
		).to.equal(true);
	});
	it('preserves a 355 sat asset carrier and verifies both final Bitcoin signatures', () => {
		const { tx, auxiliaryData } = fund();
		expect(tx.outs[0].value).to.equal(355);
		expect(tx.outs[0].script.equals(destination)).to.equal(true);
		expect(auxiliaryData.equals(proofData)).to.equal(true);
		expect(
			ecc.verifySchnorr(
				tx.hashForWitnessV1(0, [assetScript, changeScript], [355, 20_000], 0),
				publicKey.subarray(1),
				tx.ins[0].witness[0]
			)
		).to.equal(true);
		const decoded = bitcoin.script.signature.decode(tx.ins[1].witness[0]);
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: publicKey }).output!;
		expect(
			ecc.verify(
				tx.hashForWitnessV0(
					1,
					scriptCode,
					20_000,
					bitcoin.Transaction.SIGHASH_ALL
				),
				publicKey,
				decoded.signature
			)
		).to.equal(true);
		expect(
			20_355 - tx.outs.reduce((sum, output) => sum + output.value, 0)
		).to.be.at.least(tx.virtualSize() * 2);
	});

	it('pays the absolute replacement increment when the previous fee exceeds the new rate target', () => {
		const value = fixture();
		value.attachment.previousFee = 2_500n;
		const result = fund(value);
		expect(
			result.feeSatoshis >= 2_500n + BigInt(result.tx.virtualSize())
		).to.equal(true);
		expect(result.feeSatoshis).to.equal(
			BigInt(
				20_355 - result.tx.outs.reduce((sum, output) => sum + output.value, 0)
			)
		);
	});

	it('rejects wallet signer mutations of the asset witness', () => {
		const value = fixture();
		const original = value.walletInput.signWitness;
		value.walletInput.signWitness = (tx, index, amount) => {
			tx.ins[0].witness[0][0] ^= 1;
			return original(tx, index, amount);
		};
		expect(() => fund(value)).to.throw('existing auxiliary sweep witness');
	});

	it('rejects changed allocations and unproven Taproot fee change', () => {
		const value = fixture();
		const original = value.attachment.sign;
		value.attachment.sign = (...args) => {
			const signed = original(...args);
			const tx = bitcoin.Transaction.fromBuffer(signed.transaction);
			tx.outs[0].value--;
			return { ...signed, transaction: tx.toBuffer() };
		};
		expect(() => fund(value)).to.throw('funded sweep allocation');
		expect(() =>
			attachFeeInputsToAuxiliarySweepTx({
				...fixture(),
				walletInputs: [fixture().walletInput],
				changeScript: assetScript,
				feeratePerVbyte: 2
			})
		).to.throw('fee change must be P2WPKH');
	});

	it('drains only the newest waiting fee generation after stale one-coin cleanup', async () => {
		const value = fixture(),
			id = Buffer.alloc(32, 61),
			events: string[] = [],
			failures: string[] = [],
			broadcasts: Buffer[] = [];
		let frozen = false,
			persisted = false,
			selections = 0,
			generation = 1,
			releaseSelection!: () => void,
			started!: () => void;
		const selecting = new Promise<void>((resolve) => {
				started = resolve;
			}),
			paused = new Promise<void>((resolve) => {
				releaseSelection = resolve;
			});
		const manager = new ChannelManager({
			localBasepoints: {
				fundingPubkey: publicKey,
				revocationBasepoint: publicKey,
				paymentBasepoint: publicKey,
				delayedPaymentBasepoint: publicKey,
				htlcBasepoint: publicKey,
				firstPerCommitmentPoint: publicKey
			},
			localPerCommitmentSeed: Buffer.alloc(32, 9),
			localFundingPrivkey: secret,
			persistence: COMMIT_ALL,
			isMonitorPersisted: () => persisted
		});
		manager.on('error', (_channelId: Buffer | null, message: string) => {
			failures.push(message);
		});
		manager.on('monitor:updated', () => {
			persisted = true;
		});
		manager.on('broadcast:tx', (transaction: Buffer) => {
			expect(persisted).equal(true);
			broadcasts.push(transaction);
		});
		manager.setFundingProvider({
			selectFeeBumpInputs: async () => {
				expect(frozen).equal(
					false,
					'the prior attempt must finish cleanup before selection'
				);
				frozen = true;
				selections++;
				events.push(`select ${selections}`);
				if (selections === 1) {
					started();
					await paused;
				}
				return { inputs: [value.walletInput], changeScript };
			},
			releaseInputPledges: async () => {
				events.push('cleanup started');
				await Promise.resolve();
				frozen = false;
				events.push('cleanup finished');
			}
		} as unknown as IFundingProvider);
		const internal = manager as unknown as {
			monitors: Map<string, ChainMonitor>;
			_handleFeeBumpAndBroadcast(
				channelId: Buffer,
				action: IFeeBumpAndBroadcastChainAction
			): Promise<void>;
		};
		internal.monitors.set(id.toString('hex'), {
			getTrackedOutputs: () => []
		} as unknown as ChainMonitor);
		const action = (number: number): IFeeBumpAndBroadcastChainAction => ({
			type: ChainActionType.FEE_BUMP_AND_BROADCAST,
			kind: 'auxiliary-sweep-fee-attach',
			tx: value.sweepTx.toBuffer(),
			feeratePerVbyte: 2 + number,
			description: 'queued fee claim',
			auxiliarySweep: {
				...value.attachment,
				finalize: () => {
					events.push(`finalize ${number}`);
					return number === generation;
				}
			}
		});
		const first = internal._handleFeeBumpAndBroadcast(id, action(1));
		await selecting;
		generation = 2;
		const middle = internal._handleFeeBumpAndBroadcast(id, action(2));
		generation = 3;
		const last = internal._handleFeeBumpAndBroadcast(id, action(3));
		expect(selections).equal(1);
		releaseSelection();
		await Promise.all([first, middle, last]);
		expect(events).deep.equal([
			'select 1',
			'finalize 1',
			'cleanup started',
			'cleanup finished',
			'select 2',
			'finalize 3'
		]);
		expect(selections).equal(2);
		expect(broadcasts).length(1);
		expect(failures).deep.equal([]);
		expect(frozen).equal(true);
	});

	for (const outcome of [
		'initial',
		'late_success',
		'late_failure',
		'current_failure'
	] as const) {
		it(`discards ${outcome} stale fee work without releasing a retained candidate`, async () => {
			const value = fixture(),
				id = Buffer.alloc(32, 23),
				failures: string[] = [],
				broadcasts: Buffer[] = [];
			let current = outcome !== 'initial',
				selected = 0,
				released = 0;
			const manager = new ChannelManager({
				localBasepoints: {
					fundingPubkey: publicKey,
					revocationBasepoint: publicKey,
					paymentBasepoint: publicKey,
					delayedPaymentBasepoint: publicKey,
					htlcBasepoint: publicKey,
					firstPerCommitmentPoint: publicKey
				},
				localPerCommitmentSeed: Buffer.alloc(32, 9),
				localFundingPrivkey: secret,
				persistence: COMMIT_ALL
			});
			manager.on('error', (_id, message) => failures.push(message));
			manager.on('broadcast:tx', (raw) => broadcasts.push(raw));
			manager.setFundingProvider({
				buildFundingTransaction: async () => {
					throw new Error('Unexpected funding');
				},
				broadcastTransaction: async () => {
					throw new Error('Unexpected publication');
				},
				selectFeeBumpInputs: async () => {
					selected++;
					await Promise.resolve();
					if (outcome !== 'current_failure') current = false;
					if (outcome.endsWith('failure'))
						throw new Error('Current fee selection failed');
					return { inputs: [value.walletInput], changeScript };
				},
				releaseInputPledges: async () => {
					released++;
				}
			});
			const internal = manager as unknown as {
				monitors: Map<string, ChainMonitor>;
				_handleFeeBumpAndBroadcast(
					id: Buffer,
					action: IFeeBumpAndBroadcastChainAction
				): Promise<void>;
			};
			internal.monitors.set(id.toString('hex'), {
				getTrackedOutputs: () => []
			} as unknown as ChainMonitor);
			await internal._handleFeeBumpAndBroadcast(id, {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'auxiliary-sweep-fee-attach',
				tx: value.sweepTx.toBuffer(),
				description: 'stale fee work',
				feeratePerVbyte: 2,
				auxiliarySweep: value.attachment,
				isCurrent: () => current
			});
			expect(selected).equal(outcome === 'initial' ? 0 : 1);
			expect(released).equal(outcome === 'late_success' ? 1 : 0);
			expect(failures).length(outcome === 'current_failure' ? 1 : 0);
			expect(broadcasts).length(0);
		});
	}

	for (const outcome of ['saved', 'deferred', 'uncapped'] as const) {
		it(`preserves fixed peer outputs with ${outcome} bounded fee preparation`, async () => {
			const value = fixture(),
				id = Buffer.alloc(32, 19);
			const signature = Buffer.concat([
				Buffer.from(
					ecc.signSchnorr(
						value.sweepTx.hashForWitnessV1(0, [assetScript], [355], 0x81),
						secret
					)
				),
				Buffer.from([0x81])
			]);
			value.sweepTx.setWitness(0, [signature, signature]);
			const manager = new ChannelManager({
				localBasepoints: {
					fundingPubkey: publicKey,
					revocationBasepoint: publicKey,
					paymentBasepoint: publicKey,
					delayedPaymentBasepoint: publicKey,
					htlcBasepoint: publicKey,
					firstPerCommitmentPoint: publicKey
				},
				localPerCommitmentSeed: Buffer.alloc(32, 9),
				localFundingPrivkey: secret,
				persistence: COMMIT_ALL,
				isMonitorPersisted: () => true
			});
			let deferred = false,
				released = false,
				saved = false,
				writes = 0;
			const broadcasts: Buffer[] = [],
				failures: string[] = [];
			manager.on('error', (_id, message) => failures.push(message));
			manager.on('broadcast:tx', (transaction) => broadcasts.push(transaction));
			manager.on('monitor:updated', () => writes++);
			manager.setFundingProvider({
				supportsFixedOutputFees: () => true,
				buildFundingTransaction: async () => {
					throw new Error('Unexpected funding transaction');
				},
				broadcastTransaction: async () => {
					throw new Error('Unexpected direct publication');
				},
				selectFeeBumpInputs: async (_target, _rate, options) => {
					expect(options?.fixedOutputs).equal(true);
					expect(options?.feeActionId).equal(
						`asset-htlc:${id.toString('hex')}:${Buffer.from(
							value.sweepTx.ins[0].hash
						)
							.reverse()
							.toString('hex')}:0`
					);
					if (outcome === 'deferred')
						throw Object.assign(new Error('Awaiting fee preparation'), {
							code: 'FEE_PREPARATION_PENDING',
							transactionId: 'aa'.repeat(32)
						});
					return {
						inputs: [value.walletInput],
						changeScript,
						...(outcome === 'uncapped' ? {} : { maxFeeSatoshis: 20000n })
					};
				},
				releaseInputPledges: async () => {
					released = true;
				}
			} as IFundingProvider);
			const internal = manager as unknown as {
				monitors: Map<string, ChainMonitor>;
				_handleFeeBumpAndBroadcast(
					id: Buffer,
					action: IFeeBumpAndBroadcastChainAction
				): Promise<void>;
			};
			internal.monitors.set(id.toString('hex'), {
				getTrackedOutputs: () => []
			} as unknown as ChainMonitor);
			await internal._handleFeeBumpAndBroadcast(id, {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'htlc-fee-attach',
				tx: value.sweepTx.toBuffer(),
				description: 'fixed peer HTLC',
				feeratePerVbyte: 2,
				fixedHtlcOutputs: true,
				signHtlcFunding: (raw) => raw,
				deferHtlcFunding: () => {
					deferred = true;
					return true;
				},
				finalizeHtlcFunding: (raw, fee) => {
					const transaction = bitcoin.Transaction.fromBuffer(raw);
					expect(transaction.outs).deep.equal(value.sweepTx.outs);
					expect(transaction.ins[0].witness).deep.equal(
						value.sweepTx.ins[0].witness
					);
					expect(
						ecc.verifySchnorr(
							transaction.hashForWitnessV1(
								0,
								[assetScript, changeScript],
								[355, 20000],
								0x81
							),
							publicKey.subarray(1),
							signature.subarray(0, 64)
						)
					).equal(true);
					expect(fee).equal(20000n);
					saved = true;
					return true;
				}
			});
			expect(broadcasts).length(outcome === 'saved' ? 1 : 0);
			expect(deferred).equal(outcome === 'deferred');
			expect(saved).equal(outcome === 'saved');
			expect(released).equal(outcome === 'uncapped');
			expect(writes).equal(outcome === 'uncapped' ? 0 : 1);
			expect(failures).length(outcome === 'uncapped' ? 1 : 0);
		});
	}

	for (const kind of [
		'auxiliary-sweep-fee-attach',
		'htlc-fee-attach'
	] as const) {
		for (const outcome of [
			'saved',
			'refused',
			'stale',
			'forbidden',
			'unconfirmed',
			'stale_reuse'
		] as const) {
			it(`handles ${outcome} monitor persistence for ${kind} before broadcasting the exact candidate`, async () => {
				const value = fixture();
				if (kind === 'htlc-fee-attach') {
					const digest = value.sweepTx.hashForWitnessV1(
						0,
						[assetScript],
						[355],
						0x83
					);
					value.sweepTx.setWitness(0, [
						Buffer.concat([
							Buffer.from(ecc.signSchnorr(digest, secret)),
							Buffer.from([0x83])
						]),
						Buffer.concat([
							Buffer.from(ecc.signSchnorr(digest, secret)),
							Buffer.from([0x83])
						])
					]);
				}
				const id = Buffer.alloc(32, 5);
				const previousFunded =
					outcome === 'stale_reuse' ? fund(value).tx.toBuffer() : undefined;
				if (outcome === 'unconfirmed') {
					value.walletInput.confirmed = false;
					value.attachment.previousFee = 2_500n;
				}
				let persisted = false;
				let installed: Buffer | undefined;
				let released = false;
				const broadcasts: Buffer[] = [];
				const failures: string[] = [];
				const manager = new ChannelManager({
					localBasepoints: {
						fundingPubkey: publicKey,
						revocationBasepoint: publicKey,
						paymentBasepoint: publicKey,
						delayedPaymentBasepoint: publicKey,
						htlcBasepoint: publicKey,
						firstPerCommitmentPoint: publicKey
					},
					localPerCommitmentSeed: Buffer.alloc(32, 9),
					localFundingPrivkey: secret,
					persistence: COMMIT_ALL,
					isMonitorPersisted: () => persisted
				});
				manager.on('error', (_channelId: Buffer | null, message: string) =>
					failures.push(message)
				);
				manager.on('monitor:updated', () => {
					persisted = outcome === 'saved';
				});
				manager.on('broadcast:tx', (transaction: Buffer) => {
					expect(persisted).to.equal(true);
					if (kind === 'htlc-fee-attach') {
						const tx = bitcoin.Transaction.fromBuffer(transaction);
						expect(
							ecc.verifySchnorr(
								tx.hashForWitnessV1(
									0,
									[assetScript, changeScript],
									[355, 20_000],
									0x83
								),
								publicKey.subarray(1),
								tx.ins[0].witness[0].subarray(0, 64)
							)
						).to.equal(true);
					}
					broadcasts.push(transaction);
				});
				manager.setFundingProvider({
					selectFeeBumpInputs: async () => ({
						inputs: [value.walletInput],
						changeScript
					}),
					releaseInputPledges: async () => {
						released = true;
					}
				} as unknown as IFundingProvider);
				const internal = manager as unknown as {
					monitors: Map<string, ChainMonitor>;
					_handleFeeBumpAndBroadcast(
						channelId: Buffer,
						action: IFeeBumpAndBroadcastChainAction
					): Promise<void>;
				};
				internal.monitors.set(id.toString('hex'), {
					getTrackedOutputs: () => []
				} as unknown as ChainMonitor);
				value.attachment.finalize = (transaction, payload, fee) => {
					expect(payload.equals(proofData)).to.equal(true);
					expect(fee !== undefined && fee > 0n).to.equal(true);
					if (outcome === 'stale' || outcome === 'stale_reuse') return false;
					installed = Buffer.from(transaction);
					return true;
				};
				await internal._handleFeeBumpAndBroadcast(id, {
					type: ChainActionType.FEE_BUMP_AND_BROADCAST,
					kind,
					tx: value.sweepTx.toBuffer(),
					description: 'asset carrier',
					feeratePerVbyte: 2,
					isCurrent: () => installed === undefined,
					auxiliarySweep: value.attachment,
					previousFundedTransaction: previousFunded,
					conflictingCandidateTxids:
						outcome === 'forbidden'
							? [
									bitcoin.Transaction.fromBuffer(
										value.walletInput.prevTx
									).getId()
							  ]
							: [],
					...(kind === 'htlc-fee-attach'
						? {
								previousFee: 2_500n,
								signHtlcFunding: (raw: Buffer): Buffer => {
									const funded = bitcoin.Transaction.fromBuffer(raw);
									const digest = funded.hashForWitnessV1(
										0,
										[assetScript, changeScript],
										[355, 20_000],
										0x81
									);
									funded.ins[0].witness[1] = Buffer.concat([
										Buffer.from(ecc.signSchnorr(digest, secret)),
										Buffer.from([0x81])
									]);
									return funded.toBuffer();
								},
								finalizeHtlcFunding: (
									transaction: Buffer,
									fee?: bigint
								): boolean => {
									expect(
										fee !== undefined &&
											fee >=
												2_500n +
													BigInt(
														bitcoin.Transaction.fromBuffer(
															transaction
														).virtualSize()
													)
									).to.equal(true);
									return value.attachment.finalize(transaction, proofData, fee);
								}
						  }
						: {})
				});
				expect(broadcasts.length).to.equal(outcome === 'saved' ? 1 : 0);
				expect(released).to.equal(
					outcome === 'stale' ||
						outcome === 'forbidden' ||
						outcome === 'unconfirmed'
				);
				if (outcome === 'forbidden')
					expect(
						failures.some((message) =>
							message.includes('descends from a conflicting')
						)
					).to.equal(true);
				if (outcome === 'unconfirmed')
					expect(
						failures.some((message) =>
							message.includes('requires a confirmed input')
						)
					).to.equal(true);
				if (outcome === 'saved')
					expect(broadcasts[0].equals(installed!)).to.equal(true);
				if (outcome === 'refused') {
					expect(installed).to.not.equal(undefined);
					expect(failures).length(1);
				}
			});
		}
	}
});
