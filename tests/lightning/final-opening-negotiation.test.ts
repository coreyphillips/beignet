import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import type { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import {
	getPublicKey,
	isValidPublicKey
} from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxCompleteMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';
import { otherOpeningView } from './helpers/final-opening-commitment';
import { channelType, inputTransaction } from './helpers/final-opening';

function wire(actions: ChannelAction[], type: MessageType): Buffer {
	for (const action of actions)
		if (
			action.type === ChannelActionType.SEND_MESSAGE &&
			action.messageType === type
		)
			return action.payload;
	throw Error('missing message ' + type + ': ' + JSON.stringify(actions));
}
function params(
	side: typeof alice,
	fundingSatoshis: bigint,
	type: string
): IDualFundingParams {
	return {
		...DEFAULT_CHANNEL_CONFIG,
		fundingSatoshis,
		fundingFeeratePerkw: 253,
		commitmentFeeratePerkw: 253,
		locktime: 0,
		channelFlags: 0,
		channelType: Buffer.from(type, 'hex'),
		localBasepoints: side.keys.channelBasepoints,
		localPerCommitmentSeed: side.keys.perCommitmentSeed,
		secondPerCommitmentPoint: getPublicKey(
			generateFromSeed(side.keys.perCommitmentSeed, MAX_INDEX - 1n)
		)
	};
}

describe('Interactive final funding negotiation', () => {
	it('waits for the longer peer contribution before freezing the automatic opening', async () => {
		const { enrollFinalNegotiation, snapshotFinalOpening } = await import(
			'../../src/lightning/channel/final-opening-negotiation'
		);
		const type = channelType(80);
		const paramsA = params(alice, 100000n, type),
			paramsB = params(bob, 25000n, type);
		const state = (
			s: typeof alice,
			value: bigint
		): Parameters<typeof createOpenerState>[0] => ({
			temporaryChannelId: Buffer.alloc(32),
			localConfig: DEFAULT_CHANNEL_CONFIG,
			pushMsat: 0n,
			fundingSatoshis: value,
			localBasepoints: s.keys.channelBasepoints,
			localPerCommitmentSeed: s.keys.perCommitmentSeed
		});
		const a = new Channel(
			createOpenerState(state(alice, 100000n)),
			new ChannelSigner(alice.keys.fundingPrivkey)
		);
		enrollFinalNegotiation(a);
		const opened = decodeOpenChannel2Message(
			wire(a.initiateOpenV2(paramsA), MessageType.OPEN_CHANNEL2)
		);
		const b = new Channel(
			createAcceptorState({
				...state(bob, 0n),
				temporaryChannelId: opened.channelId,
				remoteBasepoints: paramsA.localBasepoints,
				remoteConfig: DEFAULT_CHANNEL_CONFIG
			}),
			new ChannelSigner(bob.keys.fundingPrivkey)
		);
		enrollFinalNegotiation(b);
		function contribute(
			c: Channel,
			id: number,
			amounts: number[],
			target: bigint
		): void {
			const inputs = amounts.map((v, i) => {
				const prev = inputTransaction(id + i, v);
				return {
					prevTx: prev.toBuffer(),
					prevOutputIndex: 0,
					value: BigInt(v),
					sequence: 0xfffffffd,
					confirmed: true,
					signWitness: (): Buffer[] => {
						throw Error('unexpected signing during negotiation');
					}
				};
			});
			c.setDualFundingContribution(
				inputs,
				inputTransaction(id + 20, 1000).outs[0].script,
				target,
				253
			);
		}
		contribute(a, 1600, [110000], 100000n);
		contribute(b, 1700, [30000, 12000, 14000], 25000n);
		a.handleAcceptChannel2(
			decodeAcceptChannel2Message(
				wire(b.handleOpenChannel2(opened, paramsB), MessageType.ACCEPT_CHANNEL2)
			)
		);
		let sender = a,
			receiver = b,
			pending = a.beginDualFundingContribution(),
			viable = 0;
		for (let i = 0; i < 32 && pending.length; i++) {
			const next: ChannelAction[] = [];
			for (const action of pending) {
				expect(action.type).not.to.equal(ChannelActionType.ERROR);
				if (action.type === ChannelActionType.FINAL_OPENING_TX_COMPLETE) {
					const view = snapshotFinalOpening(sender);
					if (view) {
						viable++;
						expect(view.candidate.inputs).to.have.length(4);
						expect(view.candidate.outputSerialIds).to.have.length(3);
					}
					if (viable < 2) next.push(...receiver.handleTxComplete());
				} else if (
					action.type === ChannelActionType.SEND_MESSAGE &&
					action.messageType === MessageType.TX_ADD_INPUT
				)
					next.push(
						...receiver.handleTxAddInput(
							decodeTxAddInputMessage(action.payload)
						)
					);
				else if (
					action.type === ChannelActionType.SEND_MESSAGE &&
					action.messageType === MessageType.TX_ADD_OUTPUT
				)
					next.push(
						...receiver.handleTxAddOutput(
							decodeTxAddOutputMessage(action.payload)
						)
					);
			}
			[sender, receiver] = [receiver, sender];
			pending = next;
		}
		expect(viable).to.equal(2);
		const result = snapshotFinalOpening(a)!;
		expect(snapshotFinalOpening(b)).to.deep.equal(
			otherOpeningView(result.candidate, result.terms)
		);
	});

	for (const type of [channelType(80), channelType(80, 46)]) {
		it(
			'freezes ' +
				type +
				' only after the shared Taproot output, preserving change and both ownership views',
			async () => {
				const {
					enrollFinalNegotiation,
					snapshotFinalOpening,
					disposableFinalTxComplete
				} = await import(
					'../../src/lightning/channel/final-opening-negotiation'
				);
				const { candidate, funding, id } = signingFixture(true);
				const state = (
					side: typeof alice,
					sats: bigint
				): Parameters<typeof createOpenerState>[0] => ({
					temporaryChannelId: Buffer.alloc(32),
					fundingSatoshis: sats,
					pushMsat: 0n,
					localConfig: DEFAULT_CHANNEL_CONFIG,
					localBasepoints: side.keys.channelBasepoints,
					localPerCommitmentSeed: side.keys.perCommitmentSeed
				});
				const opening = (): Channel =>
					new Channel(
						createOpenerState(state(alice, 140000n)),
						new ChannelSigner(alice.keys.fundingPrivkey)
					);
				const a = opening(),
					ap = params(alice, 140000n, type),
					bp = params(bob, 0n, type);
				expect(
					opening()
						.initiateOpenV2(ap)
						.some((x) => x.type === ChannelActionType.ERROR)
				).to.equal(true);
				enrollFinalNegotiation(a);
				const offer = decodeOpenChannel2Message(
					wire(a.initiateOpenV2(ap), MessageType.OPEN_CHANNEL2)
				);
				const b = new Channel(
					createAcceptorState({
						...state(bob, 0n),
						temporaryChannelId: offer.channelId,
						remoteBasepoints: ap.localBasepoints,
						remoteConfig: DEFAULT_CHANNEL_CONFIG
					}),
					new ChannelSigner(bob.keys.fundingPrivkey)
				);
				enrollFinalNegotiation(b);
				a.handleAcceptChannel2(
					decodeAcceptChannel2Message(
						wire(b.handleOpenChannel2(offer, bp), MessageType.ACCEPT_CHANNEL2)
					)
				);
				const prev = Transaction.fromHex(candidate.inputs[0].prevTxHex);
				prev.outs[0].value += 1200;
				const addInput = a.addTxInput({
					serialId: 0n,
					prevTxid: prev.getHash(),
					prevOutputIndex: 0,
					prevTx: prev.toBuffer(),
					prevTxVout: 0,
					sequence: 0xfffffffd
				});
				b.handleTxAddInput(
					decodeTxAddInputMessage(wire(addInput, MessageType.TX_ADD_INPUT))
				);
				const marker = (actions: ChannelAction[]): void => {
					expect(actions).to.deep.include({
						type: ChannelActionType.FINAL_OPENING_TX_COMPLETE,
						channelId: Buffer.from(id, 'hex')
					});
					expect(
						actions.some(
							(x) =>
								x.type === ChannelActionType.SEND_MESSAGE &&
								[
									MessageType.COMMITMENT_SIGNED,
									MessageType.TX_SIGNATURES
								].includes(x.messageType)
						)
					).to.equal(false);
				};
				marker(b.sendTxComplete());
				const disposable = disposableFinalTxComplete(b);
				const pair = decodeTxCompleteMessage(disposable, { taproot: true })
					.commitNonces!;
				expect(pair.current.equals(pair.next)).to.equal(false);
				for (const nonce of [pair.current, pair.next]) {
					expect(isValidPublicKey(nonce.subarray(0, 33))).to.equal(true);
					expect(isValidPublicKey(nonce.subarray(33))).to.equal(true);
				}
				a.handleTxComplete();
				const change = a.addTxOutput({
					serialId: 2n,
					amountSats: 1200n,
					scriptPubkey: prev.outs[0].script
				});
				b.handleTxAddOutput(
					decodeTxAddOutputMessage(wire(change, MessageType.TX_ADD_OUTPUT))
				);
				expect(snapshotFinalOpening(a)).to.equal(null);
				expect(snapshotFinalOpening(b)).to.equal(null);
				marker(b.sendTxComplete());
				a.handleTxComplete();
				const shared = a.addTxOutput({
					serialId: 4n,
					amountSats: 140000n,
					scriptPubkey: funding.outs[0].script
				});
				b.handleTxAddOutput(
					decodeTxAddOutputMessage(wire(shared, MessageType.TX_ADD_OUTPUT))
				);
				marker(b.sendTxComplete());
				a.handleTxComplete();
				marker(a.sendTxComplete());
				marker(b.handleTxComplete());
				const ours = snapshotFinalOpening(a)!;
				expect(ours.candidate.channelType).to.equal(type);
				expect(ours.candidate.channelId).to.equal(id);
				expect(ours.candidate.fundingOutputIndex).to.equal(1);
				expect(ours.candidate.inputs[0].isLocal).to.equal(true);
				expect(ours.candidate.outputSerialIds).to.deep.equal(['2', '4']);
				expect(snapshotFinalOpening(b)).to.deep.equal(
					otherOpeningView(ours.candidate, ours.terms)
				);
			}
		);
	}
});
