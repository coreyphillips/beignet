import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { mnemonicToSeedSync } from 'bip39';
import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView
} from '../../src/lightning/channel/final-opening-commitment';
import { ASSET_OPENING_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	bip32RootFromSeed,
	deriveChannelKeys
} from '../../src/lightning/keys/wallet-keys';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import type { FinalOpeningAuthority } from '../../src/lightning/storage/final-opening-authority';
import {
	signFinalUpdate,
	spliceCommitmentNonceContext,
	updateVerificationNonce
} from '../../src/lightning/storage/final-update-signing';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import {
	boundParticipant,
	signingFixture
} from './helpers/final-opening-signing';
import { otherOpeningView } from './helpers/final-opening-commitment';

const openingRoot = Buffer.alloc(32, 32),
	candidateRoot = Buffer.alloc(32, 33);
const height = 1;
const leaf = (tag: number) => ({ script: Buffer.from([0x6a, 1, tag]) });
type Generation = 'opening' | 'splice';

function device(dir: string, name: string, rooted: boolean) {
	const generated = generateFinalDaemonWallet(!rooted, rooted);
	const party = boundParticipant(
		bip32RootFromSeed(mnemonicToSeedSync(generated.mnemonic)),
		1,
		generated.binding
	);
	const file = path.join(dir, name + '.db');
	const store = SqliteStorage.createFinalWallet(file, party.binding);
	return { party, file, store };
}
function authority(store: SqliteStorage): FinalOpeningAuthority {
	return (store as unknown as { openingAuthority: FinalOpeningAuthority })
		.openingAuthority;
}

function setup(directory: string, rooted: boolean) {
	const devices = [
		device(directory, 'a', rooted),
		device(directory, 'b', rooted)
	];
	const [alice, bob] = devices.map((d) => d.party);
	const { candidate, terms, id, funding } = signingFixture(false, alice, bob);
	if (rooted) {
		candidate.channelType = ASSET_OPENING_TYPE_HEX;
		funding.outs[candidate.fundingOutputIndex].script =
			createTaprootFundingScript(
				alice.keys.channelBasepoints.fundingPubkey,
				bob.keys.channelBasepoints.fundingPubkey,
				undefined,
				openingRoot
			).p2trOutput;
		candidate.fundingTxHex = funding.toHex();
	}
	const openings = [{ candidate, terms }, otherOpeningView(candidate, terms)];
	const nextKeys = [alice, bob].map((side) =>
		deriveChannelKeys(side.root, 1, 2)
	);
	const splice = new Transaction();
	splice.version = 2;
	splice.addInput(funding.getHash(), candidate.fundingOutputIndex, 0xfffffffd);
	splice.addOutput(
		Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, 55)]),
		12000
	);
	splice.addOutput(
		createTaprootFundingScript(
			nextKeys[0].channelBasepoints.fundingPubkey,
			nextKeys[1].channelBasepoints.fundingPubkey,
			undefined,
			rooted ? candidateRoot : undefined
		).p2trOutput,
		127500
	);

	function agreement(generation: Generation, holder: number) {
		const old = generation === 'opening';
		const tx = old ? funding : splice;
		const index = old ? candidate.fundingOutputIndex : 1;
		const root = old ? openingRoot : candidateRoot;
		const transcriptDigest = Buffer.alloc(32, old ? 75 : 76);
		const assets = {
			fundingRoot: root,
			toLocal: leaf(1),
			toRemote: leaf(2),
			htlcs: [
				{
					id: 3n,
					offeredBy: 'local' as const,
					output: leaf(3),
					secondLevel: leaf(4)
				}
			]
		};
		const point = getPublicKey(
			generateFromSeed(
				devices[holder].party.keys.perCommitmentSeed,
				MAX_INDEX - BigInt(height)
			)
		);
		const context = spliceCommitmentNonceContext(id, tx.getHash(), index);
		const keys = old ? [alice.keys, bob.keys] : nextKeys;
		const reservation = {
			pub: Buffer.from(
				updateVerificationNonce(
					authority(devices[holder].store).nonceContext(context),
					keys[holder].fundingPrivkey,
					height,
					{ pub: '', source: 'splice' }
				)
			).toString('hex'),
			source: 'splice' as const
		};
		function input(i: number) {
			const { candidate: opening, terms: agreementTerms } = openings[i];
			const reference = {
				fundingTxHex: tx.toHex(),
				fundingOutputIndex: index,
				localFundingKeyIndex: old ? 1 : 2,
				localFundingPubkey:
					keys[i].channelBasepoints.fundingPubkey.toString('hex'),
				remoteFundingPubkey:
					keys[1 - i].channelBasepoints.fundingPubkey.toString('hex')
			};
			const right = 40000000n;
			const left = BigInt(tx.outs[index].value) * 1000n - 5000000n - right;
			const balances = {
				localBalanceMsat: i === 0 ? left : right,
				remoteBalanceMsat: i === 0 ? right : left
			};
			const htlc = {
				id: 3n,
				offeredBy: i === 0 ? ('local' as const) : ('peer' as const),
				amountMsat: 5000000n,
				paymentHash: Buffer.alloc(32, 71),
				cltvExpiry: 601000
			};
			const owner = i === holder ? 'local' : 'remote';
			const view = rooted
				? buildAssetSpliceCommitment(
						opening,
						agreementTerms,
						owner,
						point,
						BigInt(height),
						balances,
						[htlc],
						reference,
						openingRoot,
						{
							...assets,
							htlcs: [{ ...assets.htlcs[0], offeredBy: htlc.offeredBy }]
						}
				  )
				: buildFinalCommitmentView(
						opening,
						agreementTerms,
						owner,
						point,
						BigInt(height),
						balances,
						[htlc],
						reference
				  );
			return {
				opening,
				view,
				funding: {
					reference,
					privateKey: keys[i].fundingPrivkey,
					...(rooted && { asset: { fundingRoot: root, transcriptDigest } })
				}
			};
		}
		function submit(
			i: number,
			peer?: Buffer,
			custom?: ReturnType<typeof input>['funding'],
			nonceKey = context
		) {
			const { opening, view, funding: standard } = input(i);
			return signFinalUpdate(
				opening,
				view,
				point,
				height,
				reservation,
				devices[i].party.keys,
				authority(devices[i].store),
				nonceKey,
				['0102'],
				peer,
				custom ?? standard
			);
		}
		return { tx, index, context, root, transcriptDigest, input, submit };
	}
	return { devices, agreement };
}

describe('Original device commitment signing across splice funding generations', function () {
	let directory: string;
	let fixture: ReturnType<typeof setup> | undefined;
	beforeEach(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-update-'));
	});
	afterEach(() => {
		fixture?.devices.forEach((d) => d.store.close());
		fixture = undefined;
		fs.rmSync(directory, { recursive: true, force: true });
	});
	for (const rooted of [true, false]) {
		it(`verifies both holders' aggregate signatures on both ${
			rooted ? 'asset' : 'ordinary bitcoin'
		} outputs at the same height`, function () {
			fixture = setup(directory, rooted);
			for (const generation of ['opening', 'splice'] as const) {
				for (const holder of [0, 1]) {
					const a = fixture.agreement(generation, holder);
					const wire = a.submit(1 - holder);
					const msg = decodeCommitmentSignedMessage(wire);
					expect(msg.fundingTxid).to.deep.equal(a.tx.getHash());
					expect(msg.htlcSignatures).to.have.length(1);
					const raw = a.submit(holder, wire);
					expect(a.submit(1 - holder)).to.deep.equal(wire);
					expect(a.submit(holder, wire)).to.deep.equal(raw);
					const tx = Transaction.fromBuffer(raw),
						prev = a.tx.outs[a.index];
					expect(tx.ins[0].hash).to.deep.equal(a.tx.getHash());
					expect(tx.ins[0].index).to.equal(a.index);
					expect(tx.ins[0].witness).to.have.length(1);
					expect(
						ecc.verifySchnorr(
							tx.hashForWitnessV1(
								0,
								[prev.script],
								[prev.value],
								Transaction.SIGHASH_DEFAULT
							),
							prev.script.subarray(2),
							tx.ins[0].witness[0]
						)
					).to.equal(true);
				}
			}
		});
	}

	it('refuses a missing, changed or incorrect-length asset root before emitting the first share', function () {
		fixture = setup(directory, true);
		const a = fixture.agreement('splice', 0);
		const funding = a.input(1).funding;
		for (const asset of [
			undefined,
			{ fundingRoot: openingRoot, transcriptDigest: a.transcriptDigest },
			{ fundingRoot: Buffer.alloc(31), transcriptDigest: a.transcriptDigest },
			{ fundingRoot: a.root, transcriptDigest: Buffer.alloc(31) }
		]) {
			expect(() => a.submit(1, undefined, { ...funding, asset })).to.throw();
		}
		expect(() => a.submit(1)).not.to.throw();
	});
	it('requires the generation-specific nonce context and an explicit peer funding tag before signing', function () {
		fixture = setup(directory, true);
		const parent = fixture.agreement('opening', 0),
			next = fixture.agreement('splice', 0);
		expect(() =>
			next.submit(1, undefined, undefined, parent.context)
		).to.throw();
		const raw = next.submit(1),
			fields = decodeCommitmentSignedMessage(raw);
		for (const fundingTxid of [undefined, parent.tx.getHash()]) {
			const unbound = encodeCommitmentSignedMessage({ ...fields, fundingTxid });
			expect(() => next.submit(0, unbound)).to.throw();
		}
		expect(() => next.submit(0, raw)).not.to.throw();
	});
	it('replays the original asset transcript after reopening and refuses a changed proof digest', function () {
		fixture = setup(directory, true);
		const a = fixture.agreement('splice', 0),
			signed = a.submit(1);
		const originalDevice = fixture.devices[1];
		originalDevice.store.close();
		fs.copyFileSync(originalDevice.file, path.join(directory, 'restored.db'));
		const restored = SqliteStorage.openFinalWallet(
			path.join(directory, 'restored.db'),
			originalDevice.party.binding
		);
		try {
			expect(authority(restored)).not.to.exist;
		} finally {
			restored.close();
		}
		originalDevice.store = SqliteStorage.openFinalWallet(
			originalDevice.file,
			originalDevice.party.binding
		);
		expect(a.submit(1)).to.deep.equal(signed);
		const funding = a.input(1).funding;
		expect(() =>
			a.submit(1, undefined, {
				...funding,
				asset: { fundingRoot: a.root, transcriptDigest: Buffer.alloc(32, 99) }
			})
		).to.throw();
		expect(a.submit(1)).to.deep.equal(signed);
	});
});
