import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import {
	finalManifestDigest,
	layoutDigest
} from '../../src/lightning/channel/asset-opening-manifest';
import {
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_MONEY_SATS
} from '../../src/lightning/interactive-tx/validation';

const hash = (byte: number): Buffer => Buffer.alloc(32, byte);
const input = (serialId: bigint, vout: number) => ({
	serialId,
	txid: hash(8),
	vout,
	sequence: 0xfffffffd
});
const output = (
	serialId: bigint,
	kind: 'funding' | 'change',
	valueSats: bigint,
	byte: number
) => ({
	serialId,
	kind,
	valueSats,
	descriptorHash: hash(byte)
});
const layout = () => ({
	attempt: hash(1),
	chainHash: hash(2),
	channelId: hash(3),
	openHash: hash(4),
	acceptHash: hash(5),
	initiatorProposalHash: hash(6),
	acceptorProposalHash: hash(7),
	locktime: 62,
	inputs: [input(0n, 15), input(1n, 16)],
	outputs: [
		output(3n, 'change', 600n, 9),
		output(4n, 'funding', 94000n, 10),
		output(0xfffffffffffffffen, 'change', 800n, 11)
	]
});
type Layout = ReturnType<typeof layout>;
const p2tr = (byte: number): Buffer =>
	Buffer.concat([Buffer.from([0x51, 32]), hash(byte)]);
const funding = (terms: Layout): Transaction => {
	const tx = new Transaction();
	tx.version = 2;
	tx.locktime = terms.locktime;
	for (const prev of terms.inputs)
		tx.addInput(prev.txid, prev.vout, prev.sequence);
	terms.outputs.forEach((out, i) =>
		tx.addOutput(p2tr(32 + i), Number(out.valueSats))
	);
	return tx;
};
const final = (
	terms: Layout,
	tx = funding(terms),
	root = hash(13),
	signed: [Buffer, Buffer] = [hash(14), hash(15)],
	proof = hash(16)
): Buffer => finalManifestDigest(terms, tx, root, signed, proof);

describe('asset opening manifests for two contributors', () => {
	it('binds both roles, proposal terms and every item of the authorized layout', () => {
		const original = layoutDigest(layout());
		expect(original.toString('hex')).equal(
			'a9c71db4ee39d9f316e173c8a90907690ff355927f54d34247d6b3a7e2b52b55'
		);
		expect(layoutDigest(layout())).to.deep.equal(original);
		const edits: ((terms: Layout) => void)[] = [
			...(
				[
					'attempt',
					'chainHash',
					'channelId',
					'openHash',
					'acceptHash',
					'initiatorProposalHash',
					'acceptorProposalHash'
				] as const
			).map((field) => (terms: Layout) => {
				terms[field] = hash(20);
			}),
			(t) => {
				[t.initiatorProposalHash, t.acceptorProposalHash] = [
					t.acceptorProposalHash,
					t.initiatorProposalHash
				];
			},
			(t) => {
				t.locktime++;
			},
			(t) => {
				t.inputs[0].serialId = 2n;
				t.inputs.reverse();
			},
			(t) => {
				t.inputs[0].txid = hash(21);
			},
			(t) => {
				t.inputs[0].vout++;
				t.inputs[1].vout++;
			},
			(t) => {
				t.inputs[0].sequence--;
			},
			(t) => {
				t.outputs[2].serialId++;
			},
			(t) => {
				t.outputs[0].valueSats++;
			},
			(t) => {
				t.outputs[0].descriptorHash = hash(25);
			},
			(t) => {
				t.outputs[1].kind = 'change';
				t.outputs[2].kind = 'funding';
			},
			(t) => {
				t.outputs.pop();
			}
		];
		const changed = edits.map((edit) => {
			const terms = layout();
			edit(terms);
			return layoutDigest(terms).toString('hex');
		});
		expect(new Set([original.toString('hex'), ...changed]).size).equal(
			1 + edits.length
		);
	});

	it('rejects ambiguous, incomplete and out-of-range construction terms', () => {
		const edits: ((terms: Layout) => void)[] = [
			(t) => {
				t.inputs.reverse();
			},
			(t) => {
				t.outputs.reverse();
			},
			(t) => {
				t.inputs.splice(0, 1);
			},
			(t) => {
				t.inputs.splice(1, 1);
			},
			(t) => {
				t.inputs[1].vout = t.inputs[0].vout;
			},
			(t) => {
				t.outputs[1].kind = 'change';
			},
			(t) => {
				t.outputs[2].kind = 'funding';
			},
			(t) => {
				t.outputs[0].kind = 'funding';
				t.outputs[1].kind = 'change';
			},
			(t) => {
				t.outputs[0].serialId = t.inputs[1].serialId;
			},
			(t) => {
				t.outputs[2].serialId = 1n << 64n;
			},
			(t) => {
				t.inputs[0].serialId = -1n;
			},
			(t) => {
				t.inputs[0].sequence = 0xffffffff;
			},
			(t) => {
				t.inputs[0].vout = 2 ** 32;
			},
			(t) => {
				t.locktime = 2 ** 32;
			},
			(t) => {
				t.outputs[0].valueSats = MAX_MONEY_SATS + 1n;
			},
			(t) => {
				t.outputs[0].valueSats = -1n;
			},
			(t) => {
				t.acceptHash = Buffer.alloc(31);
			},
			(t) => {
				t.inputs[0].txid = Buffer.alloc(33);
			},
			(t) => {
				t.outputs[0].descriptorHash = Buffer.alloc(0);
			},
			(t) => {
				t.inputs = [
					input(1n, 0),
					...Array.from({ length: MAX_INTERACTIVE_TX_INPUTS + 1 }, (_, i) =>
						input(1000n + 2n * BigInt(i), i + 1)
					)
				];
			},
			(t) => {
				t.outputs = [
					t.outputs[1],
					...Array.from({ length: MAX_INTERACTIVE_TX_OUTPUTS }, (_, i) =>
						output(1000n + 2n * BigInt(i), 'change', 900n, 2)
					)
				];
			}
		];
		for (const edit of edits) {
			const terms = layout();
			edit(terms);
			expect(() => layoutDigest(terms)).to.throw();
		}
	});

	it('freezes the unsigned Bitcoin transaction exactly as declared', () => {
		const terms = layout();
		const edits: ((tx: Transaction) => void)[] = [
			(tx) => {
				tx.version = 1;
			},
			(tx) => {
				tx.locktime++;
			},
			(tx) => {
				tx.ins.reverse();
			},
			(tx) => {
				tx.ins[0].hash = hash(24);
			},
			(tx) => {
				tx.ins[0].index++;
			},
			(tx) => {
				tx.ins[0].sequence--;
			},
			(tx) => {
				tx.ins[0].script = Buffer.from([0x51]);
			},
			(tx) => {
				tx.setWitness(1, [Buffer.alloc(64, 1)]);
			},
			(tx) => {
				tx.ins.pop();
			},
			(tx) => {
				tx.outs.pop();
			},
			(tx) => {
				tx.outs.reverse();
			},
			(tx) => {
				tx.outs[0].value++;
			}
		];
		for (const edit of edits) {
			const tx = funding(terms);
			edit(tx);
			expect(() => final(terms, tx)).to.throw();
		}
	});

	it('commits separately to the final output scripts, authorizations and proof verdict', () => {
		const terms = layout();
		const digest = final(terms);
		expect(digest.toString('hex')).equal(
			'6813c042ebdd7a6346ad2322fa9136818386ec80b83f16a41bf8b6f974aed92e'
		);
		expect(final(layout())).to.deep.equal(digest);
		const changedScript = funding(terms);
		changedScript.outs[1].script = p2tr(70);
		const changedProposal = { ...terms, initiatorProposalHash: hash(4) };
		const changedAttempt = { ...terms, attempt: hash(37) };
		const variants = [
			layoutDigest(terms),
			final(changedAttempt),
			final(changedProposal),
			final(terms, changedScript),
			final(terms, undefined, hash(31)),
			final(terms, undefined, undefined, [hash(15), hash(14)]),
			final(terms, undefined, undefined, [hash(1), hash(15)]),
			final(terms, undefined, undefined, [hash(14), hash(1)]),
			final(terms, undefined, undefined, undefined, hash(11))
		];
		expect(
			new Set([digest, ...variants].map((v) => v.toString('hex'))).size
		).equal(1 + variants.length);
		expect(() => final(terms, undefined, Buffer.alloc(0))).to.throw();
		expect(() =>
			final(terms, undefined, undefined, [hash(14), Buffer.alloc(33)])
		).to.throw();
		expect(() =>
			final(terms, undefined, undefined, undefined, Buffer.alloc(64))
		).to.throw();
	});
});
