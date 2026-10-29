/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 7: a close with nothing in flight broadcasts the transactions master
 * does.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	sha256,
	Flavor,
	FLAVORS,
	Side,
	shutdown,
	makeFundedPair,
	START,
	problemsOf,
	expectNoProblems,
	who
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 7. no HTLC at all ─────────────

	describe('7. a close with nothing in flight is unchanged', function () {
		/**
		 * Recorded on master (f16dfe5b) with this harness: every key, txid and
		 * preimage is derived from the tag, and the ECDSA signatures are
		 * deterministic, so the same close produces the same bytes. Each entry
		 * is the broadcasting side, the txid, and the SHA-256 of the whole
		 * transaction, witness included. Taproot closes sign with fresh MuSig2
		 * nonces; their txid, which leaves the witness out, pins everything
		 * else. CLOSE_GATE_PRINT_GOLDEN=1 prints the current values instead.
		 */
		const GOLDEN: Record<Flavor, Record<Side, string[]>> = {
			legacy: {
				A: [
					'A 4d4d51e0f75314d7d0717eeb42bd82fa9094b47c0fd7dcf21962575b463baa24 d817ffcc19295f00e054ed3b0bfd2c7ac0250f1b8af498136b89ce93506e9386',
					'B 4d4d51e0f75314d7d0717eeb42bd82fa9094b47c0fd7dcf21962575b463baa24 d817ffcc19295f00e054ed3b0bfd2c7ac0250f1b8af498136b89ce93506e9386'
				],
				B: [
					'A df8d453b9367ff8c2d9a51366fe54d6692ab6850d3697b4b721ded1d866e0341 ee83c0ff643e80a84a5a4947e0b581523104e08cae91bf6dfdd6a4991dcb3507',
					'B df8d453b9367ff8c2d9a51366fe54d6692ab6850d3697b4b721ded1d866e0341 ee83c0ff643e80a84a5a4947e0b581523104e08cae91bf6dfdd6a4991dcb3507'
				]
			},
			simple: {
				A: [
					'A 4c1c464682626cad7d64bf735a5727d86dfb9a3216f07d0295c1f43307f9dd0d 679aaacb6df6afd8c211e11b1feb2bf1a84f3f7f62b00357c5e59ba7c01a1349',
					'A 223c60488e5a172e09fe65e42d6f20f87dcbdb14f5bf96e9714309d7cd14c60e 9e5236c25adcf7ee88da54480f79864ee38b642d15bbbf9275018d57f29e38cd',
					'B 223c60488e5a172e09fe65e42d6f20f87dcbdb14f5bf96e9714309d7cd14c60e 9e5236c25adcf7ee88da54480f79864ee38b642d15bbbf9275018d57f29e38cd',
					'B 4c1c464682626cad7d64bf735a5727d86dfb9a3216f07d0295c1f43307f9dd0d 679aaacb6df6afd8c211e11b1feb2bf1a84f3f7f62b00357c5e59ba7c01a1349'
				],
				B: [
					'A 639b00c029727cd1f5a804d8ca8da54c892b86c8ce1d1ee253bc63862ddd5ce9 114b23387904236bbbc4d399f1e7c1829e2cbb55529fffefa32ef81245bbc705',
					'A 559aa21fcf6f66bef88e83ae962b47863681d4f201eb066c586ca79290df11c8 4108baf35f2ff2a845b4701127d02c72775afcd79fdf2216d2780672c560b4fa',
					'B 559aa21fcf6f66bef88e83ae962b47863681d4f201eb066c586ca79290df11c8 4108baf35f2ff2a845b4701127d02c72775afcd79fdf2216d2780672c560b4fa',
					'B 639b00c029727cd1f5a804d8ca8da54c892b86c8ce1d1ee253bc63862ddd5ce9 114b23387904236bbbc4d399f1e7c1829e2cbb55529fffefa32ef81245bbc705'
				]
			},
			taproot: {
				A: [
					'A 925286e5ef3669a95626156a08997561753fd6f008d6cf93b32cf05d8c5681c0',
					'B 925286e5ef3669a95626156a08997561753fd6f008d6cf93b32cf05d8c5681c0'
				],
				B: [
					'A 249720beff937ffa5e1451b80f40b6529e86eab3816cca7188bd1d2f8350532a',
					'B 249720beff937ffa5e1451b80f40b6529e86eab3816cca7188bd1d2f8350532a'
				]
			}
		};

		for (const flavor of FLAVORS) {
			for (const initiator of ['A', 'B'] as Side[]) {
				it(`${flavor}, shutdown from ${who(
					initiator
				)}: the broadcast transactions are the ones master produces`, function () {
					const t = makeFundedPair(`plain-${flavor}`, flavor);
					shutdown(t, initiator);
					expectNoProblems(problemsOf(t, START));
					const seen: string[] = [];
					for (const side of ['A', 'B'] as Side[]) {
						for (const raw of t.broadcasts[side]) {
							const tx = bitcoin.Transaction.fromBuffer(raw);
							seen.push(
								flavor === 'taproot'
									? `${side} ${tx.getId()}`
									: `${side} ${tx.getId()} ${sha256(raw).toString('hex')}`
							);
						}
					}
					if (process.env.CLOSE_GATE_PRINT_GOLDEN) {
						// eslint-disable-next-line no-console
						console.log(
							`GOLDEN ${flavor} ${initiator} ${JSON.stringify(seen)}`
						);
						return;
					}
					expect(seen).to.deep.equal(GOLDEN[flavor][initiator]);
				});
			}
		}
	});
});
