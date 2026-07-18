/**
 * BOLT 3: Per-commitment secret generation and storage vectors (Appendix D).
 *
 * Generation: generate_from_seed(seed, I) must reproduce the spec secret.
 * Storage: each insert_secret sequence is replayed against a fresh compact
 * store; every OK step must be accepted and every ERROR step rejected (the
 * spec sequences always end at the first ERROR).
 */

import { expect } from 'chai';
import {
	generateFromSeed,
	ShaChainStore
} from '../../../src/lightning/keys/shachain';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IGenerationCase {
	name: string;
	seed: string;
	index: string;
	output: string;
}

interface IStorageCase {
	name: string;
	inserts: { index: string; secret: string; output: 'OK' | 'ERROR' }[];
}

interface ISecretVectors {
	generation: IGenerationCase[];
	storage: IStorageCase[];
}

const v = loadVectors<ISecretVectors>('bolt03/per-commitment-secrets.json');

describe('BOLT 3: per-commitment secret conformance', function () {
	describe('generation tests', function () {
		for (const c of v.generation) {
			it(`${c.name}`, function () {
				const secret = generateFromSeed(hexToBuffer(c.seed), BigInt(c.index));
				expect(bufferToHex(secret)).to.equal(c.output.toLowerCase());
			});
		}
	});

	describe('storage tests', function () {
		for (const c of v.storage) {
			it(`${c.name}`, function () {
				const store = new ShaChainStore();
				for (const step of c.inserts) {
					const accepted = store.addSecret(
						BigInt(step.index),
						hexToBuffer(step.secret)
					);
					expect(accepted, `index ${step.index}`).to.equal(
						step.output === 'OK'
					);
				}
			});
		}
	});
});
