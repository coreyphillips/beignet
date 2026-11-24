import type { BIP32Interface } from 'bip32';
import { deriveLightningKeys } from '../keys/wallet-keys';
import type { INodeConfig } from '../node/types';
import { Network } from '../invoice/types';
import { getPublicKey } from '../crypto/ecdh';
import type { SqliteStorage } from './sqlite-storage';
import { requireLegacyWallet } from './wallet-format-guard';
import type { IFinalOpeningRuntime } from '../channel/final-opening-runtime';

interface Admission
	extends Required<Pick<INodeConfig, 'fundingProvider' | 'chainBackend'>> {
	runtime: IFinalOpeningRuntime;
	storage: SqliteStorage;
	nodeId: string;
}
const admitted = new WeakMap<object, Admission>();

/** Bind only the daemon's fenced view, after opening the original signed wallet. */
export function bindFinalDaemonView(
	storage: SqliteStorage,
	root: BIP32Interface,
	fundingProvider: Admission['fundingProvider'],
	chainBackend: Admission['chainBackend']
): void {
	const nodeId = deriveLightningKeys(root, 1).nodePublicKey.toString('hex');
	storage.assertFinalDaemonIdentity(nodeId);
	if (typeof fundingProvider.resolveFinalOpeningInputs !== 'function')
		throw new Error(
			'Final daemon requires wallet-owned funding input resolution'
		);
	admitted.set(storage, {
		runtime: { storage, root },
		storage,
		nodeId,
		fundingProvider,
		chainBackend
	});
}

export function finalDaemonForNode(config: INodeConfig): Admission | undefined {
	const { storage } = config;
	const entry = storage && admitted.get(storage);
	if (!entry) {
		requireLegacyWallet(storage);
		return;
	}
	if (
		config.network !== Network.REGTEST ||
		config.recovery?.enabled ||
		config.chainBackend !== entry.chainBackend ||
		config.fundingProvider !== entry.fundingProvider ||
		getPublicKey(config.nodePrivateKey).toString('hex') !== entry.nodeId
	)
		throw new Error('Final wallet runtime identity mismatch');
	entry.storage.assertFinalDaemonIdentity(entry.nodeId);
	return entry;
}

/** Permit ordinary transaction bookkeeping only for this exact admitted node. */
export function requireRecoveryManagerAdmission(
	storage: object,
	token?: object
): void {
	if (token && admitted.get(storage) === token) return;
	requireLegacyWallet(storage);
}
