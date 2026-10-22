/**
 * Runtime checks for the optional capability groups of IStorageBackend
 * (IStorageCapabilities).
 */

import type {
	IRecoveryStorage,
	IStorageBackend,
	IStorageCapabilities,
	IStorageCore,
	StorageCapability
} from './types';

/** The methods of IStorageCore, which every backend implements. */
export const STORAGE_CORE_MEMBERS: Readonly<Record<keyof IStorageCore, true>> =
	{
		open: true,
		close: true,
		saveChannel: true,
		loadChannel: true,
		loadAllChannels: true,
		deleteChannel: true,
		savePayment: true,
		loadPayment: true,
		loadAllPayments: true,
		deletePayment: true,
		savePreimage: true,
		loadPreimage: true,
		loadAllPreimages: true,
		deletePreimage: true,
		saveScidMapping: true,
		loadAllScidMappings: true,
		saveHtlcPaymentMapping: true,
		loadAllHtlcPaymentMappings: true,
		deleteHtlcPaymentMapping: true,
		saveForwardedHtlc: true,
		loadAllForwardedHtlcs: true,
		deleteForwardedHtlc: true,
		saveChainMonitor: true,
		loadChainMonitor: true,
		loadAllChainMonitors: true,
		saveGossipChannel: true,
		loadAllGossipChannels: true,
		saveGossipNode: true,
		loadAllGossipNodes: true,
		savePaymentSecret: true,
		loadAllPaymentSecrets: true,
		deletePaymentSecret: true,
		deleteInvoicePathId: true,
		saveInvoice: true,
		loadAllInvoices: true,
		deleteInvoice: true,
		saveMissionControl: true,
		loadMissionControl: true,
		savePeerAddress: true,
		loadAllPeerAddresses: true,
		deletePeerAddress: true,
		saveChannelKeyIndex: true,
		loadChannelKeyIndex: true,
		loadNextChannelIndex: true,
		saveMetadata: true,
		loadMetadata: true,
		transaction: true,
		saveHtlcSharedSecret: true,
		deleteHtlcSharedSecret: true,
		loadAllHtlcSharedSecrets: true
	};

/**
 * The methods of each group. Typed against the group's interface, so a
 * method added to a group fails compilation here until it is listed.
 */
const CAPABILITY_MEMBERS: {
	readonly [K in StorageCapability]: Readonly<
		Record<keyof IStorageCapabilities[K], true>
	>;
} = {
	ffor: {
		saveFforVoucher: true,
		loadFforVoucher: true,
		loadAllFforVouchers: true
	},
	invoicePathIds: { saveInvoicePathId: true, loadAllInvoicePathIds: true },
	announcedPeerAddresses: {
		saveAnnouncedPeerAddresses: true,
		loadAllAnnouncedPeerAddresses: true
	},
	channelKeyIndexHistory: {
		hasChannelKeyIndices: true,
		loadAllChannelKeyIndices: true
	},
	metadataScan: { loadMetadataByPrefix: true, deleteMetadata: true },
	walletData: { saveWalletData: true, loadWalletData: true },
	gossipPaging: { loadGossipChannelsAfter: true, loadGossipNodesAfter: true },
	gossipPruning: { deleteGossipChannel: true, deleteGossipNode: true },
	channelPolicies: {
		saveChannelPolicy: true,
		loadAllChannelPolicies: true,
		deleteChannelPolicy: true
	},
	peerStorageBlobs: {
		savePeerStorageBlob: true,
		loadPeerStorageBlob: true,
		deletePeerStorageBlob: true
	},
	forwarding: {
		saveForwardingEvent: true,
		listForwardingEvents: true,
		getForwardingSummary: true
	},
	actionLog: { saveActionLog: true, loadActionLog: true },
	watchtower: {
		saveWatchtowerSession: true,
		loadWatchtowerSessions: true,
		setWatchtowerSessionProgress: true,
		deleteWatchtowerTower: true,
		addWatchtowerUpdate: true,
		loadPendingWatchtowerUpdates: true,
		markWatchtowerUpdateAcked: true
	},
	recoveryOutbox: {
		saveOutboxMessage: true,
		loadOutboxMessages: true,
		countOutboxMessages: true,
		setOutboxDisposition: true,
		deleteOutboxMessages: true,
		pruneOutboxMessages: true
	},
	recoveryJournal: {
		saveRecoveryFrame: true,
		loadRecoveryFrames: true,
		loadRecoveryFrame: true,
		loadRecoveryFrameHeader: true,
		deleteRecoveryFramesBelow: true,
		setOutboxFrameSequence: true,
		getRecoveryMeta: true,
		setRecoveryMeta: true,
		deleteRecoveryMeta: true,
		listRecoveryMetaKeys: true,
		recoveryFrameStats: true
	},
	offers: { saveOffer: true, loadAllOffers: true, deleteOffer: true }
};

/** Every capability group name. */
export const STORAGE_CAPABILITIES = Object.keys(
	CAPABILITY_MEMBERS
) as StorageCapability[];

/** The method names that make up a capability group. */
export function storageCapabilityMembers(
	capability: StorageCapability
): string[] {
	return Object.keys(CAPABILITY_MEMBERS[capability]);
}

/** Which of a group's methods `storage` implements. */
function implementedMembers(
	storage: IStorageBackend,
	capability: StorageCapability
): string[] {
	const methods = storage as unknown as Record<string, unknown>;
	return storageCapabilityMembers(capability).filter(
		(member) => typeof methods[member] === 'function'
	);
}

/** Whether `storage` implements every method of a capability group. */
export function hasStorageCapability<
	S extends IStorageBackend,
	K extends StorageCapability
>(storage: S, capability: K): storage is S & IStorageCapabilities[K] {
	return (
		implementedMembers(storage, capability).length ===
		storageCapabilityMembers(capability).length
	);
}

/** Whether `storage` implements the recovery outbox and journal both. */
export function hasRecoveryStorage<S extends IStorageBackend>(
	storage: S
): storage is S & IRecoveryStorage {
	return (
		hasStorageCapability(storage, 'recoveryOutbox') &&
		hasStorageCapability(storage, 'recoveryJournal')
	);
}

/**
 * The groups `storage` implements only part of. The library probes most
 * methods one at a time, so a partial group degrades without an error,
 * often by skipping what the missing method was for.
 */
export function partialStorageCapabilities(
	storage: IStorageBackend
): StorageCapability[] {
	return STORAGE_CAPABILITIES.filter((capability) => {
		const implemented = implementedMembers(storage, capability).length;
		return (
			implemented > 0 &&
			implemented < storageCapabilityMembers(capability).length
		);
	});
}
