/**
 * Asset channels and the Recovery Protocol (issue #2093).
 *
 * The recovery journal carries the node's rows for an asset channel and
 * nothing of what its provider keeps beside them. Two rules follow.
 *
 * A node that replicates its journal to guardians neither opens nor accepts
 * an asset channel: a guardian restore puts the node's rows on another
 * device, and nothing in that protocol brings the provider's own state with
 * them.
 *
 * A restore that holds asset channels is refused unless the provider says it
 * can restore them (`IAuxiliaryChannelConfig.canRestore`). The refusal is
 * thrown inside the transaction that installs the restore, so nothing of it
 * is written. With no provider at all the refusal is the one a start over
 * such rows gives: `AuxiliaryProviderRequiredError`.
 */

import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryRestoredChannel
} from '../channel/auxiliary-funding';
import { isOverlayChannel } from '../channel/types';
import type { IChannelState } from '../channel/channel-state';
import { AuxiliaryProviderRequiredError } from '../node/types';
import type { IStorageBackend } from '../storage/types';
import { CodedError } from '../../utils/errors';

/**
 * An asset channel was about to be opened or accepted on a node that
 * replicates its recovery journal to guardians. Nothing was opened.
 */
export class AuxiliaryGuardianModeError extends CodedError<'AUXILIARY_GUARDIAN_MODE'> {
	constructor() {
		super(
			'AUXILIARY_GUARDIAN_MODE',
			'Asset channels cannot be opened or accepted while this node ' +
				'replicates its recovery journal to guardians ' +
				'(AUXILIARY_GUARDIAN_MODE). Use a recovery mode without guardians ' +
				'for a wallet that holds asset channels.'
		);
		this.name = 'AuxiliaryGuardianModeError';
	}
}

/**
 * A node set to replicate its recovery journal to guardians was started
 * over stored asset channels. Nothing was started, replicated or changed:
 * the same storage starts in a recovery mode without guardians.
 *
 * A guardian restore puts the journal's rows on another device, where
 * nothing can answer for an asset channel, and it can only be refused
 * there after the takeover has fenced this device. So the channel is kept
 * out of a guardian journal from the start.
 */
export class AuxiliaryGuardianStartError extends CodedError<'AUXILIARY_GUARDIAN_START_REFUSED'> {
	/** The stored asset channels, as channel id hex. */
	readonly channelIds: readonly string[];

	constructor(channelIds: readonly string[]) {
		const one = channelIds.length === 1;
		super(
			'AUXILIARY_GUARDIAN_START_REFUSED',
			`This wallet holds ${channelIds.length} asset channel${one ? '' : 's'} ` +
				`(${channelIds.join(', ')}) and is set to back up to guardians, ` +
				`which cannot restore an asset channel, so it was not started ` +
				`(AUXILIARY_GUARDIAN_START_REFUSED). Close the asset channel${
					one ? '' : 's'
				}, or start without the guardian backup.`
		);
		this.name = 'AuxiliaryGuardianStartError';
		this.channelIds = [...channelIds];
	}
}

/**
 * The journal a guardian restore fetched holds asset channels. Nothing of
 * it was installed.
 *
 * This build never replicates an asset channel to guardians: a node in a
 * guardian mode neither opens nor accepts one and does not start over one.
 * So no provider is asked here, and none is handed to a guardian restore.
 * The takeover has happened by the time the journal can be read, which is
 * why the refusals that keep an asset channel out of a guardian journal
 * come first, at the start and at the opening.
 */
export class AuxiliaryGuardianRestoreError extends CodedError<'AUXILIARY_GUARDIAN_RESTORE_REFUSED'> {
	/** The asset channels the journal holds, as channel id hex. */
	readonly channelIds: readonly string[];

	constructor(channelIds: readonly string[]) {
		const one = channelIds.length === 1;
		super(
			'AUXILIARY_GUARDIAN_RESTORE_REFUSED',
			`The journal the guardians hold for this wallet carries ` +
				`${channelIds.length} asset channel${one ? '' : 's'} ` +
				`(${channelIds.join(', ')}). This build never replicates an ` +
				`asset channel to guardians and cannot restore one from them, ` +
				`so nothing of the journal was installed ` +
				`(AUXILIARY_GUARDIAN_RESTORE_REFUSED).`
		);
		this.name = 'AuxiliaryGuardianRestoreError';
		this.channelIds = [...channelIds];
	}
}

/** An asset channel a restore holds, as a caller shows it. */
export interface IAuxiliaryRestoreChannel {
	/** Channel id, hex. */
	channelId: string;
	/** The peer's node id, hex. */
	peerPubkey: string;
	/** The capacity of the channel's funding output. */
	capacitySatoshis: bigint;
}

/**
 * A restore holds asset channels and the provider did not say it can restore
 * them. Nothing of the restore was installed.
 */
export class AuxiliaryRestoreRefusedError extends CodedError<'AUXILIARY_RESTORE_REFUSED'> {
	/** The asset channels the restore holds, as channel id hex. */
	readonly channelIds: readonly string[];
	/**
	 * The same channels with their peer and capacity, on the refusal of a
	 * capsule restore (read it through refusedAuxiliaryChannels).
	 */
	channels?: readonly IAuxiliaryRestoreChannel[];
	/** What the provider threw in place of an answer, when it did. */
	readonly detail?: string;

	constructor(channelIds: readonly string[], detail?: string) {
		const one = channelIds.length === 1;
		super(
			'AUXILIARY_RESTORE_REFUSED',
			`This restore holds ${channelIds.length} asset channel${
				one ? '' : 's'
			} ` +
				`(${channelIds.join(', ')}) and the asset channel provider did not ` +
				`say it can restore ${one ? 'it' : 'them'}, so nothing of ` +
				`${one ? 'it' : 'them'} was restored (AUXILIARY_RESTORE_REFUSED).` +
				(detail !== undefined ? ` The provider answered: ${detail}` : '')
		);
		this.name = 'AuxiliaryRestoreRefusedError';
		this.channelIds = [...channelIds];
		if (detail !== undefined) this.detail = detail;
	}
}

/**
 * Whether a node with this recovery configuration replicates its journal to
 * guardians: it was given a durability barrier, a startup gate or a guardian
 * set. A node that only keeps the journal, or pushes capsules to its storage
 * peers, does not.
 */
export function isGuardianRecoveryMode(
	recovery:
		| {
				barrier?: unknown;
				startupGate?: unknown;
				guardians?: readonly unknown[];
		  }
		| undefined
): boolean {
	return (
		recovery !== undefined &&
		(recovery.barrier !== undefined ||
			recovery.startupGate !== undefined ||
			(recovery.guardians?.length ?? 0) > 0)
	);
}

/** Whether a stored channel state is an asset channel's. */
function carriesAssetState(state: IChannelState): boolean {
	return (
		state.auxiliaryState !== undefined ||
		state.fundingTaprootMerkleRoot !== undefined ||
		isOverlayChannel(state.channelType)
	);
}

/**
 * The asset channels a storage holds, as channel id hex: the rows that
 * carry asset state and the asset rows that could not be read. Only reads.
 */
export function storedAuxiliaryChannelIds(storage: IStorageBackend): string[] {
	const readable = storage
		.loadAllChannels()
		.filter((row) => carriesAssetState(row.state))
		.map((row) => row.channelId);
	return [...readable, ...(storage.unreadableAssetChannelIds?.() ?? [])];
}

/**
 * Throw when the journal a guardian restore just replayed into `target`
 * holds an asset channel. Called inside the transaction that installs the
 * restore, so the throw leaves the target as it was.
 */
export function assertGuardianJournalHoldsNoAuxiliaryChannels(
	target: IStorageBackend
): void {
	const held = storedAuxiliaryChannelIds(target);
	if (held.length > 0) throw new AuxiliaryGuardianRestoreError(held);
}

/**
 * Why a restore of these asset channels is refused, or undefined when it
 * may go on: there are none, or the provider says it can restore them.
 */
export function auxiliaryRestoreRefusal(
	channels: readonly IAuxiliaryRestoredChannel[],
	auxiliaryChannels: IAuxiliaryChannelConfig | undefined,
	unreadableChannelIds: readonly string[] = []
): AuxiliaryProviderRequiredError | AuxiliaryRestoreRefusedError | undefined {
	if (channels.length === 0 && unreadableChannelIds.length === 0) {
		return undefined;
	}
	const channelIds = [
		...channels.map((channel) => channel.channelId.toString('hex')),
		...unreadableChannelIds
	];
	if (!auxiliaryChannels) return new AuxiliaryProviderRequiredError(channelIds);
	// A row that cannot be read is one nobody can answer for.
	if (unreadableChannelIds.length > 0 || !auxiliaryChannels.canRestore) {
		return new AuxiliaryRestoreRefusedError(channelIds);
	}
	let answer: unknown;
	try {
		answer = auxiliaryChannels.canRestore(channels);
	} catch (err) {
		return new AuxiliaryRestoreRefusedError(
			channelIds,
			err instanceof Error ? err.message : String(err)
		);
	}
	// Only a plain yes: a promise, or anything else truthy, is not one.
	return answer === true
		? undefined
		: new AuxiliaryRestoreRefusedError(channelIds);
}

/** The asset channels among the rows a restore is about to install. */
export function auxiliaryRestoreChannels(
	channels: ReadonlyArray<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}>
): IAuxiliaryRestoreChannel[] {
	return channels
		.filter((row) => carriesAssetState(row.state))
		.map((row) => ({
			channelId: row.channelId,
			peerPubkey: row.peerPubkey,
			capacitySatoshis: row.state.fundingSatoshis
		}));
}

/**
 * The asset channels a refused capsule restore holds, with their peer and
 * capacity: what the restore would leave out were it run again with
 * `omitAuxiliaryChannels`. Undefined for any other error, and for a refusal
 * that was not a capsule restore's.
 */
export function refusedAuxiliaryChannels(
	err: unknown
): readonly IAuxiliaryRestoreChannel[] | undefined {
	if (
		!(err instanceof AuxiliaryRestoreRefusedError) &&
		!(err instanceof AuxiliaryProviderRequiredError)
	) {
		return undefined;
	}
	const channels = (err as { channels?: unknown }).channels;
	return Array.isArray(channels)
		? (channels as IAuxiliaryRestoreChannel[])
		: undefined;
}

/**
 * Throw unless the asset channels among `channels`, the rows a restore is
 * about to install, may be restored. Returns their ids, as channel id hex.
 * The refusal carries the channels with their peer and capacity
 * (refusedAuxiliaryChannels).
 *
 * Called BEFORE the transaction that installs the restore opens, with the
 * rows read from the decoded frames (channelsAfterReplay): `canRestore` is
 * the provider's code, and a hook that ran inside the install would read
 * the uncommitted rows of the restore and have whatever it wrote to the
 * same database made part of it. A restore with no asset channel asks
 * nobody.
 */
export function assertAuxiliaryRestore(
	channels: ReadonlyArray<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}>,
	auxiliaryChannels: IAuxiliaryChannelConfig | undefined
): string[] {
	const held = channels.filter((row) => carriesAssetState(row.state));
	const refusal = auxiliaryRestoreRefusal(
		held.map(
			(row): IAuxiliaryRestoredChannel => ({
				channelId: Buffer.from(row.channelId, 'hex'),
				peerPubkey: row.peerPubkey,
				source: 'journal',
				...(row.state.auxiliaryState
					? { channelData: Buffer.from(row.state.auxiliaryState.channelData) }
					: {})
			})
		),
		auxiliaryChannels
	);
	if (refusal) {
		throw Object.assign(refusal, {
			channels: auxiliaryRestoreChannels(held)
		});
	}
	return held.map((row) => row.channelId);
}

/**
 * Throw unless the asset channels a restore installed into `target` are
 * exactly the ones that were asked about before it. Called inside the
 * install transaction, where it only reads: the answer was given for those
 * channels and no others, and a row that cannot be read back is one nobody
 * answered for.
 */
export function assertAuxiliaryRestoreInstalled(
	target: IStorageBackend,
	askedChannelIds: readonly string[]
): void {
	const installed = storedAuxiliaryChannelIds(target).sort();
	const asked = [...askedChannelIds].sort();
	if (
		installed.length !== asked.length ||
		installed.some((id, index) => id !== asked[index])
	) {
		throw new AuxiliaryRestoreRefusedError(
			[...new Set([...installed, ...asked])].sort(),
			'the restore installed other asset channels than the ones it was asked about'
		);
	}
}
