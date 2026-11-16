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
 * A restore holds asset channels and the provider did not say it can restore
 * them. Nothing of the restore was installed.
 */
export class AuxiliaryRestoreRefusedError extends CodedError<'AUXILIARY_RESTORE_REFUSED'> {
	/** The asset channels the restore holds, as channel id hex. */
	readonly channelIds: readonly string[];
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

/**
 * Throw unless the asset channels a restore just replayed into `target` may
 * be restored. Called inside the transaction that installs the restore, so
 * a throw leaves the target as it was. A target with no asset channel is
 * only read.
 */
export function assertAuxiliaryRestore(
	target: IStorageBackend,
	auxiliaryChannels: IAuxiliaryChannelConfig | undefined
): void {
	const channels = target
		.loadAllChannels()
		.filter((row) => carriesAssetState(row.state))
		.map(
			(row): IAuxiliaryRestoredChannel => ({
				channelId: Buffer.from(row.channelId, 'hex'),
				peerPubkey: row.peerPubkey,
				source: 'journal',
				...(row.state.auxiliaryState
					? { channelData: Buffer.from(row.state.auxiliaryState.channelData) }
					: {})
			})
		);
	const refusal = auxiliaryRestoreRefusal(
		channels,
		auxiliaryChannels,
		target.unreadableAssetChannelIds?.() ?? []
	);
	if (refusal) throw refusal;
}
