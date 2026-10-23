/**
 * Persistence for ChannelManagers a test builds directly. The manager will
 * not construct without one (issue #1706), and the hooks below take the
 * place of the `channel:persist` listeners tests used to add.
 */

import type { ChannelManager } from '../../../src/lightning/channel/channel-manager';
import type {
	IChannelPersistence,
	IChannelPersistRequest,
	IChannelPersistResult
} from '../../../src/lightning/channel/channel-actions';

/**
 * Commits every write and stores nothing. For tests that are not about
 * durability, where every persist landing is the premise.
 */
export const COMMIT_ALL: IChannelPersistence = {
	persist: (): IChannelPersistResult => ({ committed: true, outboxIds: [] })
};

/** Fails every write, so the sends each persist authorizes are withheld. */
export const COMMIT_NONE: IChannelPersistence = {
	persist: (): IChannelPersistResult => ({ committed: false, outboxIds: [] })
};

/**
 * Sees one write after the manager's persistence answered it. Returning a
 * result replaces that answer; returning nothing keeps it.
 */
export type PersistHook = (
	request: IChannelPersistRequest,
	result: IChannelPersistResult
) => IChannelPersistResult | void;

function slot(manager: ChannelManager): { persistence: IChannelPersistence } {
	return manager as unknown as { persistence: IChannelPersistence };
}

/**
 * Run `hook` on each of the manager's writes, after the persistence it
 * already has (a LightningNode's storage, or a test's own). Hooks stack in
 * the order they are added, each seeing the answer the one before it gave.
 */
export function onPersist(manager: ChannelManager, hook: PersistHook): void {
	const inner = slot(manager).persistence;
	slot(manager).persistence = {
		persist: (request: IChannelPersistRequest): IChannelPersistResult => {
			const result = inner.persist(request);
			return hook(request, result) ?? result;
		}
	};
}

/** Replace the manager's persistence outright, hooks included. */
export function setPersistence(
	manager: ChannelManager,
	persistence: IChannelPersistence
): void {
	slot(manager).persistence = persistence;
}
