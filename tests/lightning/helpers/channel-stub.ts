import type { ChannelAction } from '../../../src/lightning/channel/channel-actions';

/**
 * What ChannelManager's dispatch calls on every channel it handles, answered
 * the way a real channel with no quiescence session and no FFOR epoch
 * answers. Spread into a channel-shaped stub, so the stub only spells out
 * what its own test is about.
 */
export const IDLE_CHANNEL_MEMBERS = {
	isQuiescing: (): boolean => false,
	setFforContext: (): void => undefined,
	setFforCapabilities: (): void => undefined,
	getFforEpoch: (): null => null,
	fforHoldStream: (actions: ChannelAction[]): ChannelAction[] => actions,
	fforNoteStateWritten: (): void => undefined,
	fforNoteActivateAckSent: (): void => undefined,
	fforTakeReconnectRequest: (): boolean => false
};
