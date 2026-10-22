import type { Channel } from '../../../src/lightning/channel/channel';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';

/**
 * The channel's live state with write access, for a fixture that needs a
 * state no named transition reaches. getFullState() is typed read-only, so
 * every test that writes channel state directly says so by coming through
 * here.
 */
export function writableState(channel: Channel): IChannelState {
	return channel.getFullState() as IChannelState;
}
