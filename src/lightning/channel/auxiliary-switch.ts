/**
 * Whether this build opens and accepts asset channels (issue #2093).
 *
 * On since an asset channel can also be closed and defended on chain: it
 * is closed cooperatively, swept after a force close, and a revoked
 * commitment of it is punished, HTLC outputs included. With this off an
 * asset opening is refused in both directions, by the channel manager,
 * before a key is derived or a message sent; every other channel is as it
 * was. Tests turn it off to reach that refusal; nothing else may, and the
 * package does not export it. A node without a provider opens and accepts
 * no asset channel whatever this says.
 */
export const auxiliaryChannelOpens = { enabled: true };

/**
 * Whether this build forwards an HTLC with an asset leg (issue #2098).
 *
 * On since such a forward can also be defended on the chain: in every
 * direction, with either channel closed by either side, a preimage the
 * outgoing leg gives up claims the incoming one, an outgoing leg that timed
 * out fails the incoming one back, and each leg's end is told to the host
 * durably. A node asks its host about a forward with an asset leg only when
 * the host supplies prepareForward; one that does not refuses every such
 * forward before anything is offered, as before. Tests turn it off to reach
 * that refusal; nothing else may, and the package does not export it.
 */
export const auxiliaryForwards = { enabled: true };
