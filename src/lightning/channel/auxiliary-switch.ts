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
 * Off until the step of that issue that defends such a forward on chain:
 * with it off, a node refuses every forward with an asset leg before
 * anything is offered, whatever its host supplies, and asks its host
 * nothing. Step 2 of the issue runs behind it: a bitcoin HTLC whose next
 * hop is a short channel id the host claims, or an asset channel the onion
 * names, forwarded over that asset channel with the records the host made.
 * So does step 3: an HTLC that came in on an asset channel with units,
 * forwarded over the ordinary channel the onion names when the host's
 * value for it covers the amount to forward and the node's fee.
 * Tests turn it on to reach that; nothing else may, and the package does
 * not export it.
 */
export const auxiliaryForwards = { enabled: false };
