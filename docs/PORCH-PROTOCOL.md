# Porch: a blind relay for Lightning peer connections

Protocol version 1. "Porch" is a working name.

## What it is for

A node at home wants a link it can hand to other people without telling them
where it runs. Any direct or hole-punched path shows each end the other's IP
address, so the node needs something in the middle. Porch is that something,
kept as small as it can be:

- the **host** (the node) dials out to a relay and waits there;
- a **visitor** connects to the relay with an ordinary `wss://` peer URI;
- the relay pairs the two and copies bytes.

The bytes are BOLT 8. The relay cannot read them, change them or stand in for
either side, because BOLT 8 authenticates the node's Lightning key end to end.
Nothing new runs on the visitor: a client that can dial
`pubkey@wss://host/path` already speaks Porch.

The relay holds no keys and stores nothing. Restarting it loses the
connections that were open and nothing else.

## Roles and trust

|         | Learns                                                                                                                                                     | Cannot                                                        |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Visitor | the relay's address, the route id, the node's Lightning pubkey (it is in the link)                                                                         | learn the host's IP address                                   |
| Relay   | the visitor's IP address; the host's IP address, or a Tor exit's when the host dials through Tor; the host key, link tags and route ids; timing and volume | read or forge traffic; learn the Lightning pubkey by watching |
| Host    | which link a visitor used                                                                                                                                  | learn the visitor's IP address                                |

The relay can still test a guess at the Lightning pubkey by acting as a
visitor. So can anyone who holds the link, and they already know it. A link
meant for strangers should therefore use a relay its owner runs, or reach the
relay through Tor, where the relay learns no address worth having.

What a relay cannot prevent: whoever holds a link can open connections to it,
and each one takes a standby until the host's BOLT 8 handshake deadline drops
it. The relay's per-address limits and the host's own inbound limits bound
that; they do not remove it. It is the same exposure as a public TCP listener.

## Identifiers

- **Host key**: a secp256k1 key the host derives from its seed,
  `HKDF-SHA256(salt = 32 zero bytes, ikm = seed, info = "beignet/porch/host/v1", 32 bytes)`.
  It is not the Lightning key and is not derivable from it.
- **Link tag**: 16 bytes naming one link. The default link's tag is
  `HKDF-SHA256(salt = 32 zero bytes, ikm = seed, info = "beignet/porch/link/default/v1", 16 bytes)`;
  further links use random tags. A host has at most 256 live tags.
- **Route id**: what the visitor's URL carries,
  `base32(SHA256("porch/route/v1" || hostKey(33) || tag(16))[0..20])`,
  RFC 4648 alphabet in lower case without padding: 32 characters. Two links of
  one host share nothing a visitor can see.
- **Authority**: the relay's public name, as the host part of its URL: the
  host in lower case, followed by `:port` unless the port is the scheme's
  default (443 for `wss`, 80 for `ws`). `wss://Relay.Example:443/` and
  `wss://relay.example` are both `relay.example`.

The link is `<lightning-pubkey>@wss://<authority>/v1/p/<routeId>`. A relay is
named by scheme, host and port only; a relay URL with a path, a query or
credentials is not valid.

## Messages

Every connection is a WebSocket (RFC 6455). Control messages are **text**
messages holding one JSON object with a `t` field, sent as a single
unfragmented frame of at most 32 KiB. Payload is **binary**. A visitor never
sends or receives text. A host sends and receives text only until it is
paired. A receiver ignores fields it does not know, and closes the connection
on a message that is malformed or unexpected.

No sender puts more than 128 KiB in one WebSocket frame, or in one message
however it is split into frames: the relay copies fragments as they come, but
a host may put a message back together before it reads it, and holds a
stranger to that size. One BOLT 8 message is at most 65,569 bytes, and the
in-repo transports send each in a frame of its own.

### Host standby: `GET /v1/host`

```
relay -> host   {"t":"challenge","v":1,"nonce":"<64 hex>","authority":"relay.example"}
host  -> relay  {"t":"register","v":1,"key":"<66 hex>","tags":["<32 hex>",...],
                 "sig":"<128 hex>","token":"<optional>"}
relay -> host   {"t":"ready"}
```

- `authority` is one of the names the relay was configured with, never a
  value taken from the request. A relay with several names (a clearnet name
  and an onion address, say) uses the request's `Host` header only to choose
  among them, and the first when it matches none. The host refuses a
  challenge whose authority is not the one in the URL it dialed.
- `sig` is a compact ECDSA signature (r, then s, low s) by the host key over

  ```
  SHA256("porch/register/v1" || nonce(32) || len(authority)(1) || authority || SHA256(tag_1 || ... || tag_n))
  ```

  with the tags in ascending byte order. The nonce stops a replay. The
  authority stops one relay from registering the host at another.

- `tags` is the full list of links this standby serves: 1 to 256 distinct
  values, ascending. The relay derives each tag's route id.
- `token` is present when the relay requires one (a private relay). It is at
  most 256 bytes and is not covered by the signature.
- `v` is the protocol version, 1.

A standby serves **one** circuit. The host keeps a small number of standbys
open and opens a replacement when one is paired or lost, at a bounded rate so
a flood of visitors cannot make it dial without bound.

The host in this repository keeps 2 standbys at each relay unless told
otherwise (at most 8). It may open 4 connections in a burst and one more
every 2 seconds after that. A connection that fails is retried after 1
second, doubling up to a minute, and after 5 minutes when the relay refused
the registration itself (close code 1008), since a wrong token or too many
links will not come right by asking again. A relay that lets a registered
standby go is redialed at once, within the same allowance.

While a standby is idle the relay sends `{"t":"ping"}` about every 20 seconds
and the host answers `{"t":"pong"}`. The relay drops a standby that leaves two
unanswered. The host replaces a standby that has heard nothing for 60 seconds.
An idle standby sends nothing but `pong`.

### Visitor: `GET /v1/p/<routeId>`

The relay looks for an idle standby whose registration lists a tag with that
route id, oldest first.

- Found: the standby leaves the idle set, the relay sends the host
  `{"t":"paired","tag":"<32 hex>"}`, and from then on copies binary frames in
  both directions, fragment by fragment. The host treats the bytes after
  `paired` as the start of a BOLT 8 handshake in which it is the responder.
- Not found: the relay holds the visitor for up to 3 seconds in case a
  replacement standby is on its way, then closes with 1013.

Binary frames a visitor sends before it is paired are held, up to 64 KiB, and
delivered after `paired` in the order they came.

After pairing there are no control messages. A text message from a visitor at
any time, or from a paired host, closes the connection with 1003. When either
side closes or is lost, the relay closes the other: with the same code when it
was 1000 or in 3000 to 4999, with 1001 otherwise. The relay answers WebSocket
pings itself and does not pass them on.

### Close codes

| Code | From the relay it means                                                                                                                                     |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1001 | the other side of the circuit went away; a standby was replaced, went unanswered, or its circuit sat idle                                                   |
| 1002 | a frame or control message out of place                                                                                                                     |
| 1003 | text where only binary is allowed                                                                                                                           |
| 1008 | the registration is refused, and the same one will be refused again: bad signature, wrong relay name, bad token, too many links, or no registration in time |
| 1009 | a frame over the size limit, or more held for an unpaired visitor than the relay holds                                                                      |
| 1013 | nothing is wrong with the request, but there is no standby or no room for it now                                                                            |

An upgrade the relay does not accept is answered in HTTP: 404 for a path it
does not serve or a malformed route id, 429 when the source address is at one
of its limits.

### Revoking a link

The host drops the tag from its list, closes its idle standbys and opens new
ones with the shorter list, and closes any circuit that was paired under that
tag. The relay keeps no list of its own: a route exists exactly while an idle
standby lists it.

## Relay limits

All configurable. The defaults suit a small public relay.

| Limit                                                                 | Default |
| --------------------------------------------------------------------- | ------- |
| Idle standbys per host key; a further one replaces the oldest         | 8       |
| Open circuits per host key                                            | 64      |
| Tags per registration                                                 | 256     |
| Host keys with a standby or a circuit                                 | 1,024   |
| Visitors per source address, waiting or paired                        | 16      |
| Connections per source address not yet registered or paired           | 32      |
| Idle standbys per source address, whatever keys they registered       | 16      |
| Upgrades one source address may start in a minute, as host or visitor | 120     |
| Sockets in total                                                      | 4,096   |
| Time to register after the challenge                                  | 10 s    |
| Time a visitor is held for a standby                                  | 3 s     |
| Frame size                                                            | 128 KiB |
| Bytes held for an unpaired visitor                                    | 64 KiB  |
| Unsent bytes queued toward a slow side before the other is paused     | 256 KiB |
| Circuit with no bytes in either direction                             | 10 min  |

A circuit can make the relay hold about the queue limit in each direction, so
512 KiB with these defaults, and 4,096 sockets can pin about 1 GiB between
them. Lower the socket limit on a smaller machine.

A source address is counted the way the node counts inbound peers: a public
IPv4 address by itself, IPv6 by its /64, private and loopback addresses not at
all. Behind a reverse proxy the relay reads the client address from
`X-Forwarded-For` only when told which proxy to trust, and then takes the
right-most entry that is not a trusted proxy.

## Test vectors

Seed: the 64 bytes `00 01 02 ... 3f`.

|                                        |                                                                      |
| -------------------------------------- | -------------------------------------------------------------------- |
| Host secret                            | `21ce437d6976c0d44a33bf9420f9fc120fb34c1faa823826a43f9ae6ddacd01d`   |
| Host key                               | `028e05ee420254452db894ac055e819662eb6546f80054ee6f54f37fa9eadc6aa4` |
| Default link tag                       | `de536d1efe0d10a770774b67b5b9fe4d`                                   |
| Route id of the default link           | `3v465neydi7h3siyohv7auvakelndu37`                                   |
| Route id of tag `abab...ab` (16 bytes) | `a2a6afyvl6pnykc7eqno5ny2aye3waud`                                   |

Registration with nonce `11` repeated 32 times, authority `relay.example` and
the two tags above (ascending: `abab...ab`, then the default tag):

|                                |                                                                                                                                    |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Signed digest                  | `b556dfbed6a42a764b637f73287b9c9e83d55be6a81a680dce661a5e8dd3590d`                                                                 |
| One valid signature (RFC 6979) | `e12a7920e9b1e7a8e4341713a64d6032af3e88d1d5b4811405f91f8dc641816114bf934713054309de62f3bf08d415cf68d83ea49b1e28b7e49371283dde7f15` |

`tests/lightning/porch-protocol.test.ts` checks these.

## Not in version 1

- A separate dial address for the host (an onion address for a relay that is
  also public) beyond the relay answering to more than one name.
- Relay discovery, payment for relaying, or relay federation.
- Hiding the route id from the relay.
