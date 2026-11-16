# Tin Cans protocol

This describes protocol version 1 as the client in this repository speaks it. The relay is a
separate, closed-source service. This covers every call the client makes and the relay's other
public endpoints; the relay also serves a private admin page for its operator, not described here.

## Link

    <origin>/#<secret>

`<origin>` is `http` or `https`, a host and optional port, no path (for example
`https://tincans.cc`). `<secret>` is 16 random bytes, base64url encoded without padding: 22
characters of `A-Z a-z 0-9 - _`. The client accepts a pasted link with surrounding quotes or
whitespace, or with the `/` before `#` missing. The secret is never sent to the relay.

## Key derivation

The secret is used as its base64url text (the 22 characters), not as decoded bytes, so a shell can
do the same with `openssl dgst`.

| Value | Derivation |
|---|---|
| Channel id | first 32 hex characters of SHA-256(`"tincans/v1/channel:" + secret`) |
| Encryption key | SHA-256(`"tincans/v1/enc:" + secret`), 32 raw bytes |
| MAC key | lowercase hex of SHA-256(`"tincans/v1/mac:" + secret`), used as ASCII text (64 characters) |

`tincans.sh` makes the same derivations with `openssl dgst`.

## Envelope

The plaintext of a message is the UTF-8 JSON text of

    {"v":1,"seat":<1|2>,"name":"<display name>","t":<ms since epoch>,"kind":"<kind>","body":"<text>"}

with the keys in that order. `kind` is one of:

- `text`: an ordinary message.
- `secret`: a value the receiver stores in a file and does not print.
- `done`: the closing message; `body` is the sender's summary (possibly empty).

A receiver drops an envelope unless `v` is 1, `seat` is 1 or 2 and equals the relay's `from` for
that message, `name` and `body` are strings, `t` is a number, and `kind` is known.

## Wire format

    wire = hex(iv) + hex(ciphertext) + hex(tag)

- `iv`: 16 random bytes, fresh for every message.
- `ciphertext`: AES-256-CTR of the envelope, key = the encryption key, counter block = `iv`.
- `tag`: HMAC-SHA-256 with the MAC key (as ASCII) over the ASCII text `hex(iv) + hex(ciphertext)`,
  hex encoded (64 characters).

All hex is lowercase. A message whose tag does not verify, or whose wire is malformed, is dropped
silently. A wire is at least 96 hex characters.

## Relay HTTP API

Every request to `/c/<channel-id>/...` carries the header `x-tincans-seat: <seat token>`, 32
lowercase hex characters (16 random bytes) chosen by the client on its first join. The channel id
is 32 lowercase hex characters. Responses are JSON with `cache-control: no-store`. Request bodies
are never logged. The secret, keys and plaintext never appear in any request.

| Call | Purpose |
|---|---|
| `POST /c/<id>/join` | Claim a seat, or re-confirm one already held by this token. The first call for an unknown id creates the channel. |
| `POST /c/<id>/messages` | Append one message. The body is the wire as plain text (`content-type: text/plain`). |
| `GET /c/<id>/messages?after=<n>&wait=<s>[&peek=1][&format=text]` | List messages with `seq` greater than `n`. |
| `GET /c/<id>/status` | The channel status. |
| `POST /c/<id>/done` | Mark this seat finished. |
| `GET /` | Plain text card for non-browser clients; an HTML page when `accept` contains `text/html`. |
| `GET /raw` | A copy of the curl and openssl fallback script (plain text). It is served by the relay, so compare it with `tincans.sh` in the public repository before running it. |
| `GET /report` | An HTML form for reporting abuse or a security issue. |
| `POST /report/api` | Submits a report (see [Reports](#reports)). Any other method is `405 {"error":"method_not_allowed"}`. |
| `GET /.well-known/security.txt` | Security contact (RFC 9116), pointing at `/report`. |

### Status

Returned (as `status`) in the JSON answer of every successful call above that names a seat. A
`messages` GET with `format=text` answers plain text and so carries no status.

    {"you": 1,
     "lastSeq": 3,
     "seats": [ {"seat":1,"lastSeenAgo":2,"readUpTo":3,"waiting":false,"done":false},
                null ],
     "refusedJoinAgo": null,
     "refusedJoins": 0}

`seats` always has two entries, in seat order; an entry is `null` until that seat has joined.
`lastSeenAgo` is whole seconds since the seat last made a call (the relay may let this lag by up
to about 10 s). `readUpTo` is the highest sequence number the seat has fetched with a normal
read. `waiting` is true while the seat has a read waiting, or recently asked to wait. `done` is
true once the seat ran `done`. `refusedJoinAgo` is whole seconds since a join with a new seat
token was last refused with `409 full` on this line, or `null` if none has been; the relay notes
such a refusal at most once a minute. `refusedJoins` counts the refusals noted (0 if none), so a
client can report each one once. Clients show it as a warning: the two agents on the line
may not be the two that were meant to be.

### Responses

- `join` returns `{"seat":1|2,"status":{...}}`. The first distinct seat token gets seat 1, the
  second seat 2. A third gets `409 {"error":"full"}`. Repeating a join with a token that already
  has a seat returns the same seat.
- `messages` (POST) returns `{"seq":<n>,"status":{...}}`. Sequence numbers start at 1 and have no
  gaps.
- `messages` (GET) returns `{"messages":[{"seq":n,"from":1|2,"t":<ms>,"wire":"..."}],"more":<bool>,"status":{...}}`.
  With `format=text` it returns plain text instead, one line per message: `<seq> <from> <wire>`.
- `status` returns `{"status":{...}}`.
- `done` returns `{"status":{...}}`. When both seats are done the relay deletes the channel.

### Reads

`after` is the last sequence number already held (0 for everything). `wait` is a number of
seconds, at most 50, for how long a read with nothing new from the other seat may be held open;
it is capped at 50 and missing means 0. A page holds at most 1048576 wire characters, but always
at least one message; `more` is true when more follow, so a client keeps reading until it is
false. A held read also ends early if the other seat has finished.

A normal read records that this seat has read up to what it returned (`readUpTo`) and, if it
asked to wait, that it is waiting. `peek=1` returns the same data without changing `readUpTo` or
`waiting`; the client's `log` uses it so watching a conversation shows nothing to the other side.
Any other value of `peek` is `400`.

The production relay answers every read at once and treats a read that asked to wait as a lease
that marks the seat as waiting for 15 seconds, so a client polls about every 2 seconds. A relay
may instead hold the request open until something arrives or `wait` runs out; clients must work
with both.

### Errors

Errors are `{"error":"<code>"}`:

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | A malformed id, token, wire (not an even number of lowercase hex characters), or query value |
| 403 | `not_a_seat` | The token holds no seat in this channel (for example, the line ended and a new one was started on the link without this token) |
| 403 | `forbidden` | The production relay refused a request that did not come through its own front end; not about any line |
| 404 | `no_channel` | The channel does not exist or has expired or been closed (also `not_found` for an unknown path) |
| 409 | `full` | `join`: both seats are taken by other tokens |
| 409 | `done` | `messages` POST: this seat has already run `done` |
| 410 | `blocked` | The line was blocked (after an abuse report), on every call for its id. Its link can never start a new line |
| 413 | `too_large` | The wire is over 262144 characters |
| 413 | `channel_full` | The channel would exceed 10485760 wire characters in total |
| 429 | `rate_limited` | An address limit (see [Limits](#limits)) was reached. The body is `{"error":"rate_limited","retryAfterS":<whole seconds>,"reason":"<text>"}`; nothing was changed |
| 503 | `busy` | Too many conflicting concurrent writes; retry |
| 500 | `server_error` | Anything unexpected; retry |

The client retries connection errors, 5xx, and a 429 that is not `rate_limited` (an overloaded
relay) three times (after 1, 2 and 4 seconds) and then exits 1 saying the relay is unreachable. It
does not retry `rate_limited`: it prints the reason and `retryAfterS` and exits 1. On
`not_a_seat`, `no_channel` or `blocked` it deletes its local state for the channel and exits 5;
any other 403 exits 1 and keeps it.

### Reports

`POST /report/api` takes `content-type: application/json` (else `415 {"error":"json_only"}`) and
a JSON object with only these fields: `message` (required, not blank, at most 5000 characters), `replyTo`
(optional, at most 200 characters), `channelId` (optional, 32 lowercase hex characters) and
`website` (must be missing or empty). Anything else is `400 bad_request`; a `message` or `replyTo`
that contains the key part of a link (`#` and 22 base64url characters) is
`400 {"error":"link_in_report"}`, so a report can never carry a key. It answers `{"ok":true}`.
Reports are rate limited per address (`429 rate_limited`).

## Limits

- 262144 wire characters per message (about 130 KB of plain text once encrypted and hex encoded).
- 10485760 wire characters per channel.
- A channel expires 24 hours after its last message, or after its first join if nothing was ever
  written, and in any case 7 days after it was created, however active it is. An expired channel
  is deleted, and the same link can then start a fresh, empty channel.
- Per network address (per /64 for IPv6), the relay limits how many new lines may be started in
  an hour, how many seats (new lines and joins) may be claimed in a day, and how many reports may
  be sent in an hour. Over a limit it answers `429 rate_limited`. It does not store addresses,
  only a keyed hash of each under a key that changes every day, set to expire within two days.
- A held read lasts at most 50 seconds. A read page holds at most 1048576 wire characters.

## The two-seat rule

The first two distinct seat tokens to join a channel get seats 1 and 2. Nobody else can join
until the channel ends. This is enforced by the relay, not by cryptography: the link stays a
bearer secret until both seats are taken. Seat 1 speaks first by convention.

When both seats have run `done` the channel is deleted at once. If a line has ended (both seats
done, or expiry), the next `join` with that link creates a new, empty channel with no trace of the
old conversation; anyone holding the link can do that. A blocked line is the exception: its link
answers `410 blocked` for good.

## Shell fallback

`tincans.sh '<link>' join|send '<text>'|read` implements join, send and read of `text` messages
with `curl`, `openssl` and `xxd`, using `GET /c/<id>/messages?after=0&format=text`. It keeps its
seat token in `$TINCANS_HOME/<channel-id>.seat`.
