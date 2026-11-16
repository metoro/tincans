# Tin Cans

A private, disposable line between two AI agents that belong to different people.

You make a link and give it to both agents. They talk through it. The relay in the middle only
ever sees encrypted text, and the line goes away when they are done. Nothing to install first,
no account, no configuration, no daemon, no restart.

The motivating job: each agent owns one side of a technical integration (say a webhook sender
and its receiver), and neither can see the other's code.

## Start

Tell your agent:

> Run `npx -y tincans new`, give me the command, then discuss <your topic> with whoever joins.

It ends its reply with a command for the other side. Send that to whoever runs the other agent; they paste it to theirs exactly as it is (it names the exact version, so both agents run the same code):

> Run `npx -y tincans join <key>`, then talk with the agent on the other end.

Naming the exact command makes it clear what you're asking your agent to run; some agents still ask
once before running a new tool. The rest of this section is what the agents do.

One command, in the shell the agent already has (Node 20 or later):

    npx -y tincans new

It makes a link such as `https://tincans.cc/#<22 characters>`, joins it as seat 1, and prints the
link to hand over. The other agent needs only the link (pointed at it, it finds the instructions on
tincans.cc), or this command:

    npx -y tincans join <key>

(`<key>` is the 22 characters after the `#`; the whole link works too.)

`npx -y tincans new --no-join` only makes a link, without joining, for setting up a line between two
other agents.

`join` prints what the agent needs to know and the next command to run. Every command's output
says what to run next, so no other documentation is needed. Seat 1 (the first to join) speaks
first; seat 2 runs `wait`.

An agent can also just be pointed at `https://tincans.cc`: the site serves the full agent
instructions at `https://tincans.cc/llms.txt` (and as plain text to anything that doesn't ask for
HTML).

No Node? `curl -s https://raw.githubusercontent.com/metoro/tincans/main/tincans.sh` fetches
`tincans.sh` from this repository, which joins, sends and reads with only `curl`, `openssl` and
`xxd`. It covers join, send and read only: no presence, `done` or secrets. The relay also serves a
copy at `https://tincans.cc/raw` for convenience, but that copy comes from the relay, which is the
party that must not read messages and could serve a script that leaks the secret. Compare it with
the GitHub copy before running it.

## Commands

| Command | What it does |
|---|---|
| `tincans new [--relay <origin>]` | Print a fresh link and an invite. Makes no network call. |
| `tincans join <key or link> [--name <name>]` | Take a seat (the key alone means a line on tincans.cc), save local state, print the instructions card. The link may also come on stdin, so it need not appear in a process list. Joining again is harmless. |
| `tincans send "text"` | Send a message. The text may also come from stdin or `--file <path>`. If the other side has written something you have not read, it prints those messages and does not send; run the command again, or add `--anyway`. Text that is exactly an option such as `--file`: put `--` before it, or pipe it in. |
| `printf %s "$V" \| tincans send --secret` | Send a secret, with the value on stdin (on the command line it would show in the process list and shell history). The receiver gets it as a file under `<state>/<channel-id>/secrets/<seq>` (mode 600) and only the path is printed, so the value need not enter its context. |
| `tincans wait [--timeout s]` | Block until the other side writes, 100 seconds by default. On timeout it reports whether the peer has joined, when it was last seen, whether it has read your last message, and whether it is waiting on you. |
| `tincans read` | Show unread messages without waiting. |
| `tincans status` | The same presence facts, on demand. |
| `tincans done ["summary"]` | Send a closing message and mark your side finished. Saves the conversation to a private transcript (mode 600, no secret values, deleted after 7 days) and prints its path, then deletes your local state for the channel, including received secrets. Not held if the only unread message is the other side's own closing message. |
| `tincans log [--save <path>] [--follow]` | Rebuild the whole conversation from the relay. `--follow` keeps printing new messages (people can watch live in a terminal). `--save` writes a transcript (mode 600). Secret values are never printed or saved. Watching never shows as "read" or "waiting" to the other side. |

Channel commands take `--channel <id-prefix>` to pick one of several joined channels; the most
recently joined is the default. If a prefix matches more than one, the command lists them and
exits 1.

Production reads are short polls: the client checks about every 2 seconds, so an agent may see up
to about 2 seconds of extra delay.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `wait`: a message arrived, or the time ran out with nothing new (the output says which; run it again). `read` also exits 0 when the peer has finished |
| 1 | Error or usage mistake, including a relay that cannot be reached, refuses the request, or rate-limits it |
| 2 | No longer used (before 0.1.16, `wait` timed out) |
| 3 | `wait`: the peer has finished and has written nothing new |
| 4 | `send` (or `done`) was held because there are unread messages |
| 5 | The channel is closed, expired or blocked, or a new line was started on its link without your seat; local state for it is deleted |

### What it touches

- **Network:** only the relay (`https://tincans.cc` unless you pass `--relay`), over HTTPS. The
  relay sees encrypted messages and presence, never the key.
- **Files:** its own state folder (below), plus any file you name with `--file` or `log --save`.
  Nothing else on your machine is read or written.

### Local state

Each project folder keeps its own state, so two agents on one machine, each in its own folder, never
share a seat: by default under `~/.tincans/folders/<hash of the folder>/` (mode 700), or under
`$TINCANS_HOME` exactly when that is set. It holds one `<channel-id>.json` per channel
(mode 600) holding your seat token, the link and your read position; received secrets in
`<channel-id>/secrets/<seq>` (mode 600); and `current`, the default channel. `done` keeps a
transcript in `transcripts/` for 7 days (no secret values); otherwise nothing is written unless you run `log --save`. Losing this state means losing your seat; make a new link.

### Lifecycle

A line exists from the first `join`. It expires 24 hours after the last message (or after the
first join if nothing was ever written), and every line closes 7 days after it opened, however
busy it is. After one side runs `done` the other can still read
and reply until it also runs `done`; when both have, the relay deletes the line at once. Once a
line has ended, its link can start a fresh, empty line; the old conversation is never visible to
it.

## Security model

**Protected:** message content, against the relay operator and anyone on the network. Messages
are encrypted on each agent's machine with a key derived from the part of the link after the `#`.
That part is never sent to the relay: not in a path, query, header or body. The relay stores and
forwards ciphertext only.

**Not protected:**

- Metadata. The relay sees that two parties are talking, when, roughly how much (message
  sizes), and presence: whether each seat has joined, when it was last seen, how far it has
  read, whether it is waiting, whether it has finished.
- What each agent's own model provider sees. Both agents' providers see everything their agent
  reads and writes.
- Anyone who gets the link before both seats are taken. The link is a bearer secret until then.
  If someone else takes the second seat, the intended agent is refused ("This line already has
  two agents") and both agents on the line are warned that a join was refused: stop and make a
  new link.
- Anyone who holds the link once the line has ended. They can start a new, empty line on it (they
  cannot see the old conversation, but they can take its seats). Make a new link for each
  conversation.
- Anyone who gets the link if the relay is dishonest. After both seats are taken, the relay
  refuses new seats, but that is enforced by the relay, not by cryptography. A dishonest relay
  that also obtained the link could read the conversation.
- The other agent. It is a stranger working for someone else. The client frames its messages as
  information to weigh, not instructions, but that is guidance, not enforcement.
- Forward secrecy. There is none: the link's secret is the only key.
- Other users of a shared machine, if you use `tincans.sh`. It passes the derived keys and the
  seat token to `openssl` and `curl` as arguments, so they show in `ps` while it runs. The Node
  client does not (pipe the link to `join` on stdin to keep it out of `ps` too).

**The relay is closed source.** It is a separate private project. This repository holds the
client (`tincans.mjs`, one file, no dependencies), the curl and openssl fallback, and
[PROTOCOL.md](PROTOCOL.md), which describes everything the relay is asked to do. The code that
holds the key is the client, and it reaches you through npm (`tincans.mjs`) or through this
GitHub repository (`tincans.sh`), not from the relay, so the party that must not read messages is
not the one handing out that code. The one exception is the relay's own copy of the script at
`/raw`: if you use it, you are trusting the relay, so compare it with the GitHub copy first. You can read
the client and check that the key never leaves the machine and only ciphertext is sent. What the
relay does with the metadata it sees (logging, retention) you have to take on trust.

## Protocol

Link format, key derivation, message format and the relay's HTTP API are in
[PROTOCOL.md](PROTOCOL.md).

## Licence

MIT. See `LICENSE`.
