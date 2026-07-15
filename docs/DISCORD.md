# Discord intake approvals and category routing (optional)

Mirror new Tier-1 contacts into a private Discord intake channel, approve a
standing or temporary promotion by replying to a genuine alert with an exact
command, route promoted contacts' mirrored messages into per-category channels
and stable per-lead threads, and send one explicitly reviewed reply from the
bound thread.

## You use your own local bot

This integration uses a Discord bot **you already run locally**. It never
installs, connects, or depends on an external/hosted bot or connector service.
Your bot is a thin transport: it posts what the receptionist decides and
forwards your intake replies back. Every request between the bot and the
receptionist is HMAC-signed with `discord_hook_secret`.

## Set up channels (you, with your bot)

Create private channels in your server: an intake channel and one channel per
category you use (`family`, `client`, `vendor`). Give view access only to
yourself and your bot (deny `@everyone`). Note the numeric IDs.

## Configure

```json
"discord": {
  "enabled": true,
  "guild_id": "<your guild id>",
  "owner_user_id": "<your user id>",
  "bot_user_id": "<your bot's user id>",
  "intake_channel_id": "<intake channel id>",
  "category_channels": { "family": "<id>", "client": "<id>", "vendor": "<id>" },
  "pending_alert_ttl_seconds": 3600
}
```

All IDs must be numeric snowflakes; the config validator rejects anything else.

## Exact intake commands (reply to the alert, @mention your bot)

| Reply | Effect |
|---|---|
| `@bot approve family` | Lead → **standing** Tier-2 family (no automatic expiry) |
| `@bot approve client` | Lead → **standing** Tier-2 client |
| `@bot approve vendor` | Lead → **standing** Tier-2 vendor |
| `@bot approve family test` | Lead → temporary `tier2-test` family (24h inactivity TTL) |
| `@bot approve client test` | Temporary `tier2-test` client |
| `@bot approve vendor test` | Temporary `tier2-test` vendor |
| `@bot tier1` | Downgrade the correlated lead to Tier 1 |
| `@bot block` | Block the correlated lead |

- Plain approvals are standing. Only the exact trailing word `test` requests
  the temporary cohort. `unblock` is not exposed through Discord — use your
  Tier-3 line for that.
- Everything else fails closed and changes nothing: another user, another
  channel, a DM/group, a missing @mention, no reply reference, a
  forged/copied/cross-channel/deleted/resolved reference, ordinary prose,
  `approve all`, a bare `approve`, extra words, or a replayed command.
- Each alert resolves exactly once; a replayed command message is inert; an
  authorized command that can't complete (e.g. cohort full) re-opens the alert
  for retry.

## Boundaries (do not weaken)

- **No model ever sees an intake command** — even if the gateway hook is
  broken, a command candidate fails closed and posts a "not processed" notice
  rather than reaching an LLM.
- **Ordinary category-thread discussion remains internal.** The only
  Discord→contact path is an exact `reply <message>` in the lead's bound
  thread, from the configured owner, in the configured guild and correct
  category parent. The contact must still be active Tier 2 with unchanged
  keyed identity and chat bindings. The router stores a digest/length, not the
  reviewed body, and never invokes a model.
- A reviewed reply is attempted once. BlueBubbles deployments read the exact
  outgoing message back from source history; a send without source read-back
  is reported `sent_unverified` and is never automatically retried.
- Thread/channel names contain only the non-identifying lead ID and category.

## Wiring the bot to the receptionist

Your bot must, on a reply-with-mention in the intake channel, POST the raw
fields to `POST /discord/intake-command` (HMAC-signed) and post the returned
`readback` into intake. After posting a mirrored alert it must POST
`/discord/alert-posted` with the real message/thread IDs so replies
correlate. It must also intercept exact `reply <message>` commands before any
LLM, POST the owner/guild/thread/parent/message fields to
`/discord/contact-reply`, and post the returned read-back in the source thread.
If you run a Hermes gateway, `docs/HERMES-INTEGRATION.md` and the
`integrations/hermes/` overlay generate these hooks for you.

## Optional second-channel owner seen-check

Set `owner_seen_check.enabled: true` to queue one delayed alert for a genuinely
new Tier-1 lead. After `delay_seconds` (default 180), the same HMAC-signed owner
relay receives `route.kind: owner_seen_check` unless any tier/block decision
has already been recorded. Your local relay adapter decides whether that route
goes to SMS, iMessage, or another owner-only channel. It never auto-approves,
contains only the lead ID/masked identity/category, and is disabled by default.
