# Discord intake approvals and category routing (optional)

Mirror new Tier-1 contacts into a private Discord intake channel, approve a
**temporary** promotion by replying to a genuine alert with an exact command,
and route promoted contacts' mirrored messages into per-category channels and
stable per-lead threads.

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
| `@bot approve family` | Lead → **temporary** `tier2-test` family (24h inactivity TTL) |
| `@bot approve client` | Lead → **temporary** `tier2-test` client |
| `@bot approve vendor` | Lead → **temporary** `tier2-test` vendor |
| `@bot tier1` | Downgrade the correlated lead to Tier 1 |
| `@bot block` | Block the correlated lead |

- Approvals map **only** to the temporary `tier2-test` cohort. Permanent
  promotion and `unblock` are **not** exposed through Discord — use your
  Tier-3 line for those.
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
- **Category threads are internal only.** Discussion in a category channel or
  thread never sends anything to the contact. There is no Discord→contact
  path in this project; adding one is a separate, explicitly authorized
  design.
- Thread/channel names contain only the non-identifying lead ID and category.

## Wiring the bot to the receptionist

Your bot must, on a reply-with-mention in the intake channel, POST the raw
fields to `POST /discord/intake-command` (HMAC-signed) and post the returned
`readback` into intake. After posting a mirrored alert it must POST
`/discord/alert-posted` with the real message/thread IDs so replies
correlate. If you run a Hermes gateway, `docs/HERMES-INTEGRATION.md` and the
`integrations/hermes/` overlay generate these hooks for you.
