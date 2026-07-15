# Hermes gateway integration (optional, advanced)

If you run a [Hermes](https://github.com/NousResearch/hermes-agent)-style
local agent gateway with a
Discord adapter, this project can wire its intake/routing lane into your
gateway **without shipping raw patches against your private tree**. Instead,
`integrations/hermes/render_overlay.py` renders hook modules and small
insertion snippets from templates, substituting *your* validated local
configuration, then applies them to *your* checkout with a clean applicability
check, backup, rollback, and fail-closed drift detection.

## Why not a patch file

A raw patch encodes one specific tree's line numbers, paths, and IDs. That
leaks private infrastructure details and breaks on any upstream change. The
overlay approach keeps your IDs on your machine (in a gitignored lockfile),
verifies the exact target files before touching them, and refuses to apply if
anything has drifted.

## Compatible versions

Anchors are matched against your gateway source. Before first use, verify the
anchors resolve uniquely on your checkout and record the exact commit/tag in
`integrations/hermes/overlay_manifest.json` under `compatible_hermes`. After
**any** gateway update, re-run `verify`, and if it reports drift, re-run
`render` + `apply` and the full gateway test battery before going live again.

## Workflow

```bash
cd integrations/hermes

# 1. Render hooks + snippets from your receptionist config (no gateway edits).
python3 render_overlay.py render \
  --hermes-root /path/to/your/hermes \
  --receptionist-config ~/.local/state/ai-receptionist/config.json

# 2. Inspect what would change.
python3 render_overlay.py verify --hermes-root /path/to/your/hermes

# 3. Apply (backs up each target, inserts marked blocks, fails closed on drift).
python3 render_overlay.py apply --hermes-root /path/to/your/hermes

# 4. Run YOUR gateway's test battery, then restart the gateway.

# Rollback at any time (restores the most recent backup byte-for-byte):
python3 render_overlay.py rollback --hermes-root /path/to/your/hermes
```

## Guarantees

- `render` validates every substitution (channel IDs numeric, endpoints
  local, state dir set) and records target file hashes in `overlay.lock.json`.
  It never modifies gateway files.
- `apply` re-checks each target hash against the lock, requires the anchor to
  appear exactly once, refuses if an overlay marker already exists, and stages
  all targets before writing any — a precondition failure on the second
  target leaves the first untouched.
- Inserted blocks are delimited by `# --- receptionist-overlay:<name>:begin/end`
  markers and are valid Python (checked by the overlay tests).
- The rendered hooks are themselves fail-closed: an intake command candidate
  never reaches the LLM even if the hook errors; forged/invalid route
  envelopes fall back to your gateway's legacy delivery; callback bodies are
  HMAC-verified.

## What gets wired

- A Discord `on_message` snippet that treats an owner reply-with-mention in
  the intake channel as a deterministic command candidate and forwards it to
  the receptionist (never to the model). It also intercepts exact
  `reply <message>` syntax in threads before the model and forwards the raw
  owner/guild/thread/parent fields to `/discord/contact-reply`; the isolated
  receptionist performs every authorization and transport check.
- A webhook-delivery snippet that honors the receptionist's additive `route`
  envelope (intake vs category channel + stable thread) and falls back to your
  legacy delivery on any missing/invalid/forged route.

Keep the rendered files and lockfile out of version control — they contain
your local IDs. The repo's `.gitignore` already excludes
`integrations/hermes/rendered/` and `overlay.lock.json`.
