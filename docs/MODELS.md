# Local model configuration

Tier 2 can use a local model to *word* replies and to classify images. Both
are optional and both are **local-only by design**.

## What the model is and isn't allowed to do

- It receives: the category policy prompt, the last N bounded conversation
  turns, and the quoted (untrusted) contact message. That's all.
- It never receives a `tools` field, secrets, owner state, or raw identity.
- Its output is redacted (secret-shaped strings removed), whitespace-
  collapsed, hard-capped, and relayed to you. It can never change trust state.
- If the endpoint is unset or unreachable, Tier 2 falls back to bounded
  per-category deterministic replies. Vision outages fail closed (see below).

## Local-only enforcement

`config.py` and `LocalModelClient` both enforce:

- **Loopback** (`127.0.0.0/8`, `localhost`) is always allowed.
- **Private LAN** (RFC 1918) is allowed only with `"allow_private_lan": true`
  on that endpoint block — an explicit, auditable opt-in.
- **Globally routable** hosts are refused in code, regardless of config.
- **Hostnames** are refused (no DNS): use an IP or `localhost`, so a config
  edit cannot silently repoint traffic through name resolution.

No external AI provider, no API key, no telemetry.

## Example (Ollama on the same host)

```json
"tier2": {
  "model":  { "base_url": "http://127.0.0.1:11434", "model": "your-text-model",
              "num_ctx": 8192, "timeout_seconds": 45, "allow_private_lan": false },
  "vision": { "base_url": "http://127.0.0.1:11434", "model": "your-vision-model",
              "timeout_seconds": 90, "allow_private_lan": false }
}
```

The client uses Ollama's native `/api/chat` with `options.num_ctx`, so the
context ceiling is enforced server-side as well as by client-side truncation.
`think:false` is set so a "thinking" model does not spend its whole output
budget on hidden reasoning and return empty content.

## Vision / image classification

The image pipeline is **fail-closed**: with no vision endpoint configured,
nothing is downloaded or retained. With one configured, a classifier error,
timeout, or empty result deletes the sanitized copy and escalates; an image is
retained only after an explicit non-sensitive classification. See
`THREAT-MODEL.md` for the full contract. Clearing `tier2.vision.base_url`
disables image retention entirely.

## Sizing note

If you run text and vision on one GPU, configure the server to load one model
at a time (e.g. Ollama `OLLAMA_MAX_LOADED_MODELS=1`) so they swap rather than
co-reside. Pick model sizes that fit your VRAM alongside anything else
resident.
