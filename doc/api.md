# Orion Proxy — API

All endpoints require `Authorization: Bearer <jwt>` unless noted.

┌──────────────────────┬────────┬─────────────────────────────────────────────┐
│       Endpoint       │ Method │       Used for                              │
├──────────────────────┼────────┼─────────────────────────────────────────────┤
│ /v1/chat/completions │ POST   │ Chat completions + streaming (SSE)          │
├──────────────────────┼────────┼─────────────────────────────────────────────┤
│ /v1/embeddings       │ POST   │ RAG embeddings                              │
├──────────────────────┼────────┼─────────────────────────────────────────────┤
│ /v1/models           │ GET    │ Model list                                  │
├──────────────────────┼────────┼─────────────────────────────────────────────┤
│ /health              │ GET    │ Liveness probe (no auth required)           │
└──────────────────────┴────────┴─────────────────────────────────────────────┘

## Routing

- `POST /v1/embeddings` → `LLM_EMBED_BACKEND_URL`
- All other `/v1/*` → `LLM_CHAT_BACKEND_URL`

## Rate-limit response headers

Every proxied response includes:

| Header | Value |
|--------|-------|
| `ratelimit-remaining` | Requests remaining in the current minute window |
| `ratelimit-reset` | Seconds until the window resets |
