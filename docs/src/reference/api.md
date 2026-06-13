# REST API v1

Interactive docs: **`/swagger-ui`**.
OpenAPI JSON: **`/api/v1/openapi.json`**.

## Endpoints (Faz 4)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET    | `/api/v1/health`            | none    | Service health |
| GET    | `/api/v1/interfaces`        | session | List interfaces |
| GET    | `/api/v1/interfaces/{id}`   | session | Single interface |
| GET    | `/api/v1/peers`             | session | List peers |
| GET    | `/api/v1/peers/{id}`        | session | Single peer |

## Real-time

`GET /ws/events` (WebSocket, auth required) streams JSON heartbeats and (in
later phases) peer handshake and traffic delta events.
