# opti-auth-api

Users, sign-in and RS256 tokens. The identity of the whole platform.

Part of the OptiView distributed system (team `opti`). Governance and documentation live in
[`opti-docs`](https://github.com/code-corhuila/opti-docs).

## Architecture

Hexagonal, in three Maven modules so the rule is enforced by the compiler:

| Module | Contents | Depends on |
|---|---|---|
| `auth-core` | domain, ports, use cases. **No framework dependency** | nothing |
| `auth-adapters` | HTTP inbound adapter, PostgreSQL outbound adapter | core |
| `auth-app` | composition root: wires everything and declares every limit (`application.yml`) | adapters |

The database schema is **not** here: it lives in [`opti-auth-db`](https://github.com/code-corhuila/opti-auth-db).
Other domains are reached only through their published API, never through their database.

## Public contract

Base path `/api/v1`. JSON in `camelCase`, UUID ids, money in cents, dates RFC 3339 UTC. Every
error uses `{"error", "message", "details"?, "traceId"}`. Full specification: [`openapi/openapi.yaml`](openapi/openapi.yaml).

| Method and path | Roles | Answers |
|---|---|---|
| `POST /api/v1/auth/login` | none (public) | `200` with the access token; always the same 401 on any failure |
| `GET /api/v1/auth/me` | any user token | the signed-in person |
| `POST /api/v1/auth/change-password` | any user token | `204` |
| `POST /api/v1/auth/service-tokens` | ADMIN | a long-lived SERVICE token for the worker or the workflow |
| `POST /api/v1/users` | ADMIN | `201`/`200` |
| `GET /api/v1/users` / `/{id}` | ADMIN | list (filters `q`, `role`, `active`) / detail |
| `POST /api/v1/users/{id}/activate` `/deactivate` | ADMIN | never your own user |
| `GET /health` | none | `200` |

Cross-cutting rules (numeral 5.3): the JWT (RS256) is validated by this service, creations require
`Idempotency-Key` (8-128 chars), listings are paginated (`page` from 1, `limit` 1-100, default 20,
newest first) and every response carries `X-Correlation-Id`, also written in each JSON log line.

## Run

The whole platform is started from `opti-infra` (see its README). To work on this service alone:

```bash
cp .env.example .env            # fill in the values
mvn -B verify                   # unit + HTTP tests (+ persistence tests if TEST_DATABASE_URL is set)
docker compose --env-file .env -f deploy/compose.yml build
```

Configuration (all from the environment, see `.env.example`): `DATABASE_URL`, `DATABASE_USER`,
`DATABASE_PASSWORD`, `JWT_PUBLIC_KEY` or `JWT_PUBLIC_KEY_FILE`.

## Explicit limits (numeral 5.3.10)

Declared in `auth-app/src/main/resources/application.yml`: header/read timeout 5 s, idle keep-alive
60 s, connection pool 10, wait for a connection 5 s, statement timeout 5 s, graceful shutdown 20 s.

## Depends on

`opti-auth-db` (its own PostgreSQL instance) and the public key of the identity service.
