# GeoLibre server API

Reference implementation of [`docs/server-api.md`](../../docs/server-api.md).
It is a separate multi-user service from the local desktop processing sidecar.

```bash
pip install -e ".[test]"
geolibre-server-api
```

Configuration:

- `GEOLIBRE_DATABASE_URL`: SQLAlchemy URL; defaults to
  `sqlite:///./geolibre-server-api.db`. Use
  `postgresql+psycopg://user:password@host/database` with the `postgres` extra.
- `GEOLIBRE_STORAGE_PATH`: local object directory, default `./data`.
- `GEOLIBRE_STORAGE=s3`, `GEOLIBRE_S3_BUCKET`, and optional
  `GEOLIBRE_S3_ENDPOINT` / `GEOLIBRE_S3_REGION`: S3-compatible storage (install
  the `s3` extra; standard AWS credential environment variables apply).
- `GEOLIBRE_PUBLIC_URL`: externally reachable API URL and, when OAuth is
  enabled, its canonical issuer. Production OAuth requires HTTPS. Loopback HTTP
  requires `localhost` or `127.0.0.1` plus an explicit port.
- `GEOLIBRE_VIEWER_URL`: GeoLibre viewer origin.
- `GEOLIBRE_CORS_ORIGINS`: comma-separated web origins, default `*` for
  ordinary API routes. OAuth CORS always includes registered web callback
  origins, but never inherits `*`. Register the exact browser app origin;
  self-hosted desktop calls use browser CORS, so allow `tauri://localhost`
  and/or `http://tauri.localhost` there as well. The shipped
  `https://share.geolibre.app` desktop origin uses native HTTP for
  authenticated requests instead; other hosts do not silently bypass CORS.
- `GEOLIBRE_OAUTH_CLIENTS`: JSON array of exact public-client registrations:
  ```json
  [
    {"client_id":"geolibre-web","name":"GeoLibre Web",
     "redirect_uris":["https://app.example/oauth-callback.html"],
     "scopes":["read:projects","write:projects","share:public","manage:sessions"]},
    {"client_id":"geolibre-desktop","name":"GeoLibre Desktop",
     "redirect_uris":["org.geolibre.desktop:/oauth/callback"],
     "scopes":["read:projects","write:projects","share:public","manage:sessions"]}
  ]
  ```
  Empty or unset disables OAuth without validating OAuth-only settings. Both
  clients must use their own exact redirect; the desktop callback works only
  after the URI handler is registered by an installed app. The three project
  scopes form a refreshable project grant; `manage:sessions` must be requested
  alone for a fresh, access-only, five-minute consent. Personal API tokens
  cannot carry that scope.
- `GEOLIBRE_OAUTH_CODE_TTL_SECONDS` (default `60`),
  `GEOLIBRE_OAUTH_ACCESS_TTL_SECONDS` (`600`), and
  `GEOLIBRE_OAUTH_REFRESH_TTL_SECONDS` (`2592000`): positive integer grant
  lifetimes. Refresh rotation never extends a project family's absolute expiry;
  the management grant always expires within 300 seconds and never refreshes.
- `GEOLIBRE_MAX_PROJECT_BYTES`, `GEOLIBRE_MAX_THUMBNAIL_BYTES`: upload limits.
- `GEOLIBRE_HOST`, `GEOLIBRE_PORT`: bind address and port for the
  `geolibre-server-api` entry point, default `0.0.0.0` and `8000`. Bind to
  `127.0.0.1` when a reverse proxy fronts the service.

On startup, the API adds the OAuth lookup and expiry indexes to databases
created by earlier builds as well as to fresh databases, without changing
unexpired grants or tokens. Index creation on a populated database can hold
write locks, so start one API instance during the upgrade before scaling out.

## Volume ownership

The container runs as the unprivileged `geolibre` user, and the image creates
`/data/objects` so a fresh named volume inherits that ownership. Docker applies
image ownership only to a volume it creates, so one that already holds data from
an image that ran as root stays root-owned and every upload fails with
`PermissionError`. Repair it once with

```bash
docker run --rm -v geolibre_geolibre-projects:/data/objects busybox \
  chown -R 1000:1000 /data/objects
```

## Hardening

The OAuth consent flow caps pending interactions, but general rate limiting and
a complete request-size limit are not implemented here. Keep the API behind a
rate-limiting proxy for **GET and POST** `/oauth/authorize`, `POST /oauth/token`,
`POST /api/auth/token`, and `POST /api/accounts`; the Compose API port binds to
loopback so that proxy cannot be bypassed from outside the host. See "What the
reference server leaves to the operator" in `docs/server-api.md` before public
exposure.
