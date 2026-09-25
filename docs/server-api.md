# GeoLibre projects and identity API

This document defines version 1 of the HTTP contract used by GeoLibre's
Project Gallery and **Project → Share** flow. A compatible server may use any
implementation or storage engine. The reference implementation lives in
`backend/geolibre_server_api`.

## Conventions

- The base URL is configured with `GEOLIBRE_SHARE_URL` at container runtime
  (or `VITE_GEOLIBRE_SHARE_URL` at build time).
- JSON request and response bodies use `application/json` and camel-case keys.
- Dates are UTC ISO 8601 strings.
- Authenticated endpoints accept a personal API token or OAuth access token in
  `Authorization: Bearer <token>`.
- Error responses are JSON objects with an `error` string. `401` means a
  missing, invalid, or expired token; `403` means the authenticated principal
  lacks permission; `404` deliberately covers both a missing project and a
  project the caller may not discover; `409` is a uniqueness conflict; `422`
  is malformed input; and `429` is rate limiting.
- Servers should send `Cache-Control: public, max-age=3600` on immutable raw
  public/unlisted project versions and may use `ETag`/conditional requests.
  Responses containing private, organization, or group-protected content must
  use `Cache-Control: private, no-store`, including metadata listings.
- Cross-origin web deployments must allow `Authorization` and `Content-Type`
  from the GeoLibre web origin. On self-hosted Tauri installations using browser
  fetch, allow `tauri://localhost` and/or `http://tauri.localhost` explicitly.
  The shipped desktop HTTPS share origin uses native HTTP for authenticated
  requests; that transport does not depend on CORS.

## What the reference server leaves to the operator

Deployment protections remain the operator's responsibility:

- **Personal-token lifecycle.** Omitting `expiresInDays` preserves the v1
  delete-only lifecycle and creates a non-expiring token. Require an explicit
  1–365 day lifetime where bounded credentials are needed, and revoke or rotate
  delete-only and legacy tokens operationally.
- **Rate limiting.** The OAuth consent flow caps pending interactions per
  browser binding, but a fresh cookie bypasses that cap; the reference server
  has no general request limiter. Before enabling OAuth publicly, enforce
  per-client-IP limits at the ingress on **GET and POST** `/oauth/authorize`,
  `POST /oauth/token`, `POST /api/auth/token`, and `POST /api/accounts`.
  The last three POSTs include password or token operations; consent login
  and the PAT/account routes run scrypt. Add per-username limits where the
  ingress can safely parse credentials. Every public path to the API must go
  through this limiter: Compose binds the API host port to loopback by default.
  A root-issuer nginx deployment can put this zone in its `http` context and
  the location in its TLS issuer `server` context:

  ```nginx
  # http context
  limit_req_zone $binary_remote_addr zone=geolibre_auth:10m rate=12r/m;

  # TLS issuer server context; proxy other API routes separately.
  location ~ ^/(oauth/(authorize|token)|api/(auth/token|accounts))$ {
      limit_req zone=geolibre_auth burst=6 nodelay;
      limit_req_status 429;
      client_max_body_size 16k;
      access_log off;
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Host $http_host;
  }
  ```

  Preserve the original Host authority, including any port, or OAuth host
  binding rejects the request. Route the issuer's exact discovery URL and
  other API paths to the same backend; for a path-prefixed issuer, apply the
  limit to its externally visible prefix and strip that prefix when proxying.
  Suppress authorization request query strings, callback `Location` headers,
  and callback request query strings at the web ingress in proxy, WAF, and
  load-balancer logs.
- **A request-size limit.** The server rejects an oversized *declared*
  `Content-Length` before reading the body, but a chunked or HTTP/2 request
  declares no length and is parsed in full before the per-route limit applies.
  Cap request size at the proxy as well.

The reference implementation is a correctness baseline, not a hardened
deployment.

## Limits

| Field | Limit |
| --- | ---: |
| project title (derived from the uploaded project) | 100 Unicode code points |
| username | 3–39 lowercase ASCII letters, digits, or hyphens |
| slug | 1–100 lowercase ASCII letters, digits, or hyphens |
| description | 2,000 Unicode code points |
| tags | 20 tags, 40 Unicode code points each |
| project document | 50 MiB UTF-8 JSON |
| thumbnail | 5 MiB; PNG, JPEG, or WebP |
| `limit` | default 24, maximum 100 |

Servers may configure a smaller upload limit, but must return `413` and an
`error` explaining that limit.

## Visibility

- `public`: discoverable in the public listing and readable without auth.
- `unlisted`: omitted from public listings, but readable by anyone holding its
  URL. It appears in the owner's authenticated listing.
- `private`: an individually owned project is readable only by its owner unless
  explicitly shared with a group. An organization-owned private project is
  readable by organization administrators and by its creator while that creator
  remains an administrator, publisher, or member. Other organization members
  and viewers need an explicit group share. Raw and thumbnail URLs require the
  same Bearer token as the metadata endpoint.
- `organization`: readable by every signed-in member of the owning organization.
  It is omitted from public listings and its raw/thumbnail responses are always
  `Cache-Control: private, no-store` so removing a member revokes a known URL
  immediately after their client revalidates it.

Changing visibility affects every version immediately. A raw URL is therefore
not a capability URL for a private project.

## Identity

### `POST /api/accounts`

Creates an account and returns a personal API token once. This endpoint may be
disabled when an installation delegates identity to an external provider.
`name`, `scopes`, and `expiresInDays` are optional. New tokens default to all
three project scopes. Omitting `expiresInDays` preserves the v1 delete-only
token lifecycle (the token does not expire); the accepted explicit lifetime is
1–365 days. An unknown or empty `scopes` list returns `400`
`{"error": "invalid_scope"}`; an `expiresInDays` outside 1–365 returns `400`
`{"error": "invalid_request"}`.

```json
{
  "username": "ada",
  "password": "correct horse battery staple",
  "email": "ada@example.org",
  "name": "GeoLibre desktop",
  "scopes": ["read:projects", "write:projects"],
  "expiresInDays": 30
}
```

Response `201`:

```json
{
  "account": {"id": "uuid", "username": "ada", "email": "ada@example.org", "createdAt": "2026-08-03T12:00:00Z"},
  "token": "secret-token",
  "tokenId": "uuid",
  "scopes": ["read:projects", "write:projects"],
  "expiresAt": "2026-09-02T12:00:00Z"
}
```

### `POST /api/auth/token`

Exchanges account credentials for a personal API token. It accepts the same
optional policy fields (but not `email`) and returns the same shape as account
creation. Tokens are opaque and stored only as SHA-256 digests. `email` is
optional at account creation, trimmed and normalized to lowercase, validated,
and unique when present.

### `PATCH /api/account`

Requires `write:projects`. `{"email":"ada@example.org"}` sets the signed-in
account's validated, normalized email; `{"email":null}` clears it. A duplicate
email is `409`. The response is `{"account": <account>}` and uses
`Cache-Control: private, no-store`.

### `DELETE /api/auth/token`

Revokes the presented Bearer token. Response: `204`.

### `GET /api/users/me`

Returns the account, effective credential scopes, and OAuth session ID. `sessionId`
is `null` for personal tokens. A management grant reports only
`["manage:sessions"]`, not the project's scopes.

```json
{
  "user": {"id": "uuid", "username": "ada", "email": "ada@example.org", "createdAt": "2026-08-03T12:00:00Z"},
  "sessionId": "oauth-session-uuid",
  "scopes": ["read:projects", "write:projects", "share:public"]
}
```

An identity provider may create accounts without a username. Project creation
for such an account must return `400` with an error containing the stable,
case-insensitive sentinel text `username required`. Existing clients recognize
that phrase and direct the user to account settings.

### Session and personal-token management

These routes require a separate OAuth Bearer grant whose **only** scope is
`manage:sessions`. A project OAuth grant, even for the same account, and every
personal API token receive `403 insufficient_scope`. The client first resolves
the account ID and project `sessionId` using its project credential, then
requests fresh management consent and compares the management account ID
before listing anything. Management credentials must not be persisted or used
for project/gallery calls.

`GET /api/auth/sessions?limit=50&offset=0&currentSessionId=<project-session-id>`
returns `{"sessions": [<session>], "limit": 50, "offset": 0, "total": 1}`.
`limit` is 1–100; `offset` is nonnegative. If supplied, `currentSessionId`
must name an active project session owned by the management account, otherwise
the response is `404`. The server marks exactly that entry `current: true`.
Only active, unexpired project OAuth sessions and personal API tokens appear;
short-lived management grants never appear. Rows sort by creation time newest
first, then ID for ties. Each row contains a public UUID, not a token:

```json
{
  "id": "uuid",
  "kind": "oauth",
  "clientId": "geolibre-desktop",
  "label": "GeoLibre Desktop",
  "scopes": ["read:projects", "write:projects", "share:public"],
  "createdAt": "2026-08-03T12:00:00Z",
  "lastUsedAt": null,
  "expiresAt": "2026-09-02T12:00:00Z",
  "current": true,
  "legacy": false
}
```

Personal tokens use `kind: "personal-token"`, `clientId: null`,
`current: false`, and may have `expiresAt: null`. Old tokens without a policy
are backfilled on listing, marked `legacy: true`, and remain valid until
revoked. Management responses use `Cache-Control: private, no-store`.

`DELETE /api/auth/sessions/{id}` returns `204` for an owned project OAuth
family or personal token, including one already revoked. Management grants are
not addressable through this endpoint; unknown, foreign, and management-only IDs
return the same `404`. Revocation invalidates the family, not just one access
token.
If the ID is the current project session, the client must immediately clear
its local project credential and protected Gallery/remote-edit state; it must
not keep a stale session UI. A pasted personal token remains a separate
credential and is not silently replaced by the OAuth grant.

`POST /api/auth/sessions/revoke-others` accepts
`{"currentSessionId":"<project-session-id>"}` and returns `204`. It atomically
revokes every other OAuth family and **every** personal token for this account,
while keeping both the owned active project session named in the request and
the calling management grant. Missing, foreign, expired, revoked, or
management-only IDs are `404` without partial revocation. Clients should
confirm this destructive action and warn that scripts and CI using personal
tokens will stop working. Refresh rotation and bulk revocation serialize on
the session rows on PostgreSQL.

## Organizations

Organization and group routes use the same scopes as project routes: every
`GET` (memberships, members, invitations, galleries, a confined group's
thumbnail, and `GET /api/projects?shared_with_me=true`) requires
`read:projects`, and every mutation (creating organizations or groups, changing
settings or membership, issuing, revoking, or accepting invitations, joining,
deciding join requests, moderating, and thumbnails) requires `write:projects`.
Reading a non-public project reached through an organization or group, like a
private one, also requires `read:projects`.

`POST /api/organizations` creates an organization and makes the caller its first
`administrator`. The body contains `slug`, `name`, `publicSharingPolicy`
(`yes`, `publishers`, or `no`), `defaultVisibility`, and optional `categories`.
The slug is globally unique. `defaultVisibility` is returned as the safe client
default; requests still state their visibility explicitly.

Organization roles are:

- `administrator`: manage settings and membership, and mutate any
  organization-owned project.
- `publisher`: create organization content and publish publicly when policy is
  `publishers` or `yes`.
- `member`: create organization content and share within the organization; may
  publish only when policy is `yes`.
- `viewer`: read organization-visible content only.

A publisher or member who creates organization content may manage that content
while they retain that organization role. Administrators may manage every
organization project. Demotion to viewer or removal from the organization
immediately removes the creator's management permission; the project remains
owned by the organization rather than becoming orphaned.

The same rule governs private reads: administrators and active creators can
read private organization projects they can manage. Membership alone does not
grant a publisher, member, or viewer access to somebody else's private project.

Routes:

- `GET /api/organizations/mine` lists memberships and each caller's `role`.
- `GET /api/organizations/{id}` returns settings to a member.
- `PATCH /api/organizations/{id}` changes `name`, `publicSharingPolicy`,
  `defaultVisibility`, or `categories`; administrator only.
- `GET /api/organizations/{id}/members` lists members.
- `PUT /api/organizations/{id}/members` adds or updates
  `{"username":"ada","role":"member"}`; administrator only.
- `DELETE /api/organizations/{id}/members/{username}` removes a member. The
  last administrator cannot be removed or demoted.
- `POST /api/organizations/{id}/invitations` creates a pending invitation for
  exactly one `username` or `email`; `GET` on the same path lists pending,
  accepted, and revoked invitations. Issuance and listing are administrator
  only. The creation response alone includes the opaque `token`.
- `DELETE /api/organizations/{id}/invitations/{invitationId}` changes a pending
  invitation to `revoked`; administrator only.
- `POST /api/organizations/invitations/{token}/accept` requires sign-in, verifies
  the account's username or email, adds the member with the invited role, and
  changes the invitation to `accepted`.
- `GET /api/organizations/{id}/projects` returns the organization gallery. A
  non-administrator sees public and organization-visible projects plus private
  projects separately shared with one of their groups.

Supplying `organizationId` on project creation or patch transfers the project
to organization ownership. Its `username` is then `null`, every organization
administrator can manage it, and raw routes use
`/org/{organizationSlug}/{projectSlug}[.geolibre.json]`. Clearing
`organizationId` transfers it to the caller's individual account. The public
sharing policy is enforced on create and patch, including direct API requests.
Servers retain a nullable creator identity separately from ownership. New
projects record their creating account whether ownership is individual or
organizational; organization ownership remains authoritative, and the creator
identity does not populate `username` or create an individual project URL.

## Groups

`POST /api/groups` creates a standalone or organization-associated group. The
body contains `name`, optional `description` and `organizationId`, `joinPolicy`
(`invite`, `request`, or `open`), and `sharedUpdate`. `sharedUpdate` is fixed at
creation and cannot be patched; `name`, `description`, and `joinPolicy` are
settings. An optional PNG, JPEG, or WebP thumbnail uses
`PUT`/`GET`/`DELETE /api/groups/{id}/thumbnail`.

Group roles are `owner`, `manager`, and `member`. Exactly one accepted member is
the owner. An owner transfers ownership by assigning `owner` through
`PUT /api/groups/{id}/members`; the prior owner becomes a manager atomically.
Managers can add/remove ordinary members, invite, decide join requests, and
remove projects from the group. Only the owner can manage managers or transfer
ownership, and an owner cannot leave until ownership is transferred.

Routes:

- `GET /api/groups/mine` lists accepted memberships; `GET /api/groups/{id}`
  returns group detail to a signed-in caller.
- `GET /api/groups/{id}/members` lists accepted members. Owners/managers also
  see pending join requests.
- `PUT /api/groups/{id}/members` adds or changes a member using `username` and
  `role`; `DELETE /api/groups/{id}/members/{username}` removes one, and
  `{username}=me` leaves.
- `POST /api/groups/{id}/invitations` creates a pending invitation for exactly
  one `username` or `email`. The creation response includes its opaque token;
  manager listings omit the token and retain pending, accepted, and revoked
  rows. `DELETE .../invitations/{invitationId}` changes a pending invitation to
  `revoked`, and `POST /api/groups/invitations/{token}/accept` changes it to
  `accepted` while adding the signed-in target account.
- `POST /api/groups/{id}/join` immediately joins an open group, creates a
  pending request for a request group, and rejects an invite-only group.
  `POST /api/groups/{id}/members/{username}/decide` with decision `accept` or
  `reject` moderates a pending request.
- `GET /api/groups/{id}/projects` lists targeted projects.
  `DELETE /api/groups/{id}/projects/{projectId}` removes that target without
  deleting the project.

Project create and patch requests accept `groupIds`. The caller must be an
accepted member of every target. A member can read a private project targeted
to their group and can update its content only if that group's immutable
`sharedUpdate` value is true. Removing the membership or target revokes access
on the next request; protected raw and thumbnail responses are never shared or
persistently cached.

Invitation tokens are bearer credentials. For both organization and group
invitations, servers must store only a SHA-256 digest, return the raw token only
from the creation call, and hash the path token before acceptance lookup.
Accepted and revoked tokens cannot be reused.

Group thumbnails follow the group's join policy. An `open` group's thumbnail is
public and may use `Cache-Control: public, max-age=3600`. For `invite` and
`request` groups, only accepted members may fetch the thumbnail and every
successful response uses `Cache-Control: private, no-store`; non-members receive
`404`. This prevents a stable public thumbnail URL from disclosing content from
a membership-confined group.

## Projects

### Project representation

```json
{
  "id": "uuid",
  "username": "ada",
  "slug": "wetlands",
  "title": "Wetlands",
  "description": "",
  "visibility": "public",
  "canEdit": true,
  "organization": {"id": "uuid", "slug": "watershed-lab", "name": "Watershed Lab"},
  "groupIds": ["group-uuid"],
  "thumbnailUrl": "/api/projects/uuid/thumbnail",
  "views": 12,
  "forkCount": 0,
  "versionCount": 1,
  "featured": false,
  "createdAt": "2026-08-03T12:00:00Z",
  "updatedAt": "2026-08-03T12:00:00Z",
  "tags": [],
  "rawJsonUrl": "https://example.org/ada/wetlands.geolibre.json",
  "projectUrl": "https://example.org/ada/wetlands",
  "viewerUrl": "https://example.org/?project=https%3A%2F%2Fexample.org%2Fada%2Fwetlands.geolibre.json"
}
```

`organization` is non-null whenever the project is organization-owned,
regardless of visibility.
`groupIds` is an array of group identifiers the project is shared with (empty
array when none). Authenticated project, listing, create, and update responses
include `canEdit`, computed by the server for that caller. It is true for an
individual owner, an organization administrator, an active organization
creator, or a member of a targeted group whose `sharedUpdate` setting is true.
Clients must use this value instead of reconstructing authorization from roles.
Anonymous responses omit it. Because authenticated public responses vary by
caller, they use `Cache-Control: private, no-store`. Unknown fields must be
ignored by consumers.

### `POST /api/projects`

Requires auth. Creates a project and its first immutable version.

```json
{
  "filename": "Wetlands.geolibre.json",
  "content": "{\"version\":\"1.0\", ...}",
  "visibility": "public",
  "organizationId": "org-uuid",
  "groupIds": ["group-uuid-1", "group-uuid-2"]
}
```

`content` is a string containing a valid GeoLibre project JSON document.
`filename` supplies a fallback title/slug; the project document's non-empty
title is authoritative. `visibility` is required and is `public`, `unlisted`,
`private`, or `organization`. `organizationId` is required when `visibility`
is `organization`. `groupIds` is an optional array of group identifiers; the
caller must be a member of every listed group.

### `GET /api/projects`

Returns a page in newest-updated-first order:

```json
{"projects": [], "limit": 24, "offset": 0, "total": 0}
```

Query parameters:

- `limit`: integer page size.
- `offset`: non-negative number of matching records to skip.
- `featured=true`: return featured projects only.
- `mine=true`: return the caller's own projects, including unlisted and private
  ones. Requires auth; without a valid token this is `401`.
- `shared_with_me=true`: return organization-visible projects from the caller's
  organizations, organization public projects, manageable private/unlisted
  organization projects, and projects explicitly targeted to their groups.
  Requires auth and cannot be combined with `mine=true`.
- `shared_source=organizations|groups`: with `shared_with_me=true`, restrict the
  query before pagination and counting. `organizations` includes public and
  organization-visible projects in the caller's organizations plus
  private/unlisted projects manageable as an administrator or active creator.
  `groups` includes projects explicitly targeted to an accepted group
  membership. Using this parameter without `shared_with_me=true` is `422`.

Only public projects are returned unless `mine=true` or `shared_with_me=true` is
set. An Authorization header does not broaden a public listing by itself.
Invalid pagination or combining both private listing modes is `422`.

### `GET /api/users/{username}/projects`

Returns `{"projects": [...]}` owned by `{username}`, in newest-updated-first
order. Auth is optional and decides the breadth of the result: when the token
identifies `{username}`, the listing includes their unlisted and private
projects; every other caller, authenticated or not, sees only that user's public
projects. The current client first resolves its username through
`GET /api/users/me`, then calls this route.

The route accepts `limit` (1-100, default 24) and `offset` (default 0).

A non-owner therefore gets a filtered `200`, not a `403` — the listing narrows
rather than refusing, which keeps a user's existence from being probed through
the status code.

### `GET /api/projects/{id}`

Returns `{"project": <project>}` if visible to the caller.

### `GET /api/projects/{id}/versions`

Requires auth and read access to the project. Returns newest first:

```json
{"versions":[{"number":3,"createdAt":"2026-08-03T12:00:00Z","url":"https://example.org/api/projects/uuid/versions/3"}]}
```

Protected project history responses use `Cache-Control: private, no-store`.
The existing `GET /api/projects/{id}/versions/{version}` route continues to
return the immutable project document itself.

### `PATCH /api/projects/{id}`

Requires ownership, or organization administrator / active organization creator access for organization-owned projects. Accepted fields are `title`, `description`, `visibility`,
`tags`, `organizationId`, and `groupIds`. Response: `{"project": <project>}`.

### `PUT /api/projects/{id}/content`

Requires ownership or write access via a shared-update group. Creates a new
immutable version.

```json
{"content": "{\"version\":\"1.0\", ...}", "expectedVersion": 3}
```

`expectedVersion` is optional. When provided and it does not match the current
latest version, the write still succeeds under last-write-wins and the `201`
response includes a `warning` string containing the stable phrase
`version conflict`. A matching or omitted version has no `warning` field.

Response `201`: `{"project": <project>, "version": <positive integer>}`.

### `DELETE /api/projects/{id}`

Requires ownership. Deletes metadata and stored objects. Response: `204`.

### `GET /api/projects/{id}/activity`

Requires ownership. Returns the project's activity log, newest first, capped
at 100 entries:

```json
{"activity": [
  {"id": "…", "action": "visibility_change", "actorId": "…",
   "details": {"before": "private", "after": "public"}, "createdAt": "…"},
  {"id": "…", "action": "open", "actorId": null,
   "details": {"date": "2026-08-21", "count": 40}, "createdAt": "…"}
]}
```

Actions and their `details`: `version_save` (`version`), `fork`
(`forked_project_id`), `visibility_change` (`before`, `after`), `fetch` of
the raw JSON (`version`) and `open` of the project page. `actorId` is the
acting account, or `null` for an anonymous visitor. Anonymous `open` and
`fetch` events are **never stored per visitor**: they are aggregated into one
row per action and UTC day carrying a `count`, and no IP address or other
visitor fingerprint is recorded. Rows are pruned after
`GEOLIBRE_ACTIVITY_RETENTION_DAYS` (default 90) the next time the project logs
an event. The log is visible only to the owner and never appears in listings.

### `DELETE /api/projects/{id}/activity`

Requires ownership. Deletes every activity row for the project. Response: `204`.

### `POST /api/projects/{id}/forks`

Requires auth. Creates a new project owned by the caller from the visible
source's latest content. The request body is **optional**: `{"visibility": ...}`
selects the fork's visibility, and omitting the body entirely (the common "fork
this project" call) must behave as `{"visibility":"private"}` rather than
returning `422`. Responds `201` with `{"project": <project>}`. The source
`forkCount` increases atomically.

### Raw project and website-compatible routes

- `GET /{username}/{slug}.geolibre.json` returns the latest project document
  with `Content-Type: application/json`.
- `GET /api/projects/{id}/versions/{version}` returns an immutable historical
  document.
- `GET /{username}/{slug}` may return an HTML project page or redirect to the
  configured GeoLibre viewer. It is the `projectUrl` advertised by the API.
- Organization-owned equivalents are
  `GET /org/{organizationSlug}/{slug}.geolibre.json` and
  `GET /org/{organizationSlug}/{slug}`.

Every successful read of the latest raw document may increment `views`; servers
must not count failed or unauthorized reads.

### Thumbnails

`PUT /api/projects/{id}/thumbnail` requires ownership and accepts the image
bytes with their image content type. `GET /api/projects/{id}/thumbnail` follows
project visibility. `DELETE` removes it. Upload and delete responses are `204`.

## Personal token scopes

| Scope | Grants |
| --- | --- |
| `read:projects` | List and open the caller's own projects, including unlisted/private projects; read organization/group memberships, galleries, and projects shared with the caller |
| `write:projects` | Create, update, delete, and fork projects the caller may manage or shared-update; create and manage organizations, groups, memberships, and invitations; change the account email |
| `share:public` | Create a public project or raise a project's visibility to public |

New personal tokens require a nonempty subset of these scopes. Omitting
`scopes` preserves the historical project permissions for existing clients.
Omitting `expiresInDays` keeps the token valid until revoked (the v1
delete-only lifecycle); set `expiresInDays` to 1–365 to mint an expiring token.
Tokens that predate the policy table are upgraded on first use with all three
project scopes, no expiry, and a legacy marker.

A valid credential missing a required scope receives `403` with
`{"error": "insufficient_scope", "requiredScope": "<scope>"}` and
`WWW-Authenticate: Bearer error="insufficient_scope"`. Missing credentials use
the `Bearer` challenge; malformed, unknown, revoked, and expired credentials use
`Bearer error="invalid_token"`.

## OAuth 2.0 sign-in (Authorization Code + S256 PKCE)

The reference server implements Authorization Code with PKCE (`S256` only) for
public clients; no client secret is accepted. Registrations are exact and
startup-validated through `GEOLIBRE_OAUTH_CLIENTS`. The only supported client
IDs are `geolibre-web` and `geolibre-desktop`. Empty or unset configuration
disables every OAuth route without changing personal-token startup behavior.

The issuer is `GEOLIBRE_PUBLIC_URL`. When OAuth is enabled it must be an
absolute HTTPS URL. Loopback HTTP is allowed only for `localhost` or
`127.0.0.1` with an explicit port. The request `Host` header, including its
port, must match the issuer authority.

### Discovery

`GET /.well-known/oauth-authorization-server` returns RFC 8414 metadata. For an
issuer with path `/services/projects`, the route is
`/.well-known/oauth-authorization-server/services/projects`. The document
advertises the authorization, token, and revocation endpoints; authorization
code and refresh grants; `S256`; the three project scopes; and
`manage:sessions` (OAuth-only).

### Authorization and consent

`GET /oauth/authorize` accepts one value each for `response_type=code`,
`client_id`, exact `redirect_uri`, nonempty `scope`, `state`, `code_challenge`,
and `code_challenge_method=S256`; `device_label` is optional. State is 16–512
URL-safe characters. The S256 challenge is the 43-character unpadded base64url
SHA-256 value.

Duplicate authorization parameters, unknown clients, unregistered redirects,
and state values longer than 512 characters return a local error page without
a `Location` header. Other authorization errors redirect to the already
validated callback with `error`, `iss`, and the exact `state` value when supplied.

`POST /oauth/authorize` submits the server-owned consent form. It requires the
browser-binding cookie, CSRF value, same-origin `Origin` or `Referer`, and
account credentials. Approval returns `303` to the exact callback with a
single-use code, `state`, and `iss`; cancellation returns `access_denied`.
Authorization codes expire after 60 seconds by default.
Production HTTPS uses a host-only `Secure` browser-binding cookie; permitted
loopback HTTP development uses a host-only non-`Secure` cookie so Safari can
submit the consent form.

Web redirects must be absolute HTTPS URLs ending in `/oauth-callback.html`.
Explicit-port loopback HTTP is allowed for development. Desktop redirects must
be exactly `org.geolibre.desktop:/oauth/callback`. The installed Tauri desktop
app opens consent in the system browser and receives that URI through the OS
protocol handler (on macOS, Windows, and Linux), not an inbound HTTP listener.
It accepts a callback only for a live, matching state and issuer. A callback
that cold-launches an app with no pending verifier cannot complete sign-in:
the user must restart consent. No authorization code or token belongs in a
diagnostic log or a persisted project.

### Token exchange and rotation

`POST /oauth/token` accepts form-urlencoded bodies up to 16 KiB:

- `grant_type=authorization_code` requires `client_id`, `code`,
  `redirect_uri`, and a 43–128 character `code_verifier`.
- `grant_type=refresh_token` requires `client_id` and `refresh_token`.
  Optional `scope` must be the same scope set as the original grant; ordering
  does not matter.

Success returns:

```json
{
  "access_token": "opaque",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "opaque",
  "scope": "read:projects write:projects"
}
```

Request `manage:sessions` **alone** for a fresh step-up consent. Combining it
with project scopes is `invalid_scope`. Its success response has
`"scope":"manage:sessions"` and `"expires_in":300` (or less if the server
enforces a shorter access lifetime), but **no `refresh_token`**. The server
never creates a refresh row for this grant, rejects refresh attempts, and
caps its access token and family at five minutes. A client must hold the
management token only in memory and discard it when session management closes,
the project session changes, or the grant expires. A `401` on a management
request requires a new consent; it must not sign the project session out.

Access tokens expire after 600 seconds by default and never outlive their
family. Refresh tokens are single-use and rotate on every use. Reusing a
consumed refresh token revokes the entire family, including tokens minted by
the successful rotation. A family expires at issuance plus the configured
refresh TTL (30 days by default); rotation never extends it.

An enabled server deletes bounded batches of expired interactions, access
tokens, and families at startup, during OAuth requests, and every five minutes
while running. Consumed refresh generations stay until the family expires so
replay detection remains effective.

`POST /oauth/revoke` accepts `client_id`, `token`, and optional advisory
`token_type_hint`. A matching access or refresh token revokes its entire
family. Unknown, already-revoked, and wrong-client tokens all return the same
empty `200`.

OAuth failures use `invalid_request`, `invalid_client`, `invalid_grant`,
`invalid_scope`, `unsupported_grant_type`, or `unsupported_token_type`. Token
and revocation responses are `no-store`. Raw codes and tokens are returned once;
the database stores only SHA-256 digests.

Project OAuth access tokens use the same project scope matrix as personal
tokens. `manage:sessions` authorizes only the session-management routes
documented above. It is exclusive to OAuth consent, never available to
personal tokens; it grants no project read or write access. `admin:org`
remains reserved and is rejected.

## Compatibility

The API is additive within version 1. Implementations must not repurpose fields
or narrow visibility rules. New optional fields and endpoints may be added.
Breaking changes require a new `/api/v2` namespace. The conformance baseline is
the frontend tests for `share-geolibre.ts` and `share-gallery.ts`, plus the
reference server's API tests.
