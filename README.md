# M365 Response Worker

A small HTTP API that exposes the Microsoft 365 response actions that **have no
REST equivalent** — Tenant Allow/Block List sender blocking, and Purview
compliance search + purge — so that n8n (or any other orchestrator) can call
them.

Built because Exchange Online and Security & Compliance PowerShell are the only
supported paths for these operations. The Graph `tiIndicator` entity, which used
to cover sender blocking, was retired in April 2026.

## API

All routes except `/health` require `Authorization: Bearer $WORKER_TOKEN`.

| Method | Path | Body | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Liveness. Never contacts Exchange. |
| `POST` | `/block-sender` | `{senders: [...], notes?, expiration_days?}` | Add senders to the Tenant Allow/Block List |
| `POST` | `/search` | `{query, name?, mailboxes?}` | Run a compliance search, return counts **per mailbox** |
| `POST` | `/purge` | `{search_name, purge_type}` | `SoftDelete` or `HardDelete` the results of a named search |
| `GET` | `/purge-status?action_name=` | — | Poll a purge action |

`expiration_days: 0` (the default) creates a block with **no expiration**.

### The two-step purge is deliberate

`/search` runs the search and returns the item count and the per-mailbox
breakdown. `/purge` then acts on **that same named search**. Approving one set
and deleting another is impossible by construction — which matters when the
approval step is a human deciding whether to hard-delete someone's mail.

## Prerequisites

Unattended Exchange PowerShell needs an Entra app registration with a
**certificate**. Client secrets are not supported for app-only EXO.

1. Register an app; note the Application (client) ID and tenant domain.
2. Generate a certificate, upload the **.cer** to the app registration, and keep
   the **.pfx** for the container.
3. Grant the app the **`Exchange.ManageAsApp`** application permission (Office 365
   Exchange Online) and admin-consent it.
4. Assign the service principal the **Exchange Administrator** role in Entra.
5. In Purview, add the service principal to **Organization Management** or
   **Data Investigator** — those are the only role groups holding the
   *Search and Purge* role. Without this, purge fails.

## Deployment

Place the PFX on the Docker host (default `/opt/m365-worker/certs/exo.pfx`),
readable by uid `10002`, then deploy `docker-compose.yml` as a Portainer stack.
It builds directly from this repo — no registry required.

Set these as stack environment variables:

| Variable | Purpose |
|---|---|
| `EXO_APP_ID` | Application (client) ID |
| `EXO_ORGANIZATION` | Tenant domain, e.g. `contoso.onmicrosoft.com` |
| `EXO_CERT_PASSWORD` | PFX password |
| `EXO_CERT_HOST_DIR` | Host directory holding `exo.pfx` |
| `WORKER_TOKEN` | Bearer token callers must present |
| `WORKER_PORT` | Published host port (default 3022) |

## Gotchas this encodes

These are all non-obvious and each one fails in a way that is hard to diagnose:

- **`-CertificateThumbprint` is Windows-only.** On Linux the certificate must be
  passed as an `X509Certificate2` object loaded from a PFX.
- **`Connect-IPPSSession` requires `-EnableSearchOnlySession`** or
  `New-ComplianceSearchAction -Purge` will not run.
- **ExchangeOnlineManagement must be ≥ 3.9.0** for purge support.
- **Purge removes at most 10 items per mailbox per action.** Larger sets need
  repeated actions, or eDiscovery Premium via Graph (100 per location).
- Sender blocking and search/purge use **separate connections** — the
  search-only session cannot run `New-TenantAllowBlockListItems`.
- The container is **not** `read_only`; the EXO module writes temp state at
  runtime.

## Safety

`HardDelete` purges past the Recoverable Items folder and is unrecoverable.
Items under Litigation Hold, retention policy, or eDiscovery hold are preserved
regardless of purge type. Anything calling `/purge` should put a human in front
of it.
