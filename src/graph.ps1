# Microsoft Graph eDiscovery (Premium) search and purge.
#
# Replaces the Security & Compliance PowerShell path, which is unusable under
# app-only certificate auth: Start-ComplianceSearch requires a session created
# with -EnableSearchOnlySession, and that flag returns UnAuthorized for app-only
# identities. Verified on two independent machines with the service principal in
# both DataInvestigator and OrganizationManagement, so it is not an RBAC gap.
#
# Graph eDiscovery has no equivalent session concept, is app-only capable, and
# purges up to 100 items per location instead of PowerShell's 10 per mailbox.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GraphToken = $null
$script:GraphTokenExpiry = [datetime]::MinValue
$script:CaseId = $null

function Get-GraphToken {
    <#
      Client-credentials token using a signed JWT assertion.

      Built by hand rather than via MSAL: the module ships as a DLL inside
      ExchangeOnlineManagement and loading it from an arbitrary path is brittle
      across module versions. The assertion is ~20 lines and has no dependency.
    #>
    if ($script:GraphToken -and [datetime]::UtcNow -lt $script:GraphTokenExpiry) {
        return $script:GraphToken
    }

    $cert = Get-ExoCertificate
    $appId = $env:EXO_APP_ID
    $tenant = $env:EXO_TENANT_ID
    if (-not $tenant) { $tenant = $env:EXO_ORGANIZATION }
    if (-not $appId -or -not $tenant) { throw 'EXO_APP_ID and EXO_TENANT_ID (or EXO_ORGANIZATION) are required.' }

    $authority = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"

    function ConvertTo-Base64Url([byte[]]$bytes) {
        [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-Base64Url $cert.GetCertHash()
    } | ConvertTo-Json -Compress
    $payload = @{
        aud = $authority
        iss = $appId
        sub = $appId
        jti = [guid]::NewGuid().ToString()
        nbf = $now - 60
        exp = $now + 600
    } | ConvertTo-Json -Compress

    $encHeader = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
    $encPayload = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
    $unsigned = "$encHeader.$encPayload"

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw 'Certificate has no usable RSA private key.' }
    $sig = $rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $assertion = "$unsigned." + (ConvertTo-Base64Url $sig)

    $body = @{
        client_id             = $appId
        scope                 = 'https://graph.microsoft.com/.default'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
        grant_type            = 'client_credentials'
    }

    $resp = Invoke-RestMethod -Method Post -Uri $authority -Body $body -ContentType 'application/x-www-form-urlencoded'
    $script:GraphToken = $resp.access_token
    # Refresh a minute early rather than racing the expiry.
    $script:GraphTokenExpiry = [datetime]::UtcNow.AddSeconds([int]$resp.expires_in - 60)
    return $script:GraphToken
}

function Invoke-Graph {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body,
        [string]$ApiVersion = 'v1.0',
        # Long-running actions answer 202 with an empty body and put the
        # operation URL in the Location header, so those callers need the whole
        # response rather than the parsed content.
        [switch]$Raw
    )
    $token = Get-GraphToken
    $uri = "https://graph.microsoft.com/$ApiVersion$Path"
    $headers = @{ Authorization = "Bearer $token" }

    # Not $args: that is an automatic variable inside a function.
    $req = @{ Method = $Method; Uri = $uri; Headers = $headers }
    if ($null -ne $Body) {
        $req['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $req['ContentType'] = 'application/json'
    }

    # Graph puts the actual complaint in the response body; the exception message
    # is only "Response status code does not indicate success: 400". Losing the
    # body turns every schema mistake into a guessing game, so re-throw with it.
    #
    # 502/503/504 come from Azure's front door rather than Graph itself and are
    # routinely transient -- a 504 creating a search failed an entire poll run
    # once. Retry those and 429; never retry a 4xx, which would just repeat a
    # request Graph has already rejected on its merits.
    $attempt = 0
    $maxAttempts = 4
    while ($true) {
        $attempt++
        try {
            if ($Raw) { return Invoke-WebRequest @req }
            return Invoke-RestMethod @req
        }
        catch {
            $err = $_
            $status = 0
            # StrictMode turns a read of a missing property into a throw, and not
            # every exception reaching here is an HttpResponseException. Probing
            # first matters because a crash inside the error handler destroys the
            # error it was meant to report -- that is how a Graph 400 surfaced as
            # "The property 'Response' cannot be found on this object."
            if ($err.Exception.PSObject.Properties.Name -contains 'Response') {
                $resp = $err.Exception.Response
                if ($resp) {
                    try { $status = [int]$resp.StatusCode } catch { $status = 0 }
                }
            }
            # Status 0 means no HTTP response at all -- DNS, TLS or a dead
            # socket. Those are transient far more often than not, and one of
            # them ("Network is unreachable" when the resolver returns only AAAA
            # records for graph.microsoft.com and the bridge is IPv4-only) failed
            # a whole run. Retrying a connection failure costs nothing.
            $transient = ($status -in @(429, 500, 502, 503, 504)) -or ($status -eq 0)

            if ($transient -and $attempt -lt $maxAttempts) {
                $backoff = [Math]::Pow(2, $attempt) * 5
                Write-Host "Graph $Method $Path -> $status, retry $attempt/$($maxAttempts - 1) in ${backoff}s"
                Start-Sleep -Seconds $backoff
                continue
            }

            $detail = $null
            if ($err.ErrorDetails -and $err.ErrorDetails.Message) { $detail = $err.ErrorDetails.Message }
            $suffix = if ($transient) { " after $attempt attempts" } else { '' }
            throw "Graph $Method $Path failed$suffix (HTTP $status): $($err.Exception.Message) | body: $(if ($detail) { $detail } else { '(none)' })"
        }
    }
}

function Get-WorkerCase {
    <#
      One long-lived eDiscovery case reused for every search, rather than a case
      per request. Cases are heavyweight objects and there is no automatic
      cleanup; creating one per phishing finding would sprawl indefinitely.
    #>
    if ($script:CaseId) { return $script:CaseId }

    $name = 'm365-response-worker'
    $existing = Invoke-Graph -Method GET -Path "/security/cases/ediscoveryCases"
    $match = $existing.value | Where-Object { $_.displayName -eq $name } | Select-Object -First 1
    if ($match) { $script:CaseId = $match.id; return $script:CaseId }

    $created = Invoke-Graph -Method POST -Path '/security/cases/ediscoveryCases' -Body @{
        displayName = $name
        description = 'Automated searches and purges driven by eSentire response actions.'
    }
    $script:CaseId = $created.id
    return $script:CaseId
}

function Invoke-GraphSearch {
    <#
      Creates a search in the worker case and runs an estimate. Returns the item
      count and the number of mailboxes hit, plus the search id, which the purge
      then acts on -- so the set approved is exactly the set deleted.
    #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$Name,
        # Scope to named mailboxes instead of the whole tenant. Estimate time
        # scales with locations searched, so a handful of addresses returns in
        # under a minute against 730 s tenant-wide.
        #
        # Faster, but strictly less complete: it can only find mail in mailboxes
        # somebody already named. Use it to break a known set down per mailbox
        # -- which is the only way to learn WHICH mailbox a hit is in, since
        # estimateStatistics reports a mailboxCount and no names -- not as a
        # substitute for the tenant-wide sweep that catches the rest.
        [string[]]$Mailboxes,
        # A tenant-wide estimate for a single sender over eight days was measured
        # at 730 s against this tenant, so the old 600 s ceiling failed every
        # real search a couple of minutes before Graph finished. Callers run this
        # on a background job, so a generous ceiling costs nothing.
        [int]$TimeoutSeconds = 3600
    )

    if (-not $Name) { $Name = "auto-$([guid]::NewGuid().ToString('N').Substring(0,12))" }
    $caseId = Get-WorkerCase
    $scoped = ($Mailboxes -and $Mailboxes.Count -gt 0)

    # Scoping to named mailboxes takes three calls, because the obvious one-shot
    # forms are both rejected:
    #
    #   * creating with dataSourceScopes 'none' and no sources fails with
    #     "At least one data source is required"
    #   * additionalSources is a navigation property, so it cannot be set inline
    #     on create -- it only accepts POSTs to its own collection
    #
    # So: create wide, narrow the sources, then patch the scope down. Nothing
    # runs until estimateStatistics below, so the intermediate wide scope never
    # actually searches anything.
    # REUSE a search with this name if one exists. Both alternatives are wrong:
    #
    #   * Deleting the old one first (an earlier version did this, to keep the
    #     Purview case tidy) invalidates the search id already sitting in every
    #     approval card in Teams. The purge then fails 404 NotFound. Two cases
    #     had to be purged by hand because of it.
    #   * Not deleting and creating anyway fails outright: Graph enforces unique
    #     display names within a case and answers
    #     409 Conflict "An entity with the same name already exists."
    #
    # Reusing keeps the id stable for the lifetime of the case, so an approval
    # link never goes stale no matter how often the poller re-runs.
    $existing = $null
    try {
        $all = Invoke-Graph -Method GET -Path "/security/cases/ediscoveryCases/$caseId/searches"
        $existing = $all.value | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
    }
    catch {
        Write-Host "Could not list existing searches, will try to create: $($_.Exception.Message)"
    }

    $created = $false
    if ($existing) {
        $search = $existing
        Write-Host "Reusing search '$Name' ($($search.id))"
    }
    else {
        $search = Invoke-Graph -Method POST -Path "/security/cases/ediscoveryCases/$caseId/searches" -Body @{
            displayName      = $Name
            contentQuery     = $Query
            dataSourceScopes = 'allTenantMailboxes'
        }
        $created = $true
    }

    try {
        # The received window ends "tomorrow", so the query differs on every run
        # even when nothing else has changed. Refresh it on a reused search.
        if (-not $created) {
            Invoke-Graph -Method PATCH `
                -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)" `
                -Body @{ contentQuery = $Query } | Out-Null
        }

        if ($scoped) {
            # Add only what is missing. Sources are never removed: an extra
            # mailbox left over from an earlier run simply returns no hits,
            # whereas removing one risks dropping a recipient still in scope.
            $have = @()
            try {
                $srcs = Invoke-Graph -Method GET `
                    -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources"
                foreach ($s in $srcs.value) { if ($s.email) { $have += $s.email.ToLower() } }
            }
            catch { $have = @() }

            foreach ($mbx in $Mailboxes) {
                if ($have -contains $mbx.ToLower()) { continue }
                # email only: includedSources is returned by Graph, not accepted.
                Invoke-Graph -Method POST `
                    -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources" `
                    -Body @{ '@odata.type' = 'microsoft.graph.security.userSource'; email = $mbx } | Out-Null
            }
        }

        # Set the scope last: 'none' is only legal once sources exist.
        Invoke-Graph -Method PATCH `
            -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)" `
            -Body @{ dataSourceScopes = $(if ($scoped) { 'none' } else { 'allTenantMailboxes' }) } | Out-Null
    }
    catch {
        $setupError = $_
        # Only roll back a search WE created this run. Deleting a reused one
        # would destroy the id every existing approval card points at -- the
        # exact failure this whole block exists to prevent.
        if ($created) {
            try {
                Invoke-Graph -Method DELETE -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)" | Out-Null
                Write-Host "Rolled back partially built search '$Name'"
            }
            catch { Write-Host "Could not roll back search '$Name': $($_.Exception.Message)" }
        }
        throw $setupError
    }

    Invoke-Graph -Method POST `
        -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/estimateStatistics" | Out-Null

    # Estimates run for minutes, so poll every 15 s rather than every 5: the
    # extra calls buy nothing and count against the Graph throttle budget.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $op = $null
    do {
        Start-Sleep -Seconds 15
        $op = Invoke-Graph -Method GET `
            -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/lastEstimateStatisticsOperation"
    } while ($op.status -in @('notStarted', 'running', 'submitted') -and (Get-Date) -lt $deadline)

    if ($op.status -ne 'succeeded') {
        throw "Estimate did not succeed within $TimeoutSeconds s (status: $($op.status))."
    }

    return @{
        action        = 'graph_ediscovery_search'
        case_id       = $caseId
        search_id     = $search.id
        search_name   = $Name
        query         = $Query
        scope         = if ($scoped) { 'mailboxes' } else { 'all_tenant_mailboxes' }
        mailboxes     = if ($scoped) { @($Mailboxes) } else { @() }
        total_items   = [int]$op.indexedItemCount
        total_size    = [int64]$op.indexedItemsSize
        mailbox_count = [int]$op.mailboxCount
        status        = $op.status
        note          = 'Purge removes up to 100 items per location.'
    }
}

function Invoke-GraphPurge {
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$SearchId,
        [ValidateSet('SoftDelete', 'HardDelete')][string]$PurgeType = 'SoftDelete'
    )

    # Graph names these differently to the PowerShell cmdlet.
    $graphType = if ($PurgeType -eq 'HardDelete') { 'permanentlyDelete' } else { 'recoverable' }

    # 202 with an empty body: the only handle on the running purge is the
    # operation URL in the Location header. Without it there is no way to report
    # whether a hard delete actually landed.
    $resp = Invoke-Graph -Raw -Method POST `
        -Path "/security/cases/ediscoveryCases/$CaseId/searches/$SearchId/purgeData" `
        -Body @{ purgeType = $graphType; purgeAreas = 'mailboxes' }

    $opId = $null
    $location = $resp.Headers['Location']
    if ($location) {
        # e.g. .../ediscoveryCases('<case>')/operations('<op>')
        $m = [regex]::Match(([string]$location), "operations\('?([^')]+)'?\)")
        if ($m.Success) { $opId = $m.Groups[1].Value }
    }

    return @{
        action       = 'graph_ediscovery_purge'
        case_id      = $CaseId
        search_id    = $SearchId
        purge_type   = $PurgeType
        graph_type   = $graphType
        irreversible = ($PurgeType -eq 'HardDelete')
        operation_id = $opId
        http_status  = [int]$resp.StatusCode
        status       = 'submitted'
        note         = 'purgeData is asynchronous. Poll /purge-status?operation_id=... for the outcome.'
    }
}

function Get-GraphPurgeStatus {
    <#
      Replaces the Security & Compliance Get-ComplianceSearchAction path, which
      is unreachable under app-only auth (see the header of this file).
    #>
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$OperationId
    )

    $op = Invoke-Graph -Method GET -Path "/security/cases/ediscoveryCases/$CaseId/operations/$OperationId"

    return @{
        action       = 'graph_ediscovery_purge_status'
        case_id      = $CaseId
        operation_id = $OperationId
        status       = $op.status
        percent      = $op.percentProgress
        created      = $op.createdDateTime
        completed    = $op.completedDateTime
        graph_action = $op.action
    }
}
