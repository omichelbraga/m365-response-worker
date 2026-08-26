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
        [int]$TimeoutSeconds = 3600,
        # Above this many named recipients, scoping stops being worth it: each
        # mailbox is a separate source to create and commit, and a tenant-wide
        # sweep answers the same question in one pass. Below it, scoped is far
        # faster (minutes vs ~15-25).
        [int]$TenantWideThreshold = 25
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
    $rebuilt = $false
    $unresolved = @()
    # Mailboxes that exist but are INACTIVE. They cannot be used as a scoped
    # source without corrupting the estimate, and a scoped search cannot see
    # their contents at all -- only a tenant-wide sweep can.
    $inactive = @()
    # The scope a reused search was BUILT with. Changing it later does not work:
    # Graph binds a search to its committed source collection, and flipping
    # dataSourceScopes afterwards leaves the properties looking right while the
    # search keeps answering from the old collection. Measured: a search built
    # scoped, then stripped of sources and set to allTenantMailboxes, reported 0
    # items and verified_clean=true while a freshly created search with the same
    # query found 5 and the message was still sitting in four mailboxes. A false
    # clean is worse than no verification at all, so if the scope has to change,
    # the search is rebuilt rather than repurposed.
    $originalScopes = $null
    if ($existing) {
        $search = $existing
        $originalScopes = $existing.dataSourceScopes
        Write-Host "Reusing search '$Name' ($($search.id)), built with dataSourceScopes '$originalScopes'"
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

        # Declared out here rather than inside the scoped branch: $haveAny below
        # reads it unconditionally, so under StrictMode a tenant-wide search --
        # which skips that branch entirely -- died on the unset variable. Scoped
        # searches always set it, which is why this hid until the first real
        # tenant-wide call.
        $have = @()

        # Decided BEFORE any source is created: past the threshold there is no
        # point paying to create and commit a source per mailbox for a search
        # that is going tenant-wide anyway.
        $tooMany = ($scoped -and $Mailboxes.Count -gt $TenantWideThreshold)

        if ($scoped -and -not $tooMany) {
            # ASK EXCHANGE FIRST. Two facts are only knowable here, and getting
            # either wrong silently wrecks the search:
            #
            #  * PRIMARY SMTP. eDiscovery userSource rejects proxy addresses with
            #    "User not found" even when the mailbox is real and active.
            #    dnorris@san-marcos.net was refused all night; it is a proxy for
            #    DGordon@sanmarcosca.gov, an ordinary active mailbox. eSentire
            #    reports @san-marcos.net addresses while this tenant's primaries
            #    are @sanmarcosca.gov, so nearly every recipient needs resolving.
            #
            #  * INACTIVE. One inactive mailbox among the sources collapses the
            #    estimate for EVERY other mailbox in the same search -- four
            #    active mailboxes holding one message each estimated as 1. It was
            #    previously detected by creating the source and reading the
            #    displayName back, i.e. only after the damage was done.
            $state = $null
            try { $state = Test-MailboxState -Mailboxes $Mailboxes }
            catch { Write-Host "Mailbox pre-check failed, falling back to raw addresses: $($_.Exception.Message)" }

            $wanted = @()
            if ($state) {
                foreach ($r in $state.results) {
                    if (-not $r.exists) { $unresolved += $r.email; continue }
                    if ($r.inactive) { $inactive += $r.email; continue }
                    $addr = if ($r.primary) { [string]$r.primary } else { [string]$r.email }
                    if ($addr -and ($wanted -notcontains $addr.ToLower())) { $wanted += $addr.ToLower() }
                }
                if ($unresolved.Count) { Write-Host "Not mailboxes, skipped: $($unresolved -join ', ')" }
                if ($inactive.Count) { Write-Host "Inactive mailboxes, skipped: $($inactive -join ', ')" }
            }
            else {
                $wanted = @($Mailboxes | ForEach-Object { $_.ToLower() })
            }

            try {
                $srcs = Invoke-Graph -Method GET `
                    -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources"
                foreach ($s in $srcs.value) {
                    if (-not $s.email) { continue }
                    # A reused search can carry an inactive source from an earlier
                    # run and stay poisoned indefinitely.
                    if ($s.displayName -match '\(Inactive Mailbox\)') {
                        Write-Host "Removing inactive mailbox source '$($s.email)' from reused search"
                        try {
                            Invoke-Graph -Method DELETE `
                                -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources/$($s.id)" | Out-Null
                        }
                        catch { Write-Host "Could not remove inactive source '$($s.email)': $($_.Exception.Message)" }
                        if ($inactive -notcontains $s.email) { $inactive += $s.email }
                        continue
                    }
                    $have += $s.email.ToLower()
                }
            }
            catch { $have = @() }

            foreach ($mbx in $wanted) {
                if ($have -contains $mbx) { continue }
                try {
                    # email only: includedSources is returned by Graph, not accepted.
                    Invoke-Graph -Method POST `
                        -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources" `
                        -Body @{ '@odata.type' = 'microsoft.graph.security.userSource'; email = $mbx } | Out-Null
                    $have += $mbx
                }
                catch {
                    # Should be rare now the pre-check runs, but a mailbox can
                    # still be refused. One bad address must not take down the
                    # mailboxes that were perfectly fine.
                    Write-Host "Skipping unresolvable mailbox '$mbx': $($_.Exception.Message)"
                    $unresolved += $mbx
                }
            }
        }

        # 'none' is only legal once at least one source exists. Escalate to a
        # tenant-wide sweep whenever scoping cannot answer the question honestly.
        # Slower, but a slow true answer beats a fast false one -- the scoped
        # estimate that read "1 message in 1 mailbox" while four mailboxes held
        # the phish is what this guards against.
        $haveAny = ($have.Count -gt 0)
        # An inactive mailbox no longer forces tenant-wide. It is excluded from the
        # sources by the pre-check, so it can no longer corrupt the estimate, and
        # escalating a five-recipient case to a tenant-wide sweep to reach one
        # departed user's mailbox costs ~25 minutes and a tenant-wide purge for a
        # mailbox nobody reads. It is reported on the card as not searched instead.
        # Tenant-wide stays reserved for the recipient-count threshold.
        $effectiveScoped = ($scoped -and $haveAny -and -not $tooMany)

        # A tenant-wide search must have NO sources. Setting dataSourceScopes to
        # allTenantMailboxes while additionalSources remain does NOT widen the
        # search: measured, four leftover sources plus allTenantMailboxes still
        # returned 1 item -- the same wrong answer the sources alone gave. The
        # scope field said tenant-wide and the search behaved as if scoped, which
        # is the worst of both. So when escalating, strip every source first.
        if (-not $effectiveScoped) {
            try {
                $cur = Invoke-Graph -Method GET `
                    -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources"
                foreach ($s in $cur.value) {
                    try {
                        Invoke-Graph -Method DELETE `
                            -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources/$($s.id)" | Out-Null
                        Write-Host "Removed source '$($s.email)' so the tenant-wide search is genuinely tenant-wide"
                    }
                    catch { Write-Host "Could not remove source '$($s.email)': $($_.Exception.Message)" }
                }
            }
            catch { Write-Host "Could not list sources to strip: $($_.Exception.Message)" }
            $have = @()
        }

        $scopeReason = 'scoped to the named mailboxes'
        if (-not $scoped) { $scopeReason = 'no mailboxes named; tenant-wide' }
        elseif ($tooMany) {
            $scopeReason = "tenant-wide: $($Mailboxes.Count) recipients exceeds the scoping threshold of $TenantWideThreshold"
            Write-Host $scopeReason
        }
        elseif (-not $haveAny) {
            $scopeReason = 'tenant-wide: not one named mailbox resolved'
            Write-Host $scopeReason
        }
        $wantScopes = if ($effectiveScoped) { 'none' } else { 'allTenantMailboxes' }

        # Rebuild rather than repurpose when a reused search was built with a
        # different scope. Deleting invalidates the search id in any approval
        # card already sitting in Teams -- a purge from one of those then fails
        # 404, which is loud. A search that silently reports 0 because it is
        # still answering from a stale source collection is not loud, and it is
        # what closes a case as remediated while the mail is still there.
        if (-not $created -and $originalScopes -and $originalScopes -ne $wantScopes) {
            Write-Host "Search '$Name' was built as '$originalScopes' but needs '$wantScopes'; rebuilding it"
            Invoke-Graph -Method DELETE -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)" | Out-Null
            $search = Invoke-Graph -Method POST -Path "/security/cases/ediscoveryCases/$caseId/searches" -Body @{
                displayName      = $Name
                contentQuery     = $Query
                dataSourceScopes = 'allTenantMailboxes'
            }
            $created = $true
            $rebuilt = $true

            if ($effectiveScoped) {
                # Re-add the sources we established are safe (inactive ones are
                # already excluded from $have).
                foreach ($mbx in $have) {
                    try {
                        Invoke-Graph -Method POST `
                            -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/additionalSources" `
                            -Body @{ '@odata.type' = 'microsoft.graph.security.userSource'; email = $mbx } | Out-Null
                    }
                    catch { Write-Host "Could not re-add source '$mbx' after rebuild: $($_.Exception.Message)" }
                }
            }
        }

        Invoke-Graph -Method PATCH `
            -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)" `
            -Body @{ dataSourceScopes = $wantScopes } | Out-Null
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
        # Derived from what the search ACTUALLY ended up scoped to, not from what
        # was requested. Reporting 'mailboxes' for a search that quietly went
        # tenant-wide is how a card ends up describing a different search than
        # the one it ran.
        scope         = if ($effectiveScoped) { 'mailboxes' } else { 'all_tenant_mailboxes' }
        scope_reason  = $scopeReason
        rebuilt       = $rebuilt
        mailboxes     = if ($scoped) { @($Mailboxes) } else { @() }
        searched      = @($have)
        unresolved    = @($unresolved)
        inactive      = @($inactive)
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

function Invoke-GraphMailVerify {
    <#
      Ask the MAILBOX whether the message is still there, not eDiscovery.

      Demonstrated side by side on one mailbox, minutes apart: Graph returned an
      empty result for the message while an eDiscovery estimate on the same query
      reported 2 items remaining. The message was genuinely gone -- deleted, and
      confirmed absent from Inbox and Deleted Items. eDiscovery reports deleted
      mail as present, for hours.

      Every purge this worker ran actually worked. What kept failing was the
      verification, because it asked an index instead of the mailbox. This reads
      the same view Outlook shows and answers in about a second.

      Needs Mail.ReadBasic (application). Basic properties only -- subject, from,
      receivedDateTime -- so this cannot read anyone's message bodies. Filtering
      is on those properties for the same reason: $search reaches into bodies and
      is refused under ReadBasic.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Mailboxes,
        [Parameter(Mandatory)][string[]]$Senders,
        [string]$From,
        [string]$To
    )

    # A sender entry is either a full address or a bare domain, so matching is
    # done here rather than in $filter: endswith() on from/emailAddress/address
    # is rejected as an inefficient filter by Exchange's backend.
    function Test-SenderMatch([string]$addr, [string[]]$wanted) {
        if (-not $addr) { return $false }
        $a = $addr.ToLower()
        foreach ($w in $wanted) {
            $x = $w.ToLower().TrimStart('@')
            if ($a -eq $x) { return $true }
            if ($a.EndsWith("@$x")) { return $true }
            # sub-domain of a named domain, e.g. mail.example.com under example.com
            if ($a -match "@(.+\.)?$([regex]::Escape($x))$") { return $true }
        }
        return $false
    }

    $perMailbox = @()
    $total = 0

    foreach ($mbx in $Mailboxes) {
        $found = @()
        $err = $null
        try {
            $filter = @()
            if ($From) { $filter += "receivedDateTime ge $($From)T00:00:00Z" }
            if ($To) { $filter += "receivedDateTime le $($To)T23:59:59Z" }
            $qs = '$select=subject,receivedDateTime,from&$top=100'
            if ($filter.Count) { $qs = '$filter=' + [uri]::EscapeDataString(($filter -join ' and ')) + '&' + $qs }

            $path = "/users/$([uri]::EscapeDataString($mbx))/messages?$qs"
            $page = 0
            while ($path -and $page -lt 20) {
                $page++
                $resp = Invoke-Graph -Method GET -Path $path
                foreach ($m in $resp.value) {
                    # StrictMode turns a read of a MISSING property into a throw,
                    # and not every message carries 'from' -- drafts and some
                    # system items do not. Two mailboxes failed verification with
                    # "The property 'from' cannot be found on this object" purely
                    # because of this. Probe before reading, exactly as Invoke-Graph
                    # has to do for 'Response'.
                    $addr = $null
                    if ($m.PSObject.Properties.Name -contains 'from') {
                        $f = $m.from
                        if ($f -and ($f.PSObject.Properties.Name -contains 'emailAddress')) {
                            $ea = $f.emailAddress
                            if ($ea -and ($ea.PSObject.Properties.Name -contains 'address')) {
                                $addr = [string]$ea.address
                            }
                        }
                    }
                    if (Test-SenderMatch $addr $Senders) {
                        $found += [ordered]@{ subject = "$($m.subject)"; from = $addr; received = "$($m.receivedDateTime)" }
                    }
                }
                $next = $null
                if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = [string]$resp.'@odata.nextLink' }
                $path = if ($next) { $next -replace '^https://graph\.microsoft\.com/v1\.0', '' } else { $null }
            }
        }
        catch {
            # A mailbox we cannot read is NOT a clean mailbox. Record the failure
            # so the caller refuses to call the case verified.
            $err = $_.Exception.Message
            Write-Host "mail-verify: could not read '$mbx': $err"
        }

        $total += $found.Count
        $perMailbox += [ordered]@{
            mailbox   = $mbx
            remaining = if ($err) { $null } else { $found.Count }
            error     = $err
            messages  = @($found | Select-Object -First 5)
        }
    }

    $unreadable = @($perMailbox | Where-Object { $_.error })

    return @{
        action         = 'graph_mail_verify'
        measured_with  = 'Graph mail (the mailbox itself, not the eDiscovery index)'
        mailboxes      = @($perMailbox)
        remaining_items = $total
        unreadable     = @($unreadable | ForEach-Object { $_.mailbox })
        # Clean ONLY when every mailbox was readable and every one came back empty.
        verified_clean = ($total -eq 0 -and $unreadable.Count -eq 0 -and $Mailboxes.Count -gt 0)
        senders        = @($Senders)
        window         = "$From..$To"
    }
}

function Invoke-GraphPurgeVerify {
    <#
      Re-runs the estimate on a search AFTER its purge reported success, and
      reports what is still there.

      This exists because "the purge succeeded" and "the mail is gone" are not
      the same statement. purgeData returned status 'succeeded' at 100% on
      CS5016743 and CS5016745 while every message stayed exactly where it was --
      so a workflow that resolves the eSentire case on purge status alone closes
      tickets for remediation that never happened, and writes "should NOT be
      reopened" into the resolution notes while the phish sits in five inboxes.

      Slow on purpose: it blocks until Graph finishes the estimate, because a
      caller that gets an answer before the estimate completes learns nothing.
      Note the index trails deletions by minutes, so a non-zero count shortly
      after a purge is not proof of failure -- but zero IS proof of success.
    #>
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$SearchId,
        [int]$TimeoutSeconds = 900
    )

    # Verify with a FRESH search, never by re-estimating the one that was purged.
    #
    # Re-estimating the purged search reported remaining_items 0 and
    # verified_clean TRUE while the message was still in four mailboxes. The same
    # search reported 5 a few minutes later, unchanged. An estimate taken on a
    # search whose sources or scope were recently touched can be stale, and a
    # stale zero here closes an eSentire case as remediated.
    #
    # Every freshly created search measured tonight was correct; every reused or
    # mutated one was not. So this copies the query and scope onto a throwaway
    # search, measures that, and deletes it.
    $orig = Invoke-Graph -Method GET -Path "/security/cases/ediscoveryCases/$CaseId/searches/$SearchId"

    # PREFER THE MAILBOX. eDiscovery reported 2 items remaining for a message that
    # Graph confirmed was gone from the mailbox entirely, minutes apart, on the
    # same query. Every purge this worker ran worked; the verification was what
    # kept failing, because it asked the index instead of the mailbox. Only fall
    # back to an eDiscovery probe when there are no named mailboxes to read --
    # a tenant-wide search -- and say so in the result.
    $srcList = @()
    try {
        $srcResp = Invoke-Graph -Method GET `
            -Path "/security/cases/ediscoveryCases/$CaseId/searches/$SearchId/additionalSources"
        $srcList = @($srcResp.value | Where-Object { $_.email } | ForEach-Object { [string]$_.email })
    }
    catch { Write-Host "verify: could not list sources: $($_.Exception.Message)" }

    if ($srcList.Count -gt 0) {
        $q = [string]$orig.contentQuery
        # KQL keywords are case-INSENSITIVE, and the query is CALLER-supplied --
        # n8n, a manual curl, and this worker each write it differently. A
        # case-sensitive 'From:"..."' matched nothing against a lowercase
        # 'from:"..."' query, so $senders came back empty and this fell through
        # to the eDiscovery probe: the exact ask-the-index-not-the-mailbox answer
        # this whole function exists to avoid. It reported 7 items remaining on a
        # mailbox that had just been purged clean (Halo 0050661). Match
        # case-insensitively, quoted or bare, across the sender keywords KQL
        # accepts.
        $senders = @(
            [regex]::Matches($q, '(?i)(?:from|sender|participants)\s*:\s*"([^"]+)"') |
                ForEach-Object { $_.Groups[1].Value }
        )
        if ($senders.Count -eq 0) {
            $senders = @(
                [regex]::Matches($q, '(?i)(?:from|sender|participants)\s*:\s*([^\s()"]+)') |
                    ForEach-Object { $_.Groups[1].Value }
            )
        }
        $senders = @($senders | Where-Object { $_ } | Select-Object -Unique)
        $win = [regex]::Match($q, '(?i)received\s*:\s*(\d{4}-\d{2}-\d{2})\.\.(\d{4}-\d{2}-\d{2})')
        $wFrom = if ($win.Success) { $win.Groups[1].Value } else { $null }
        $wTo = if ($win.Success) { $win.Groups[2].Value } else { $null }

        if ($senders.Count -gt 0) {
            $r = Invoke-GraphMailVerify -Mailboxes $srcList -Senders $senders -From $wFrom -To $wTo
            $r['case_id'] = $CaseId
            $r['search_id'] = $SearchId
            return $r
        }
        Write-Host "verify: no senders parsed from contentQuery, falling back to an eDiscovery probe"
    }

    $verifyName = "verify-$SearchId-$([guid]::NewGuid().ToString('N').Substring(0,8))"

    $probe = Invoke-Graph -Method POST -Path "/security/cases/ediscoveryCases/$CaseId/searches" -Body @{
        displayName      = $verifyName
        contentQuery     = $orig.contentQuery
        dataSourceScopes = 'allTenantMailboxes'
    }

    try {
        # Mirror the original's scope. A scoped original is verified scoped (fast);
        # a tenant-wide one is verified tenant-wide.
        if ($orig.dataSourceScopes -eq 'none') {
            $srcs = Invoke-Graph -Method GET `
                -Path "/security/cases/ediscoveryCases/$CaseId/searches/$SearchId/additionalSources"
            $added = 0
            foreach ($src in $srcs.value) {
                if (-not $src.email) { continue }
                # Never copy an inactive mailbox: one of them collapses the whole
                # estimate to a single item, which would fake a clean result.
                if ($src.displayName -match '\(Inactive Mailbox\)') { continue }
                try {
                    Invoke-Graph -Method POST `
                        -Path "/security/cases/ediscoveryCases/$CaseId/searches/$($probe.id)/additionalSources" `
                        -Body @{ '@odata.type' = 'microsoft.graph.security.userSource'; email = $src.email } | Out-Null
                    $added++
                }
                catch { Write-Host "verify: could not copy source '$($src.email)': $($_.Exception.Message)" }
            }
            if ($added -gt 0) {
                Invoke-Graph -Method PATCH `
                    -Path "/security/cases/ediscoveryCases/$CaseId/searches/$($probe.id)" `
                    -Body @{ dataSourceScopes = 'none' } | Out-Null
            }
        }

        Invoke-Graph -Method POST `
            -Path "/security/cases/ediscoveryCases/$CaseId/searches/$($probe.id)/estimateStatistics" | Out-Null

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $op = $null
        do {
            Start-Sleep -Seconds 15
            $op = Invoke-Graph -Method GET `
                -Path "/security/cases/ediscoveryCases/$CaseId/searches/$($probe.id)/lastEstimateStatisticsOperation"
        } while ($op.status -in @('notStarted', 'running', 'submitted') -and (Get-Date) -lt $deadline)
    }
    finally {
        # The probe is disposable and must not accumulate in the case.
        try { Invoke-Graph -Method DELETE -Path "/security/cases/ediscoveryCases/$CaseId/searches/$($probe.id)" | Out-Null }
        catch { Write-Host "verify: could not delete probe search $($probe.id): $($_.Exception.Message)" }
    }

    $remaining = if ($op.status -eq 'succeeded') { [int]$op.indexedItemCount } else { $null }

    return @{
        action              = 'graph_ediscovery_purge_verify'
        case_id             = $CaseId
        search_id           = $SearchId
        measured_with       = 'fresh probe search (the purged search is never re-estimated)'
        status              = $op.status
        remaining_items     = $remaining
        remaining_mailboxes = if ($op.status -eq 'succeeded') { [int]$op.mailboxCount } else { $null }
        # The ONLY field a caller should gate on. Null status or a timeout must
        # never read as clean.
        verified_clean      = ($op.status -eq 'succeeded' -and $remaining -eq 0)
        note                = 'The eDiscovery index trails deletions, so re-check before treating a non-zero count as failure.'
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
