# M365 response actions: sender blocking and Purview search/purge.
#
# Two separate connections are used on purpose:
#   * Connect-ExchangeOnline  -> Tenant Allow/Block List (sender blocks)
#   * Connect-IPPSSession     -> compliance search + purge
#
# The IPPS session MUST be opened with -EnableSearchOnlySession or
# New-ComplianceSearchAction -Purge fails. That is not obvious from the error.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ExoCertificate {
    <#
      Loads the app-only auth certificate from a mounted PFX.
      -CertificateThumbprint is Windows-only, so on Linux the certificate has to
      be passed as an X509Certificate2 object rather than a store reference.
    #>
    $path = $env:EXO_CERT_PATH
    if (-not $path) { throw 'EXO_CERT_PATH is not set.' }
    if (-not (Test-Path $path)) { throw "Certificate not found at $path" }

    $password = $env:EXO_CERT_PASSWORD
    if ($password) {
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path, $secure)
    }
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
}

function Connect-Exo {
    param([switch]$SearchOnly)

    $cert = Get-ExoCertificate
    $appId = $env:EXO_APP_ID
    $org = $env:EXO_ORGANIZATION
    if (-not $appId) { throw 'EXO_APP_ID is not set.' }
    if (-not $org) { throw 'EXO_ORGANIZATION is not set.' }

    if ($SearchOnly) {
        # -EnableSearchOnlySession is documented as required for purge, but that
        # guidance is for delegated sessions: with app-only certificate auth the
        # flag makes Connect-IPPSSession fail outright with "UnAuthorized", while
        # the identical connection without it succeeds. Verified against this
        # tenant via /diag (scc_plain ok, scc_search_only UnAuthorized).
        # Set EXO_SEARCH_ONLY_SESSION=1 to re-enable if that ever changes.
        $useSearchOnly = ($env:EXO_SEARCH_ONLY_SESSION -in @('1', 'true', 'yes'))
        if ($useSearchOnly) {
            Connect-IPPSSession -Certificate $cert -AppId $appId -Organization $org `
                -EnableSearchOnlySession -ShowBanner:$false | Out-Null
        }
        else {
            Connect-IPPSSession -Certificate $cert -AppId $appId -Organization $org `
                -ShowBanner:$false | Out-Null
        }
    }
    else {
        Connect-ExchangeOnline -Certificate $cert -AppId $appId -Organization $org `
            -ShowBanner:$false | Out-Null
    }
}

function Disconnect-Exo {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
}

function Invoke-Diagnostics {
    <#
      Read-only. Tests the three connection modes independently so a failure can
      be attributed to a specific layer rather than the single "UnAuthorized"
      that Connect-IPPSSession surfaces for everything.

        exchange_online  -> governed by the Entra Exchange Administrator role
        scc_plain        -> governed by Purview role group membership
        scc_search_only  -> as above, plus -EnableSearchOnlySession (needed to purge)

      If exchange_online succeeds and both scc_* fail, the identity is fine and
      the Purview role group membership is the problem.
    #>
    $results = [ordered]@{}

    try {
        Connect-Exo
        $org = (Get-OrganizationConfig).Name
        $results['exchange_online'] = @{ ok = $true; organization = "$org" }
    }
    catch { $results['exchange_online'] = @{ ok = $false; error = $_.Exception.Message } }
    finally { Disconnect-Exo }

    try {
        $cert = Get-ExoCertificate
        Connect-IPPSSession -Certificate $cert -AppId $env:EXO_APP_ID `
            -Organization $env:EXO_ORGANIZATION -ShowBanner:$false | Out-Null
        $n = @(Get-ComplianceSearch -ResultSize 1).Count
        $results['scc_plain'] = @{ ok = $true; searches_visible = $n }
    }
    catch { $results['scc_plain'] = @{ ok = $false; error = $_.Exception.Message } }
    finally { Disconnect-Exo }

    try {
        Connect-Exo -SearchOnly
        $n = @(Get-ComplianceSearch -ResultSize 1).Count
        $results['scc_search_only'] = @{ ok = $true; searches_visible = $n }
    }
    catch { $results['scc_search_only'] = @{ ok = $false; error = $_.Exception.Message } }
    finally { Disconnect-Exo }

    return @{
        action       = 'diagnostics'
        app_id       = $env:EXO_APP_ID
        organization = $env:EXO_ORGANIZATION
        results      = $results
    }
}

function Test-MailboxState {
    <#
      Ask Exchange what each address actually is, BEFORE any eDiscovery search is
      built.

      This exists because the worker used to discover an inactive mailbox the
      hard way: create the source, read the displayName Graph hands back, notice
      "(Inactive Mailbox)", then unpick it. That is backwards -- it has to make
      the mistake before it can detect it -- and one inactive source silently
      collapses the estimate for every other mailbox in the same search (four
      active mailboxes holding one message each estimated as 1).

      Knowing up front means inactive mailboxes are simply never added, the
      estimate is never corrupted, and the card can say plainly which addresses
      were searched and which were not.
    #>
    param([Parameter(Mandatory)][string[]]$Mailboxes)

    Connect-Exo
    try {
        $results = @()
        foreach ($mbx in $Mailboxes) {
            $rec = [ordered]@{ email = $mbx; exists = $false; inactive = $false; searchable = $false }
            try {
                $m = Get-Mailbox -Identity $mbx -ErrorAction Stop
                $rec.exists = $true
                # IsInactiveMailbox is the Exchange flag for a mailbox whose user
                # is gone but which is retained by a hold.
                $rec.inactive = [bool]$m.IsInactiveMailbox
                $rec.searchable = -not $rec.inactive
                $rec.display = $m.DisplayName
                $rec.type = "$($m.RecipientTypeDetails)"
                $rec.primary = "$($m.PrimarySmtpAddress)"
                # HOLDS. A purge cannot permanently remove content from a mailbox
                # under hold: the item is moved to Recoverable Items\Purges and
                # retained for compliance, where eDiscovery STILL FINDS IT. So a
                # post-purge estimate never reaches zero on a held mailbox, and a
                # verification that demands zero can never pass. That is not a
                # failed purge - the user cannot see the message - but it is
                # indistinguishable from one if you only look at the count.
                $rec.litigation_hold = [bool]$m.LitigationHoldEnabled
                $rec.delay_hold = [bool]$m.DelayHoldApplied
                $rec.delay_release_hold = [bool]$m.DelayReleaseHoldApplied
                $rec.compliance_tag_hold = [bool]$m.ComplianceTagHoldApplied
                $rec.in_place_holds = @($m.InPlaceHolds)
                $rec.retention_policy = "$($m.RetentionPolicy)"
                $rec.on_hold = ($rec.litigation_hold -or $rec.delay_hold -or $rec.delay_release_hold -or $rec.compliance_tag_hold -or (@($m.InPlaceHolds).Count -gt 0))
            }
            catch {
                # Not a mailbox at all: a distribution list, an alias that does
                # not resolve, or a departed user. Either way it cannot be a
                # scoped source, and saying so here is cheaper than a 400 later.
                $rec.error = $_.Exception.Message
                # An inactive mailbox is only returned when asked for explicitly.
                try {
                    $im = Get-Mailbox -Identity $mbx -InactiveMailboxOnly -ErrorAction Stop
                    if ($im) {
                        $rec.exists = $true
                        $rec.inactive = $true
                        $rec.display = $im.DisplayName
                        $rec.type = "$($im.RecipientTypeDetails)"
                        $rec.error = $null
                    }
                }
                catch { }
            }
            $results += $rec
        }
        return @{ action = 'mailbox_state'; results = $results }
    }
    finally { Disconnect-Exo }
}

function Get-RecoverableCopies {
    <#
      Lists what is sitting in a mailbox's Recoverable Items.

      eDiscovery counts Recoverable Items, so a message that was SOFT deleted is
      still counted by an estimate even though the user cannot see it. That makes
      a post-purge verification report "still there" for mail that is, from the
      user's point of view, gone -- and the case then never closes. This is how
      to tell the two apart.

      Read through GRAPH rather than Get-RecoverableItems. That cmdlet is gated
      behind the Mailbox Import Export RBAC role, and EXO omits cmdlets the
      connecting principal holds no role for instead of failing the call -- so
      under app-only certificate auth it surfaced as CommandNotFoundException on
      every request, which reads like a typo rather than a missing role and cost
      an investigation to run down (Halo 0050661). Graph needs only the
      Mail.ReadBasic this worker already has, and shows the same view.
    #>
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [string]$SubjectContains,
        [string]$From
    )

    $enc = [uri]::EscapeDataString($Mailbox)
    $out = @()
    $scanned = 0
    $unreadable = @()

    # Deletions is the dumpster a user can still recover from. Purges is where a
    # hard delete leaves the item when a hold keeps it alive -- which is exactly
    # this mailbox's case (compliance_tag_hold). A caller asking "is it really
    # gone" needs both. Purges only exists on a held mailbox, so a failure there
    # is a normal answer for an unheld one, not an error worth throwing over.
    foreach ($folder in @('recoverableitemsdeletions', 'recoverableitemspurges')) {
        $url = "/users/$enc/mailFolders/$folder/messages?`$select=subject,from,receivedDateTime&`$top=100"
        $pages = 0
        while ($url -and $pages -lt 10) {
            try { $resp = Invoke-Graph -Method GET -Path $url }
            catch {
                $unreadable += $folder
                Write-Host "recoverable: $folder unreadable on ${Mailbox}: $($_.Exception.Message)"
                break
            }

            foreach ($m in @($resp.value)) {
                $scanned++
                # StrictMode: reading a property that is absent THROWS, and Graph
                # omits 'from' on drafts and some system items. Probe first.
                $addr = ''
                if ($m.PSObject.Properties.Name -contains 'from' -and $m.from) {
                    $f = $m.from
                    if ($f.PSObject.Properties.Name -contains 'emailAddress' -and $f.emailAddress) {
                        $addr = [string]$f.emailAddress.address
                    }
                }
                $subj = if ($m.PSObject.Properties.Name -contains 'subject') { [string]$m.subject } else { '' }

                if ($From -and ($addr -notlike "*$From*")) { continue }
                if ($SubjectContains -and ($subj -notlike "*$SubjectContains*")) { continue }

                $out += [ordered]@{
                    subject  = $subj
                    from     = $addr
                    received = "$($m.receivedDateTime)"
                    folder   = $folder
                }
            }

            $next = $null
            if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = [string]$resp.'@odata.nextLink' }
            $url = if ($next) { $next -replace '^https://graph\.microsoft\.com/v1\.0', '' } else { $null }
            $pages++
        }
    }

    return @{
        action        = 'recoverable_items'
        mailbox       = $Mailbox
        count         = $out.Count
        scanned       = $scanned
        items         = $out
        unreadable    = @($unreadable | Select-Object -Unique)
        measured_with = 'graph mail (recoverableitemsdeletions + recoverableitemspurges)'
    }
}

function Invoke-BlockSender {
    <#
      Adds a sender to the Tenant Allow/Block List. There is no REST equivalent:
      the Graph tiIndicator entity was retired in April 2026, so this cmdlet is
      the only supported path.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Senders,
        [string]$Notes = 'Blocked by automated eSentire response workflow',
        [int]$ExpirationDays = 0
    )

    Connect-Exo
    try {
        $results = @()
        foreach ($sender in $Senders) {
            $params = @{
                ListType = 'Sender'
                Block    = $true
                Entries  = @($sender)
                Notes    = $Notes
            }
            if ($ExpirationDays -gt 0) {
                $params['ExpirationDate'] = (Get-Date).ToUniversalTime().AddDays($ExpirationDays)
            }
            else {
                $params['NoExpiration'] = $true
            }

            try {
                $entry = New-TenantAllowBlockListItems @params
                $results += [ordered]@{
                    sender  = $sender
                    status  = 'blocked'
                    id      = $entry.Identity
                    expires = if ($ExpirationDays -gt 0) { $params['ExpirationDate'].ToString('o') } else { 'never' }
                }
            }
            catch {
                # An existing entry is not a failure for our purposes -- the desired
                # end state (sender is blocked) already holds. Exchange words this
                # inconsistently: "already exists" in some paths, "Duplicate value"
                # in others. Matching only the first reported a re-run of an
                # already-successful block as a failure.
                $msg = $_.Exception.Message
                $already = $msg -match 'already exist|duplicate value|duplicate entry'
                $results += [ordered]@{
                    sender = $sender
                    status = if ($already) { 'already_blocked' } else { 'failed' }
                    error  = $msg
                }
            }
        }
        return @{ action = 'block_sender'; results = $results }
    }
    finally { Disconnect-Exo }
}

function Invoke-ComplianceSearch {
    <#
      Creates and runs a compliance search, then returns the item count and the
      per-mailbox breakdown. This is the evidence shown to a human before any
      destructive action.

      The same named search is later handed to the purge, so what was approved is
      exactly what gets deleted -- estimating with one mechanism and purging with
      another risks the two sets diverging.
    #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$Name,
        [string[]]$Mailboxes,
        [int]$TimeoutSeconds = 600
    )

    if (-not $Name) { $Name = "auto-$([guid]::NewGuid().ToString('N').Substring(0,12))" }

    Connect-Exo -SearchOnly
    try {
        $params = @{ Name = $Name; ContentMatchQuery = $Query }
        if ($Mailboxes -and $Mailboxes.Count -gt 0) {
            $params['ExchangeLocation'] = $Mailboxes
        }
        else {
            $params['ExchangeLocation'] = 'All'
        }

        New-ComplianceSearch @params | Out-Null
        Start-ComplianceSearch -Identity $Name | Out-Null

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            Start-Sleep -Seconds 5
            $search = Get-ComplianceSearch -Identity $Name
        } while ($search.Status -ne 'Completed' -and (Get-Date) -lt $deadline)

        if ($search.Status -ne 'Completed') {
            throw "Search '$Name' did not complete within $TimeoutSeconds s (status: $($search.Status))."
        }

        # SearchStatistics is a JSON string; parse it for the per-mailbox breakdown.
        $locations = @()
        if ($search.SearchStatistics) {
            try {
                $stats = $search.SearchStatistics | ConvertFrom-Json
                foreach ($row in $stats.ExchangeBinding.Sources) {
                    if ($row.ContentItems -gt 0) {
                        $locations += [ordered]@{
                            mailbox = $row.Name
                            items   = [int]$row.ContentItems
                            size    = [int64]$row.ContentSize
                        }
                    }
                }
            }
            catch {
                # Statistics shape varies between tenants; the total below is still valid.
                $locations = @()
            }
        }

        return @{
            action      = 'compliance_search'
            search_name = $Name
            query       = $Query
            status      = $search.Status
            total_items = [int]$search.Items
            total_size  = [int64]$search.Size
            locations   = $locations
            note        = 'Purge removes a maximum of 10 items per mailbox per action.'
        }
    }
    finally { Disconnect-Exo }
}

function Invoke-CompliancePurge {
    param(
        [Parameter(Mandatory)][string]$SearchName,
        [ValidateSet('SoftDelete', 'HardDelete')][string]$PurgeType = 'SoftDelete'
    )

    Connect-Exo -SearchOnly
    try {
        $search = Get-ComplianceSearch -Identity $SearchName
        if ($search.Status -ne 'Completed') {
            throw "Search '$SearchName' is '$($search.Status)', not Completed. Refusing to purge."
        }

        $action = New-ComplianceSearchAction -SearchName $SearchName -Purge `
            -PurgeType $PurgeType -Confirm:$false

        return @{
            action           = 'compliance_purge'
            search_name      = $SearchName
            purge_type       = $PurgeType
            action_name      = $action.Name
            status           = $action.Status
            items_in_search  = [int]$search.Items
            irreversible     = ($PurgeType -eq 'HardDelete')
        }
    }
    finally { Disconnect-Exo }
}

function Get-PurgeStatus {
    param([Parameter(Mandatory)][string]$ActionName)

    Connect-Exo -SearchOnly
    try {
        $a = Get-ComplianceSearchAction -Identity $ActionName -Details
        return @{
            action      = 'purge_status'
            action_name = $ActionName
            status      = $a.Status
            results     = $a.Results
        }
    }
    finally { Disconnect-Exo }
}
