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
        # -EnableSearchOnlySession is required for purge actions to run at all.
        Connect-IPPSSession -Certificate $cert -AppId $appId -Organization $org `
            -EnableSearchOnlySession -ShowBanner:$false | Out-Null
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
                # end state (sender is blocked) already holds.
                $msg = $_.Exception.Message
                $already = $msg -match 'already exist'
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
