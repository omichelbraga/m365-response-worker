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
        [string]$ApiVersion = 'v1.0'
    )
    $token = Get-GraphToken
    $uri = "https://graph.microsoft.com/$ApiVersion$Path"
    $headers = @{ Authorization = "Bearer $token" }
    if ($null -ne $Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers `
            -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json'
    }
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
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
        [int]$TimeoutSeconds = 600
    )

    if (-not $Name) { $Name = "auto-$([guid]::NewGuid().ToString('N').Substring(0,12))" }
    $caseId = Get-WorkerCase

    $search = Invoke-Graph -Method POST -Path "/security/cases/ediscoveryCases/$caseId/searches" -Body @{
        displayName      = $Name
        contentQuery     = $Query
        dataSourceScopes = 'allTenantMailboxes'
    }

    Invoke-Graph -Method POST `
        -Path "/security/cases/ediscoveryCases/$caseId/searches/$($search.id)/estimateStatistics" | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $op = $null
    do {
        Start-Sleep -Seconds 5
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

    Invoke-Graph -Method POST `
        -Path "/security/cases/ediscoveryCases/$CaseId/searches/$SearchId/purgeData" `
        -Body @{ purgeType = $graphType; purgeAreas = 'mailboxes' } | Out-Null

    return @{
        action       = 'graph_ediscovery_purge'
        case_id      = $CaseId
        search_id    = $SearchId
        purge_type   = $PurgeType
        graph_type   = $graphType
        irreversible = ($PurgeType -eq 'HardDelete')
        status       = 'submitted'
        note         = 'purgeData is asynchronous; Graph returns 202 with no body on acceptance.'
    }
}
