# Minimal HTTP front end over the M365 response actions.
#
# Uses System.Net.HttpListener rather than a web framework so the image has no
# dependencies beyond PowerShell and ExchangeOnlineManagement.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/actions.ps1"
. "$PSScriptRoot/graph.ps1"

$Port = if ($env:WORKER_PORT) { $env:WORKER_PORT } else { '8080' }
$Token = $env:WORKER_TOKEN

if (-not $Token) {
    Write-Warning 'WORKER_TOKEN is not set: this worker will accept UNAUTHENTICATED requests that can delete mail. Do not run it this way.'
}

function Write-Json {
    param($Response, $Body, [int]$Status = 200)
    $json = ($Body | ConvertTo-Json -Depth 12)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $Status
    $Response.ContentType = 'application/json'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Read-Body {
    param($Request)
    if (-not $Request.HasEntityBody) { return @{} }
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $raw = $reader.ReadToEnd()
    $reader.Close()
    if (-not $raw.Trim()) { return @{} }
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Test-Auth {
    param($Request)
    if (-not $Token) { return $true }
    $header = $Request.Headers['Authorization']
    if (-not $header) { return $false }
    $expected = "Bearer $Token"
    # Constant-time-ish compare to avoid leaking the token through timing.
    if ($header.Length -ne $expected.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $header.Length; $i++) {
        $diff = $diff -bor ([int][char]$header[$i] -bxor [int][char]$expected[$i])
    }
    return ($diff -eq 0)
}

# --- Background search jobs -------------------------------------------------
#
# HttpListener.GetContext() serves one request at a time, so anything slow on
# the request thread takes the whole worker down with it -- including /health,
# which is how this container kept flapping to unhealthy.
#
# A tenant-wide eDiscovery estimate was measured at 730 s against this tenant.
# Nothing sane waits that long on an HTTP request, so /search hands the work to
# a background runspace and answers 202 immediately; the caller polls
# /search-status. The request thread then never blocks for more than a moment.

$script:Jobs = [hashtable]::Synchronized(@{})
# 8 rather than 4: a per-mailbox fan-out over a handful of named recipients
# plus the tenant-wide sweep should all run at once, not queue behind each other.
$script:Pool = [runspacefactory]::CreateRunspacePool(1, 8)
$script:Pool.Open()

function Start-VerifyJob {
    <#
      Same background-job treatment as a search, and for the same reason: a
      post-purge estimate takes minutes, and GetContext() serves one request at
      a time. A synchronous /purge-verify held the only request thread for the
      whole estimate, so /health stopped answering and every other caller got
      "connection cannot be established" -- exactly the failure the comment
      above this section warns about. Answer 202, poll /search-status.
    #>
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$SearchId
    )

    $jobId = [guid]::NewGuid().ToString('N').Substring(0, 16)
    $script:Jobs[$jobId] = @{
        job_id    = $jobId
        status    = 'running'
        action    = 'graph_ediscovery_purge_verify'
        case_id   = $CaseId
        search_id = $SearchId
        started   = (Get-Date).ToUniversalTime().ToString('o')
    }

    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:Pool
    [void]$ps.AddScript({
        param($ScriptRoot, $Jobs, $JobId, $CaseId, $SearchId)
        try {
            . "$ScriptRoot/actions.ps1"
            . "$ScriptRoot/graph.ps1"
            $result = Invoke-GraphPurgeVerify -CaseId $CaseId -SearchId $SearchId
            $result['job_id'] = $JobId
            $result['finished'] = (Get-Date).ToUniversalTime().ToString('o')
            $Jobs[$JobId] = $result
        }
        catch {
            # verified_clean must be present and FALSE on failure. A missing key
            # would leave the caller's gate reading undefined, and an undefined
            # that is not 'true' is only safe by accident.
            $Jobs[$JobId] = @{
                job_id         = $JobId
                status         = 'failed'
                action         = 'graph_ediscovery_purge_verify'
                case_id        = $CaseId
                search_id      = $SearchId
                verified_clean = $false
                error          = $_.Exception.Message
                finished       = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
    }).AddArgument($PSScriptRoot).AddArgument($script:Jobs).AddArgument($jobId).AddArgument($CaseId).AddArgument($SearchId) | Out-Null

    [void]$ps.BeginInvoke()
    return $script:Jobs[$jobId]
}

function Start-SearchJob {
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$Name,
        [string[]]$Mailboxes,
        [int]$TenantWideThreshold = 25
    )

    # A search is identified by its NAME, and Invoke-GraphSearch REUSES the Graph
    # search of that name rather than creating a second one. So two jobs running
    # the same name are not two searches -- they are two callers mutating one
    # search object at the same time. Graph answers the loser with
    #   400 "Committed in-progress Source collection <id>, can not be updated"
    # and that whole run reports SEARCH FAILED.
    #
    # This is not hypothetical: a manual Poller run and the scheduled tick 96
    # seconds later processed CS5016743 and CS5016745 together, and every search
    # in the second run died that way. Two cards reached Teams per case, one
    # usable and one broken.
    #
    # Returning the IN-FLIGHT job rather than an error is deliberate: the second
    # caller wanted the estimate for that exact search, and that is precisely
    # what the running job will produce. Both callers poll the same job_id and
    # get the same answer.
    if ($Name) {
        $existing = $null
        foreach ($k in @($script:Jobs.Keys)) {
            $j = $script:Jobs[$k]
            if ($j -and $j['status'] -eq 'running' -and $j['name'] -eq $Name) { $existing = $j; break }
        }
        if ($existing) {
            Write-Host "Search '$Name' is already running as job $($existing['job_id']); returning it instead of starting a second."
            $copy = @{}
            foreach ($k in $existing.Keys) { $copy[$k] = $existing[$k] }
            $copy['deduped'] = $true
            $copy['note'] = 'A search with this name was already running; this is that job. Two callers mutating one Graph search is what produces "Committed in-progress Source collection".'
            return $copy
        }
    }

    $jobId = [guid]::NewGuid().ToString('N').Substring(0, 16)
    $script:Jobs[$jobId] = @{
        job_id    = $jobId
        status    = 'running'
        query     = $Query
        name      = $Name
        scope     = if ($Mailboxes -and $Mailboxes.Count -gt 0) { 'mailboxes' } else { 'all_tenant_mailboxes' }
        mailboxes = @($Mailboxes)
        started   = (Get-Date).ToUniversalTime().ToString('o')
    }

    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:Pool
    [void]$ps.AddScript({
        param($ScriptRoot, $Jobs, $JobId, $Query, $Name, $Mailboxes, $Threshold)
        # A fresh runspace shares no state with the server, so the modules have
        # to be dot-sourced again. Environment variables are process-wide and
        # come across on their own.
        try {
            . "$ScriptRoot/actions.ps1"
            . "$ScriptRoot/graph.ps1"
            $result = if ($Mailboxes -and $Mailboxes.Count -gt 0) {
                Invoke-GraphSearch -Query $Query -Name $Name -Mailboxes $Mailboxes -TenantWideThreshold $Threshold
            }
            else {
                Invoke-GraphSearch -Query $Query -Name $Name
            }
            $result['job_id'] = $JobId
            $result['finished'] = (Get-Date).ToUniversalTime().ToString('o')
            $Jobs[$JobId] = $result
        }
        catch {
            # Keep `name` on the failure too. Callers correlate a job back to the
            # work that requested it by search name; without it a failed job is
            # an orphan and gets silently dropped downstream.
            $Jobs[$JobId] = @{
                job_id      = $JobId
                status      = 'failed'
                query       = $Query
                name        = $Name
                search_name = $Name
                mailboxes   = @($Mailboxes)
                error       = $_.Exception.Message
                detail      = ($_.Exception.ToString() -split "`n" | Select-Object -First 10) -join ' | '
                finished    = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
    }).AddArgument($PSScriptRoot).AddArgument($script:Jobs).AddArgument($jobId).AddArgument($Query).AddArgument($Name).AddArgument($Mailboxes).AddArgument($TenantWideThreshold) | Out-Null

    [void]$ps.BeginInvoke()
    return $script:Jobs[$jobId]
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()
Write-Host "m365-response-worker listening on :$Port (auth: $(if ($Token) { 'bearer' } else { 'NONE' }))"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.AbsolutePath.TrimEnd('/')
    if (-not $path) { $path = '/' }

    try {
        # /health is deliberately unauthenticated and never touches Exchange, so an
        # expired certificate cannot make Docker restart-loop a healthy container.
        if ($path -eq '/health' -and $request.HttpMethod -eq 'GET') {
            Write-Json $response @{
                status       = 'ok'
                auth         = if ($Token) { 'bearer' } else { 'none' }
                app_id       = if ($env:EXO_APP_ID) { 'set' } else { 'missing' }
                organization = if ($env:EXO_ORGANIZATION) { $env:EXO_ORGANIZATION } else { 'missing' }
                certificate  = if ($env:EXO_CERT_PATH -and (Test-Path $env:EXO_CERT_PATH)) { 'present' } else { 'missing' }
                jobs_total   = $script:Jobs.Count
                jobs_running = @($script:Jobs.Values | Where-Object { $_['status'] -eq 'running' }).Count
            }
            continue
        }

        if (-not (Test-Auth $request)) {
            Write-Json $response @{ error = 'unauthorized' } 401
            continue
        }

        $body = Read-Body $request

        switch ("$($request.HttpMethod) $path") {

            'GET /diag' {
                Write-Json $response (Invoke-Diagnostics)
                break
            }

            'POST /block-sender' {
                # Index rather than dot-access: under StrictMode a missing hashtable
                # key thrown as a property error would surface as a 500, not a 400.
                if (-not $body['senders']) { Write-Json $response @{ error = 'senders is required' } 400; break }
                $result = Invoke-BlockSender `
                    -Senders ([string[]]$body['senders']) `
                    -Notes ($body['notes'] ?? 'Blocked by automated eSentire response workflow') `
                    -ExpirationDays ([int]($body['expiration_days'] ?? 0))
                Write-Json $response $result
                break
            }

            'POST /search' {
                if (-not $body['query']) { Write-Json $response @{ error = 'query (KQL) is required' } 400; break }
                # Omit mailboxes for the tenant-wide sweep. Pass one address to
                # learn whether that specific mailbox holds the message --
                # estimateStatistics never names the mailboxes it counted.
                $mbx = if ($body['mailboxes']) { [string[]]$body['mailboxes'] } else { @() }
                # Optional. Above this many recipients the search goes tenant-wide
                # instead of creating a source per mailbox.
                $thr = if ($body['tenant_wide_threshold']) { [int]$body['tenant_wide_threshold'] } else { 25 }
                $job = Start-SearchJob -Query $body['query'] -Name $body['name'] -Mailboxes $mbx -TenantWideThreshold $thr
                Write-Json $response $job 202
                break
            }

            'GET /search-status' {
                $jobId = $request.QueryString['job_id']
                if (-not $jobId) { Write-Json $response @{ error = 'job_id is required' } 400; break }
                if (-not $script:Jobs.ContainsKey($jobId)) {
                    # Jobs are in memory only, so a restart loses them. Say that
                    # rather than let a caller read 404 as "still running".
                    Write-Json $response @{ error = 'unknown job_id (jobs do not survive a worker restart)'; job_id = $jobId } 404
                    break
                }
                Write-Json $response $script:Jobs[$jobId]
                break
            }

            'GET /searches' {
                Write-Json $response @{ action = 'list_jobs'; count = $script:Jobs.Count; jobs = @($script:Jobs.Values) }
                break
            }

            'POST /purge' {
                # case_id and search_id come straight back from /search, so the
                # purge acts on exactly the set whose counts were approved.
                if (-not $body['case_id'] -or -not $body['search_id']) {
                    Write-Json $response @{ error = 'case_id and search_id are required (both returned by /search)' } 400; break
                }
                $type = $body['purge_type'] ?? 'SoftDelete'
                if ($type -notin @('SoftDelete', 'HardDelete')) {
                    Write-Json $response @{ error = 'purge_type must be SoftDelete or HardDelete' } 400; break
                }
                Write-Json $response (Invoke-GraphPurge -CaseId $body['case_id'] -SearchId $body['search_id'] -PurgeType $type)
                break
            }

            'GET /purge-status' {
                $caseId = $request.QueryString['case_id']
                $opId = $request.QueryString['operation_id']
                if (-not $caseId -or -not $opId) {
                    Write-Json $response @{ error = 'case_id and operation_id are required (both returned by /purge)' } 400; break
                }
                Write-Json $response (Get-GraphPurgeStatus -CaseId $caseId -OperationId $opId)
                break
            }

            # Asynchronous, like /search: answers 202 with a job_id and runs the
            # estimate in a background runspace. Poll /search-status?job_id=...
            # An earlier synchronous version blocked the single request thread
            # for the whole estimate and took the worker offline.
            'POST /purge-verify' {
                $caseId = $body['case_id']
                $searchId = $body['search_id']
                if (-not $caseId -or -not $searchId) {
                    Write-Json $response @{ error = 'case_id and search_id are required' } 400; break
                }
                Write-Json $response (Start-VerifyJob -CaseId $caseId -SearchId $searchId) 202
                break
            }

            'GET /purge-verify' {
                Write-Json $response @{
                    error = 'purge-verify is asynchronous: POST {case_id, search_id} for a job_id, then poll /search-status?job_id=...'
                } 405
                break
            }

            default {
                Write-Json $response @{ error = 'not found'; path = $path } 404
            }
        }
    }
    catch {
        # Connect-ExchangeOnline / Connect-IPPSSession collapse a lot of distinct
        # failures into a bare "UnAuthorized", so surface the whole error record.
        # Without the inner exception and category there is nothing to act on.
        $err = $_
        Write-Host "ERROR $path : $($err.Exception.Message)"
        try {
            Write-Json $response @{
                error     = $err.Exception.Message
                type      = $err.Exception.GetType().FullName
                inner     = if ($err.Exception.InnerException) { $err.Exception.InnerException.Message } else { $null }
                category  = $err.CategoryInfo.ToString()
                target    = $err.TargetObject
                detail    = ($err.Exception.ToString() -split "`n" | Select-Object -First 20) -join ' | '
                stack     = ($err.ScriptStackTrace -split "`n" | Select-Object -First 6) -join ' | '
                path      = $path
            } 500
        }
        catch { }
    }
}
