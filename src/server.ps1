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
                Write-Json $response (Invoke-GraphSearch -Query $body['query'] -Name $body['name'])
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
                $name = $request.QueryString['action_name']
                if (-not $name) { Write-Json $response @{ error = 'action_name is required' } 400; break }
                Write-Json $response (Get-PurgeStatus -ActionName $name)
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
