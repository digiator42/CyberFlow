param(
    [string]$Server = "http://127.0.0.1:8010",
    [string]$ApiKey = "",
    [int]$Count = 100
)

<#
.SYNOPSIS
    Pushes sample logs (INFO / DEBUG / ERROR / CRITICAL) to the Logs-SOC backend.
.DESCRIPTION
    Sends one POST per log (so an open SSE stream shows each frame arrive live),
    using realistic fields. Accepts -ApiKey when the backend runs in key mode.
    By default sends 100 logs, split evenly across the 4 levels.
.EXAMPLE
    ./submit-logs.ps1
    ./submit-logs.ps1 -Server http://localhost:8010 -ApiKey topsecret -Count 200
#>

$ErrorActionPreference = "Stop"

if ($Count -lt 1) { throw "-Count must be >= 1" }

$sample = @(
    @{ level = "INFO";    ip = "198.51.100.4";  route = "/api/v1/threats"; msg = "threat ingested" },
    @{ level = "DEBUG";   ip = "203.0.113.7";  route = "/login";          msg = "token issued in 1.2ms" },
    @{ level = "ERROR";   ip = "203.0.113.9";  route = "/pay";            msg = "db timeout after retry" },
    @{ level = "CRITICAL"; ip = "198.51.100.66"; route = "/auth";          msg = "token replay detected" }
)

$uri = "$Server/api/v1/logs"
if ($ApiKey) { $uri = "$uri?api_key=$ApiKey" }
$headers = @{ "Content-Type" = "application/json" }

$sent = 0
$rounds = [math]::Ceiling($Count / $sample.Count)
for ($r = 0; $r -lt $rounds; $r++) {
    foreach ($ev in $sample) {
        if ($sent -ge $Count) { break }
        $payload = $ev | ConvertTo-Json -Compress
        try {
            $res = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $payload -TimeoutSec 5
            $sent++
            if ($sent -le 8 -or $sent % 20 -eq 0) {
                Write-Host ("[{0}] accepted={1} live_consumers={2}  {3}" -f $ev.level, $res.accepted, $res.live_consumers, $ev.msg)
            }
        }
        catch {
            Write-Warning ("[{0}] POST failed: {1}" -f $ev.level, $_.Exception.Message)
        }
        Start-Sleep -Milliseconds 50
    }
}

Write-Host "Done - sent $sent logs ($($sample.Count) levels) to $Server"