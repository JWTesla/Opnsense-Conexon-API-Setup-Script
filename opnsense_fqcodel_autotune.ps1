# =====================================================================
# File: scripts/opnsense_fqcodel_autotune.ps1
# Purpose: Auto-tune OPNsense FQ-CoDel shaper (download/upload) via loaded latency
# Adds: -SelfTest (prints /settings/get and minimal create→search→delete)
# Requires: PowerShell 7+; Ookla Speedtest CLI (default: C:\Tools\Speedtest\speedtest.exe)
# =====================================================================

[CmdletBinding()]
param(
  [string]$OpnUrl = "",
  [string]$ApiKey = "",
  [string]$ApiSecret = "",
  [string]$CredFile = (Join-Path $PSScriptRoot 'OPNsense.localdomain_root_apikey.txt'),
  [string]$WanIf = "wan",
  [string]$LanIf = "lan",
  [int]$DownMbit = 1000,
  [int]$UpMbit   = 1000,
  [int]$FqQuantumBytes = 1514,
  [int]$FqLimitPackets = 10240,
  [int]$FqFlows        = 1024,
  [int]$CodelTargetMs  = 5,
  [int]$CodelIntervalMs= 100,
  [switch]$EnableECN   = $true,
  [string]$PipeDownDesc  = "Gaming-Download",
  [string]$PipeUpDesc    = "Gaming-Upload",
  [string]$QueueDownDesc = "Gaming-Download-Queue",
  [string]$QueueUpDesc   = "Gaming-Upload-Queue",
  [string]$RuleDownDesc  = "Gaming-Download-Rule",
  [string]$RuleUpDesc    = "Gaming-Upload-Rule",
  [ValidateSet('auto','icmp','speedtest')]
  [string]$BaselineMode = 'auto',
  [string[]]$BaselinePingTargets = @("1.1.1.1","8.8.8.8"),
  [int]$BaselinePingCount = 25,
  [int]$AllowedDeltaMs = 5,
  [int]$MinMbps = 100,
  [int]$MaxIterations = 8,
  [int]$TimeoutSec = 20,
  [int]$ServerId = 0,
  [int]$SpeedtestMinIntervalSec = 10,
  [int]$SpeedtestRateLimitBackoffSec = 300,
  [int]$SpeedtestExecTimeoutSec = 45,
  [switch]$SkipSpeedTest,
  [switch]$InsecureTLS,
  [string]$SpeedtestPath = "C:\\Tools\\Speedtest\\speedtest.exe",
  [switch]$PurgeLegacy,
  [switch]$DebugApi,
  [switch]$SelfTest,
  [switch]$GamingProfile = $true
)

if ($GamingProfile) {
  if (-not $PSBoundParameters.ContainsKey('AllowedDeltaMs')) { $AllowedDeltaMs = 3 }
  if (-not $PSBoundParameters.ContainsKey('BaselinePingCount')) { $BaselinePingCount = 20 }
}

$DEFAULT_OPNSENSE_URL    = "https://192.168.1.1"
$DEFAULT_API_KEY         = "PASTE_API_KEY_HERE"
$DEFAULT_API_SECRET      = "PASTE_API_SECRET_HERE"
$DEFAULT_SPEEDTEST_SERVER_ID = 0

$FileApiKey = $null; $FileApiSecret = $null; $FileUrl = $null; $FileServerId = $null
if ($CredFile -and (Test-Path -LiteralPath $CredFile)) {
  Get-Content -LiteralPath $CredFile | ForEach-Object {
    if (-not $_ -or $_.Trim().StartsWith('#')) { return }
    $kv = $_ -split '=', 2
    if ($kv.Count -ne 2) { return }
    $name = $kv[0].Trim().ToLowerInvariant()
    $val  = $kv[1].Trim().Trim('"').Trim("'")
    if ($name -eq 'key')    { $FileApiKey = $val }
    if ($name -eq 'secret') { $FileApiSecret = $val }
    if ($name -eq 'url')    { $FileUrl = $val }
    if ($name -eq 'serverid') { try { $FileServerId = [int]$val } catch {} }
  }
}

function Get-Final4 { param([string]$Flag,[string]$Env,[string]$FileVal,[string]$Default)
  if ($Flag -and $Flag.Trim()) { return $Flag.Trim() }
  if ($Env  -and $Env.Trim())  { return $Env.Trim() }
  if ($FileVal -and $FileVal.Trim()) { return $FileVal.Trim() }
  return $Default
}
$OpnUrlFinal    = Get-Final4 -Flag $OpnUrl    -Env $env:OPNSENSE_URL        -FileVal $FileUrl       -Default $DEFAULT_OPNSENSE_URL
$ApiKeyFinal    = Get-Final4 -Flag $ApiKey    -Env $env:OPNSENSE_API_KEY    -FileVal $FileApiKey    -Default $DEFAULT_API_KEY
$ApiSecretFinal = Get-Final4 -Flag $ApiSecret -Env $env:OPNSENSE_API_SECRET -FileVal $FileApiSecret -Default $DEFAULT_API_SECRET

if ([string]::IsNullOrWhiteSpace($OpnUrlFinal)) { throw "Missing -OpnUrl" }
if ($ApiKeyFinal -eq "PASTE_API_KEY_HERE" -or [string]::IsNullOrWhiteSpace($ApiKeyFinal) -or
    $ApiSecretFinal -eq "PASTE_API_SECRET_HERE" -or [string]::IsNullOrWhiteSpace($ApiSecretFinal)) {
  throw "Missing API creds. Fix $CredFile (key=/secret=), pass -ApiKey/-ApiSecret, env vars, or edit defaults."
}

if ($OpnUrlFinal -notmatch '^https?://') { $OpnUrlFinal = 'https://' + $OpnUrlFinal }

if ($InsecureTLS) {
  if ($PSVersionTable.PSVersion.Major -ge 7) { $script:SkipCertParam = @{ SkipCertificateCheck = $true } }
  else {
@"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public static class PermissiveCertPolicy {
  public static bool AlwaysTrust(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }
}
"@ | Add-Type
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [PermissiveCertPolicy]::AlwaysTrust
    $script:SkipCertParam = @{}
  }
} else { $script:SkipCertParam = @{} }

$basicAuth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ApiKeyFinal}:${ApiSecretFinal}"))
$script:CommonHeaders = @{ Accept='application/json'; Authorization=$basicAuth; 'X-Requested-With'='XMLHttpRequest' }

if (-not $SkipSpeedTest) {
  if (-not (Test-Path -LiteralPath $SpeedtestPath)) { throw "Speedtest CLI not found at '$SpeedtestPath'." }
  $script:SpeedtestCmd = (Resolve-Path -LiteralPath $SpeedtestPath).Path
  $script:SpeedtestServerId = $DEFAULT_SPEEDTEST_SERVER_ID
  if ($PSBoundParameters.ContainsKey('ServerId') -and $ServerId -gt 0) {
    $script:SpeedtestServerId = [int]$ServerId
  } elseif ($env:OPNSENSE_SPEEDTEST_SERVERID) {
    try { $script:SpeedtestServerId = [int]$env:OPNSENSE_SPEEDTEST_SERVERID } catch {}
  } elseif ($FileServerId -gt 0) {
    $script:SpeedtestServerId = [int]$FileServerId
  }
  $script:LastSpeedtestAt = [datetime]::MinValue
}

function Invoke-OPNSenseApi {
  param([ValidateSet('GET','POST')][string]$Method,[string]$Path,[object]$Body)
  $uri = "{0}{1}" -f $OpnUrlFinal.TrimEnd('/'), $Path
  $p = @{ Uri=$uri; Method=$Method; Headers=$script:CommonHeaders; ErrorAction='Stop'; TimeoutSec=$TimeoutSec } + $script:SkipCertParam
  if ($Method -eq 'POST' -and $PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
    $p.ContentType = 'application/json'
    $p.Body = ($Body | ConvertTo-Json -Depth 10)
  }
  $attempts = 3
  for ($try=1; $try -le $attempts; $try++) {
    if ($DebugApi) {
      $bPrev = if ($p.ContainsKey('Body')) { $p.Body } else { '<no-body>' }
      if ($bPrev -and $bPrev.Length -gt 800) { $bPrev = $bPrev.Substring(0,800) + '…' }
      Write-Host ("[api] {0} {1} attempt={2} body={3}" -f $Method, $Path, $try, $bPrev)
    }
    try {
      $r = Invoke-RestMethod @p
      if ($r -is [string]) {
        $t = $r.TrimStart()
        if ($t.StartsWith('<')) { throw "Non-JSON response (likely login HTML)" }
        try { $r = $r | ConvertFrom-Json -Depth 10 } catch {}
      }
      if ($DebugApi) {
        $respStr = try { ($r | ConvertTo-Json -Depth 6) } catch { "$r" }
        if ($respStr -and $respStr.Length -gt 800) { $respStr = $respStr.Substring(0,800) + '…' }
        Write-Host ("[api][ok] {0} {1} → {2}" -f $Method, $Path, $respStr)
      }
      return $r
    }
    catch {
      $isTransient = $false
      $statusCode = $null
      try { $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
      $msg = $_.Exception.Message
      if ($statusCode -ge 500 -and $statusCode -lt 600) { $isTransient = $true }
      if ($msg -match '(timed out|timeout|temporarily unavailable|TLS handshake|connection.*closed|unable to connect)') { $isTransient = $true }
      if ($try -lt $attempts -and $isTransient) { Start-Sleep -Seconds ([int][math]::Pow(2,$try)); continue }
      $bodyTxt = if ($p.ContainsKey('Body')) { $p.Body } else { '<no-body>' }
      if ($DebugApi) { Write-Host ("[api][err] {0} {1} → {2}" -f $Method, $Path, $_.Exception.Message) }
      throw "API call failed → $Method $Path on $OpnUrlFinal`nBody: $bodyTxt`nError: $($_.Exception.Message)"
    }
  }
}

function Get-AllShaper {
  param([ValidateSet('pipes','queues','rules')][string]$Type)
  $endpoint = switch ($Type) { 'pipes' { 'search_pipes' } 'queues' { 'search_queues' } 'rules' { 'search_rules' } }
  $res = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/$endpoint" -Body @{current=1;rowCount=9999;sort=@{};searchPhrase=""}
  @($res.rows)
}
function Get-ShaperConfig { Invoke-OPNSenseApi -Method GET -Path "/api/trafficshaper/settings/get" }

function Assert-ApiReady {
  try {
    $probe = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/search_pipes" -Body @{current=1;rowCount=1;sort=@{};searchPhrase=""}
    if (-not $probe -or -not $probe.PSObject.Properties['rows']) { throw "Unexpected response" }
  } catch {
    throw "API auth/URL failed. Verify -OpnUrl, API key/secret, and that the user has Traffic Shaper privileges. $_"
  }
}

function Find-Uuid {
  param(
    [ValidateSet('pipes','queues','rules')][string]$Type,
    [string]$Description,
    [object]$Rows,
    [object]$Config
  )
  $rows = if ($PSBoundParameters.ContainsKey('Rows') -and $Rows) { @($Rows) } else { Get-AllShaper -Type $Type }
  foreach($r in $rows){
    $desc = $null
    if ($r.PSObject.Properties['description']) { $desc = $r.description }
    elseif ($r.PSObject.Properties['descr'])   { $desc = $r.descr }
    elseif ($r.PSObject.Properties['desc'])    { $desc = $r.desc }
    if ($desc -eq $Description) {
      if ($r.PSObject.Properties['uuid']) { return $r.uuid }
      if ($r.PSObject.Properties['id'])   { return $r.id }
    }
  }
  $cfg = if ($PSBoundParameters.ContainsKey('Config') -and $Config) { $Config } else { Get-ShaperConfig }
  $root = if ($cfg -and $cfg.PSObject.Properties['ts']) { $cfg.ts } else { $cfg }
  if ($Type -eq 'pipes'  -and $root -and $root.pipes -and $root.pipes.pipe)  {
    foreach($k in $root.pipes.pipe.PSObject.Properties.Name){ $n=$root.pipes.pipe.$k; if ($n -and ($n.description -eq $Description -or $n.descr -eq $Description)){ return $k } }
  }
  if ($Type -eq 'queues' -and $root -and $root.queues -and $root.queues.queue) {
    foreach($k in $root.queues.queue.PSObject.Properties.Name){ $n=$root.queues.queue.$k; if ($n -and ($n.description -eq $Description -or $n.descr -eq $Description)){ return $k } }
  }
  if ($Type -eq 'rules'  -and $root -and $root.rules  -and $root.rules.rule)  {
    $rr = $root.rules.rule
    if ($rr -is [System.Collections.IDictionary]) {
      foreach($k in $rr.PSObject.Properties.Name){ $n=$rr.$k; if ($n -and ($n.description -eq $Description -or $n.descr -eq $Description)){ return $k } }
    } else {
      foreach($n in @($rr)){ if ($n -and ($n.description -eq $Description -or $n.descr -eq $Description)){ if ($n.PSObject.Properties['uuid']) { return $n.uuid } } }
    }
  }
  return $null
}
function Dump-ShaperState {
  Write-Host "---- /api/trafficshaper/settings/get ----"
  try { (Get-ShaperConfig | ConvertTo-Json -Depth 6) | Write-Host } catch { Write-Host "<error dumping settings/get>" }
  Write-Host "---- search_pipes ----"
  try { (Get-AllShaper -Type pipes)  | ConvertTo-Json -Depth 6 | Write-Host } catch { Write-Host "<error>" }
  Write-Host "---- search_queues ----"
  try { (Get-AllShaper -Type queues) | ConvertTo-Json -Depth 6 | Write-Host } catch { Write-Host "<error>" }
  Write-Host "---- search_rules ----"
  try { (Get-AllShaper -Type rules)  | ConvertTo-Json -Depth 6 | Write-Host } catch { Write-Host "<error>" }
}

function New-PipePayloadMinimal { param([string]$Desc,[int]$Mbps)
  @{ pipe = @{ enabled="1"; description=$Desc; bandwidth="$Mbps"; bandwidth_metric="Mbit"; bandwidthMetric="Mbit"; scheduler="fq_codel" } }
}
function New-PipePayloadAdvanced { param([string]$Desc,[int]$Mbps)
  @{
    pipe = @{
      enabled="1"; description=$Desc; bandwidth="$Mbps"; bandwidth_metric="Mbit"; bandwidthMetric="Mbit"
      scheduler="fq_codel"; codel_enable="1"; codel_ecn_enable = $(if ($EnableECN) {"1"} else {"0"})
      fqcodel_quantum="$FqQuantumBytes"; fqcodel_limit="$FqLimitPackets"; fqcodel_flows="$FqFlows"
      codel_target="$CodelTargetMs"; codel_interval="$CodelIntervalMs"
    }
  }
}

function Ensure-Pipe {
  param([string]$Description,[int]$BandwidthMbit)
  $rowsP = Get-AllShaper -Type pipes
  $cfg   = Get-ShaperConfig
  $uuid = Find-Uuid -Type pipes -Description $Description -Rows $rowsP -Config $cfg
  if (-not $uuid) {
    $resp1 = $null; $err1 = $null
    try { $resp1 = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/add_pipe" -Body (New-PipePayloadAdvanced -Desc $Description -Mbps $BandwidthMbit) } catch { $err1 = $_.Exception.Message }
    if ($err1 -or ($resp1.result -eq 'failed')) {
      $resp2 = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/add_pipe" -Body (New-PipePayloadMinimal -Desc $Description -Mbps $BandwidthMbit)
      if ($resp2.result -eq 'failed') { throw "add_pipe failed (minimal). Validations: $(($resp2.validations | ConvertTo-Json -Depth 8))" }
      $uuid = if ($resp2.uuid) { $resp2.uuid } else { $null }
    } else { $uuid = if ($resp1.uuid) { $resp1.uuid } else { $null } }
    if (-not $uuid) { Start-Sleep -Milliseconds 250; $rowsP = Get-AllShaper -Type pipes; $cfg = Get-ShaperConfig; $uuid = Find-Uuid -Type pipes -Description $Description -Rows $rowsP -Config $cfg }
  }
  if (-not $uuid) { Dump-ShaperState; throw "Failed to obtain pipe UUID for '$Description'." }
  try { [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/set_pipe/$uuid" -Body (New-PipePayloadAdvanced -Desc $Description -Mbps $BandwidthMbit)) } catch {}
  return $uuid
}
function Ensure-Queue {
  param([string]$Description,[string]$PipeUuid)
  $rowsQ = Get-AllShaper -Type queues
  $cfg   = Get-ShaperConfig
  $uuid = Find-Uuid -Type queues -Description $Description -Rows $rowsQ -Config $cfg
  $obj  = @{ queue = @{
      enabled="1"; description=$Description; pipe=$PipeUuid; weight="100"
      codel_enable="1"; codel_ecn_enable = $(if ($EnableECN) {"1"} else {"0"})
      codel_target="$CodelTargetMs"; codel_interval="$CodelIntervalMs"
    } }
  if (-not $uuid) {
    $resp = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/add_queue" -Body $obj
    if ($resp.result -eq 'failed') { throw "add_queue failed: $(($resp.validations | ConvertTo-Json -Depth 6))" }
    $uuid = if ($resp.uuid) { $resp.uuid } else { $null }
    if (-not $uuid) { Start-Sleep -Milliseconds 200; $rowsQ = Get-AllShaper -Type queues; $cfg = Get-ShaperConfig; $uuid = Find-Uuid -Type queues -Description $Description -Rows $rowsQ -Config $cfg }
  }
  if (-not $uuid) { Dump-ShaperState; throw "Failed to obtain queue UUID for '$Description'." }
  try { [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/set_queue/$uuid" -Body $obj) } catch {}
  return $uuid
}
function Ensure-Rule {
  param([string]$Description,[string]$Interface,[ValidateSet('in','out')][string]$Direction,[ValidateSet('ip','ip4','ip6','ipv6')][string]$Proto,[string]$QueueUuid)
  $p = switch ($Proto) { 'ipv6' { 'ip6' } 'ipv4' { 'ip4' } default { $Proto } }
  $rowsR = Get-AllShaper -Type rules
  $cfg   = Get-ShaperConfig
  $uuid = Find-Uuid -Type rules -Description $Description -Rows $rowsR -Config $cfg
  $obj  = @{ rule = @{
      enabled="1"; description=$Description; interface=$Interface; direction=$Direction; proto=$p
      source="any"; destination="any"; target=$QueueUuid
  } }
  if (-not $uuid) {
    $resp = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/add_rule" -Body $obj
    if ($resp.result -eq 'failed') { throw "add_rule failed: $(($resp.validations | ConvertTo-Json -Depth 6))" }
    $uuid = if ($resp.uuid) { $resp.uuid } else { $null }
    if (-not $uuid) { Start-Sleep -Milliseconds 200; $rowsR = Get-AllShaper -Type rules; $cfg = Get-ShaperConfig; $uuid = Find-Uuid -Type rules -Description $Description -Rows $rowsR -Config $cfg }
  }
  if (-not $uuid) { Dump-ShaperState; throw "Failed to obtain rule UUID for '$Description'." }
  try { [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/set_rule/$uuid" -Body $obj) } catch {}
  return $uuid
}
function Ensure-RuleDualStack { param([string]$BaseDesc,[string]$Interface,[ValidateSet('in','out')][string]$Direction,[string]$QueueUuid)
  [void](Ensure-Rule -Description $BaseDesc            -Interface $Interface -Direction $Direction -Proto 'ip'   -QueueUuid $QueueUuid)
  [void](Ensure-Rule -Description ($BaseDesc + '-IPv6') -Interface $Interface -Direction $Direction -Proto 'ip6' -QueueUuid $QueueUuid)
}

function Apply-Shaper {
  try { [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/service/reconfigure" -Body @{}) }
  catch {
    if ($_.Exception.Message -like "*Endpoint not found*" -or $_.Exception.Message -like "*404*") {
      [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/service/flushreload" -Body @{})
    } else { throw }
  }
}
function Remove-Pipe {
  param([string]$Uuid)
  try { [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/del_pipe/$Uuid" -Body @{}) } catch {
    throw "del_pipe failed for ${Uuid}: $($_.Exception.Message)"
  }
}

function Purge-Legacy {
  $legacy = @('WAN pipe','LAN pipe','WAN IPv6 Pipe','LAN IPv6 pipe')
  foreach ($name in $legacy) {
    $uuid = Find-Uuid -Type pipes -Description $name
    if ($uuid) {
      try { Remove-Pipe -Uuid $uuid; if ($DebugApi) { Write-Host "[purge] removed pipe '$name' ($uuid)" } }
      catch { if ($DebugApi) { Write-Host "[purge][warn] $($_.Exception.Message)" } }
    }
  }
  Apply-Shaper
}

function Run-SelfTest {
  Write-Host "=== SELF-TEST: /settings/get snapshot ==="
  try { (Get-ShaperConfig | ConvertTo-Json -Depth 6) | Write-Host }
  catch { Write-Warning "Failed to fetch /settings/get: $($_.Exception.Message)" }

  $desc = "SelfTest-Pipe-" + ([Guid]::NewGuid().ToString("N").Substring(0,8))
  $payload = New-PipePayloadMinimal -Desc $desc -Mbps 100
  Write-Host "=== SELF-TEST: add_pipe ($desc) ==="
  $resp = Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/add_pipe" -Body $payload
  if ($resp.result -eq 'failed') { throw "add_pipe failed: $(($resp.validations | ConvertTo-Json -Depth 6))" }

  Start-Sleep -Milliseconds 300
  $uuid = Find-Uuid -Type pipes -Description $desc
  if (-not $uuid) { Dump-ShaperState; throw "SELF-TEST: Pipe not found after add." }
  Write-Host "SELF-TEST: Found pipe UUID = $uuid"

  Write-Host "SELF-TEST: reconfigure (apply)…"
  Apply-Shaper

  Write-Host "SELF-TEST: delete pipe…"
  Remove-Pipe -Uuid $uuid
  Apply-Shaper

  Start-Sleep -Milliseconds 200
  $uuid2 = Find-Uuid -Type pipes -Description $desc
  if ($uuid2) { throw "SELF-TEST: Pipe still present after delete (uuid=$uuid2)." }

  Write-Host "=== SELF-TEST: PASS (create→search→delete OK) ==="
}

function Set-PipeBandwidth {
  param([string]$PipeUuid,[string]$PipeDesc,[int]$Mbps)
  $obj = @{ pipe = @{
      enabled="1"; description=$PipeDesc; bandwidth="$Mbps"; bandwidth_metric="Mbit"; bandwidthMetric="Mbit"; scheduler="fq_codel"
      codel_enable="1"; codel_ecn_enable = $(if ($EnableECN) {"1"} else {"0"})
      fqcodel_quantum="$FqQuantumBytes"; fqcodel_limit="$FqLimitPackets"; fqcodel_flows="$FqFlows"
      codel_target="$CodelTargetMs"; codel_interval="$CodelIntervalMs"
  } }
  [void](Invoke-OPNSenseApi -Method POST -Path "/api/trafficshaper/settings/set_pipe/$PipeUuid" -Body $obj)
  Apply-Shaper
}

function Invoke-SpeedtestCapture {
  param([string[]]$Args,[int]$TimeoutSec)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:SpeedtestCmd
  $psi.Arguments = [string]::Join(' ', $Args)
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill($true) } catch {}; throw "Speedtest timed out after $TimeoutSec seconds" }
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  return ($stdout + "`n" + $stderr)
}

function Run-SpeedtestJson {
  param([int]$Retries = 3)
  $args = @('--accept-license','--accept-gdpr','-f','json')
  if ($script:SpeedtestServerId -gt 0) { $args += @('--server-id', $script:SpeedtestServerId) }
  $lastOut = ''
  $lastCode = -1
  for ($i = 1; $i -le $Retries; $i++) {
    if ($script:LastSpeedtestAt -ne [datetime]::MinValue) {
      $elapsed = (Get-Date) - $script:LastSpeedtestAt
      $remain = $SpeedtestMinIntervalSec - [int]$elapsed.TotalSeconds
      if ($remain -gt 0) { Write-Host "Waiting $remain s before next Speedtest…"; Start-Sleep -Seconds $remain }
    }
    $out = Invoke-SpeedtestCapture -Args $args -TimeoutSec $SpeedtestExecTimeoutSec
    $script:LastSpeedtestAt = Get-Date
    $lastCode = $LASTEXITCODE
    $lastOut = [string]$out
    if ($lastOut -match 'Too many requests|exceeded the number of speedtests') {
      $backoff = [int][math]::Max($SpeedtestRateLimitBackoffSec, $SpeedtestMinIntervalSec)
      Write-Host "Speedtest rate-limited. Backing off $backoff seconds…"
      for ($s=$backoff; $s -gt 0; $s-=5) { Start-Sleep -Seconds ([Math]::Min(5,$s)) }
      continue
    }
    if (-not [string]::IsNullOrWhiteSpace($lastOut)) {
      $jsonStart = $lastOut.IndexOf('{')
      $jsonEnd   = $lastOut.LastIndexOf('}')
      if ($jsonStart -ge 0 -and $jsonEnd -ge $jsonStart) {
        $json = $lastOut.Substring($jsonStart, $jsonEnd - $jsonStart + 1)
        try {
          $obj = $json | ConvertFrom-Json -Depth 6
          if (-not $script:SpeedtestServerId -and $obj.PSObject.Properties['server'] -and $obj.server.id) {
            try {
              $script:SpeedtestServerId = [int]$obj.server.id
              $env:OPNSENSE_SPEEDTEST_SERVERID = "$($script:SpeedtestServerId)"
              if ($CredFile -and (Test-Path -LiteralPath $CredFile)) { Add-Content -LiteralPath $CredFile -Value "serverid=$($script:SpeedtestServerId)" -Encoding UTF8 }
            } catch {}
          }
          return $obj
        } catch {}
      }
    }
    Start-Sleep -Seconds ([int][math]::Pow(2,$i))
  }
  $msg = "Speedtest CLI failed (exit=$lastCode). Output: " + ($lastOut.Substring(0,[Math]::Min(4000,[Math]::Max(0,$lastOut.Length))))
  throw $msg
}
function Collect-IcmpLatencies { param([string]$Target,[int]$Count)
  try {
    $samples = Test-Connection -TargetName $Target -Count $Count -ErrorAction Stop
    foreach($s in $samples){
      if     ($s.PSObject.Properties['Latency'])       { $s.Latency }
      elseif ($s.PSObject.Properties['ResponseTime'])  { $s.ResponseTime }
      elseif ($s.PSObject.Properties['RoundTripTime']) { $s.RoundTripTime }
    }
  } catch { @() }
}
function Measure-BaselineLatencyMs {
  param([ValidateSet('auto','icmp','speedtest')][string]$Mode,[string[]]$Targets,[int]$Count)
  if ($Mode -in @('auto','icmp')) {
    $vals = foreach($t in $Targets){ Collect-IcmpLatencies -Target $t -Count $Count }
    $arr = @($vals | Where-Object { $_ -is [double] -or $_ -is [int] })
    if ($arr.Count -gt 0) {
      $sorted = @($arr | Sort-Object)
      $mid = [int][math]::Floor($sorted.Count/2)
      $median = if ($sorted.Count % 2 -eq 1) { [double]$sorted[$mid] } else { ([double]$sorted[$mid-1] + [double]$sorted[$mid]) / 2.0 }
      return [pscustomobject]@{ LatencyMs=[math]::Round($median,2); Source='icmp' }
    }
    elseif ($Mode -eq 'icmp') { throw "Baseline ping via ICMP failed (no replies). Try -BaselineMode speedtest." }
  }
  $st = Run-SpeedtestJson
  $lat = $null
  try { $lat = [double]$st.ping.iqm } catch {}
  if (-not $lat) { $lat = [double]$st.ping.latency }
  [pscustomobject]@{ LatencyMs = [math]::Round($lat,2); Source='speedtest' }
}
function To-Mbps { param([double]$BytesPerSec) [math]::Round(($BytesPerSec * 8.0) / 1e6, 2) }

function AutoTune-Direction {
  param([ValidateSet('download','upload')][string]$Direction,[string]$PipeUuid,[string]$PipeDesc,[int]$InitialMbps,[double]$BaselineMs,[int]$AllowedDeltaMs,[int]$MinMbps,[int]$MaxIterations)
  $warm = Run-SpeedtestJson
  $measMbps = if ($Direction -eq 'download') { To-Mbps $warm.download.bandwidth } else { To-Mbps $warm.upload.bandwidth }
  $upper = [math]::Max($InitialMbps, [int]([math]::Floor($measMbps * 0.98)))
  $lower = [int][math]::Min([math]::Max($MinMbps, [int]([math]::Floor($measMbps * 0.6))), $upper)
  if ($upper -le $lower) { $upper = [int]([math]::Max($lower+10, $InitialMbps)) }
  Write-Host "[$Direction] search: $lower … $upper Mbps (baseline ${BaselineMs}ms, max +${AllowedDeltaMs}ms)"

  $best = $lower
  for ($i=1; $i -le $MaxIterations -and ($upper - $lower) -gt 5; $i++) {
    $cand = [int]([math]::Floor(($lower + $upper)/2))
    Write-Host "[$Direction][$i] testing $cand Mbps…"
    try { Set-PipeBandwidth -PipeUuid $PipeUuid -PipeDesc $PipeDesc -Mbps $cand }
    catch { Write-Warning $_; continue }
    Start-Sleep -Seconds 2

    $res = Run-SpeedtestJson
    $achMbps = if ($Direction -eq 'download') { To-Mbps $res.download.bandwidth } else { To-Mbps $res.upload.bandwidth }
    $loaded = if ($Direction -eq 'download') { $res.download.latency.iqm } else { $res.upload.latency.iqm }
    if (-not $loaded) { $loaded = $res.ping.latency }

    $delta = [math]::Round(($loaded - $BaselineMs),2)
    $ok = ($delta -le $AllowedDeltaMs)
    Write-Host ("    achieved={0} Mbps, loaded={1} ms (Δ{2} ms) → {3}" -f $achMbps,$loaded,$delta,($(if($ok){"OK"}else{"HIGH"})))
    if ($ok) { $best = $cand; $lower = $cand } else { $upper = $cand - 1 }
  }

  Set-PipeBandwidth -PipeUuid $PipeUuid -PipeDesc $PipeDesc -Mbps $best
  Write-Host "[$Direction] final = $best Mbps"
  return $best
}

if ($SelfTest) {
  Run-SelfTest
  return
}

Assert-ApiReady

if ($PurgeLegacy) { Purge-Legacy }
Write-Host "Ensuring shaper objects…"
$downPipeUuid  = Ensure-Pipe  -Description $PipeDownDesc  -BandwidthMbit $DownMbit
$upPipeUuid    = Ensure-Pipe  -Description $PipeUpDesc    -BandwidthMbit $UpMbit
if (-not $downPipeUuid -or -not $upPipeUuid) { Dump-ShaperState; throw "Pipe UUIDs missing. Cannot continue." }

$downQueueUuid = Ensure-Queue -Description $QueueDownDesc -PipeUuid $downPipeUuid
$upQueueUuid   = Ensure-Queue -Description $QueueUpDesc   -PipeUuid $upPipeUuid
if (-not $downQueueUuid -or -not $upQueueUuid) { Dump-ShaperState; throw "Queue UUIDs missing. Cannot continue." }

[void](Ensure-RuleDualStack -BaseDesc $RuleDownDesc -Interface $WanIf -Direction 'in'  -QueueUuid $downQueueUuid)
[void](Ensure-RuleDualStack -BaseDesc $RuleUpDesc   -Interface $WanIf -Direction 'out' -QueueUuid $upQueueUuid)
Apply-Shaper

if ($SkipSpeedTest) {
  $null = Set-PipeBandwidth -PipeUuid $downPipeUuid -PipeDesc $PipeDownDesc -Mbps $DownMbit
  $null = Set-PipeBandwidth -PipeUuid $upPipeUuid   -PipeDesc $PipeUpDesc   -Mbps $UpMbit
  $finalDown = $DownMbit
  $finalUp   = $UpMbit
} else {
  Write-Host "Measuring baseline ping…"
  $baselineObj = Measure-BaselineLatencyMs -Mode $BaselineMode -Targets $BaselinePingTargets -Count $BaselinePingCount
  $baseline = $baselineObj.LatencyMs
  Write-Host ("Baseline: {0} ms (source: {1})" -f $baseline, $baselineObj.Source)
  $finalDown = AutoTune-Direction -Direction download -PipeUuid $downPipeUuid -PipeDesc $PipeDownDesc -InitialMbps $DownMbit -BaselineMs $baseline -AllowedDeltaMs $AllowedDeltaMs -MinMbps $MinMbps -MaxIterations $MaxIterations
  $finalUp   = AutoTune-Direction -Direction upload   -PipeUuid $upPipeUuid   -PipeDesc $PipeUpDesc   -InitialMbps $UpMbit   -BaselineMs $baseline -AllowedDeltaMs $AllowedDeltaMs -MinMbps $MinMbps -MaxIterations $MaxIterations
}

$CredSource = if ($PSBoundParameters.ContainsKey('ApiKey') -and $PSBoundParameters.ContainsKey('ApiSecret') -and $ApiKey -and $ApiSecret) { 'flags' } elseif ($env:OPNSENSE_API_KEY -or $env:OPNSENSE_API_SECRET) { 'env' } elseif ($FileApiKey -and $FileApiSecret) { 'file' } else { 'defaults' }

$notes = @()
if (-not $SkipSpeedTest) { $notes += "  • Using Speedtest at: $($script:SpeedtestCmd)" }
$notes += "  • Cred source: $CredSource"
$summary = @(
  "Done.",
  "",
  "Final Shaper Rates:",
  "  Download: $finalDown Mbit",
  "  Upload:   $finalUp   Mbit",
  "",
  "Notes:",
  ($notes -join "`n"),
  ""
) -join "`n"
Write-Host $summary
