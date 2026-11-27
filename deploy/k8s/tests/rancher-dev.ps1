<#
.SYNOPSIS
Sets up the lab's dev overlay on Rancher Desktop and checks that it works there.

.DESCRIPTION
From a PowerShell window (Windows PowerShell 5.1 or PowerShell 7), anywhere in the repository:

    powershell -ExecutionPolicy Bypass -File .\deploy\k8s\tests\rancher-dev.ps1

Without switches it runs -Setup, then -Check. Every step prints "ok", "FAIL" or "skip". Everything is also written to
rancher-dev-<time>.log in the current folder, without passwords or keys: paste that log back if something fails.

  -Setup     builds the console image into Rancher Desktop's container engine; creates the namespaces and Secrets
             (asks for a console password the first time); applies the overlay and waits for every pod; connects
             n8n (asks for an n8n login; a fresh n8n gets it as its owner account)
  -Check     the login, the Ingress (http://lab.localhost), the network policies, the console's Kubernetes API access,
             the kill switch, the copilot's models, a knowledge upload that a copilot run retrieves, a free prompt
  -Pipeline  a tiny random GLM through every stage as Kubernetes Jobs, then Promote (a few minutes on a laptop)
  -Teardown  deletes the namespaces lab and lab-copilot with all their data (asks first)
  -EvalJudge how reliably the judge model enforces rules of engagement written as text: 49 labelled commands through
             the copilot's Ollama with the workflow's exact prompt (copilot/eval_judge.py, run in the console pod;
             10 to 30 seconds per command on a CPU). The report goes to workspace/eval/. -JudgeModel picks the model.

GPU: Rancher Desktop gives pods no GPU, so the copilot's judge and embeddings run on the CPU. With an NVIDIA GPU, add
-HostOllama to any of the above: Ollama for Windows then serves them, on the GPU. Install it, then run
"ollama pull qwen3:8b" (or your -JudgeModel) and "ollama pull nomic-embed-text". With -HostOllama the preflight checks
that this Ollama answers on 127.0.0.1:11434 and has both models; -Setup applies deploy/k8s/overlays/dev-host-ollama
(unless -Overlay names another) and connects n8n to -HostOllamaUrl (default http://192.168.127.254:11434: this
machine's 127.0.0.1 as pods reach it); -Check and -EvalJudge use that Ollama.

It talks to the cluster through the kubectl context "rancher-desktop" (-Context), whatever context is current, and
installs nothing. Needs: Rancher Desktop with Kubernetes and Traefik enabled, and Python 3 for the n8n step.
Unattended (CI): -NonInteractive, with LAB_PASSWORD, N8N_EMAIL and N8N_PASSWORD in the environment.
#>
[CmdletBinding()]
param(
    [switch]$Setup,
    [switch]$Check,
    [switch]$Pipeline,
    [switch]$Teardown,
    [switch]$EvalJudge,                                  # measure the judge on rules of engagement (copilot/eval_judge.py)
    [switch]$SkipBuild,                                  # use the console image that is already there
    [switch]$Force,                                      # -Teardown without asking
    [switch]$NonInteractive,                             # never prompt: secrets come from the environment
    [switch]$HostOllama,                                 # judge and embeddings from Ollama for Windows (its GPU)
    [string]$Context = 'rancher-desktop',
    [string]$Overlay = 'deploy/k8s/overlays/dev',
    [string]$Image = 'ghcr.io/thrizzo/redteam-llm-lab:latest',
    [string]$LabUser = 'admin',
    [string]$IngressUrl = 'http://127.0.0.1',            # where Traefik answers (Rancher Desktop: localhost:80)
    [string]$IngressHost = 'lab.localhost',
    [string]$N8nEmail = $env:N8N_EMAIL,
    [string]$JudgeModel = 'qwen3:8b',
    [string]$HostOllamaUrl = 'http://192.168.127.254:11434', # -HostOllama: that Ollama as pods reach it
    [int]$ConsolePort = 18080,
    [int]$N8nPort = 15678
)

$ErrorActionPreference = 'Continue'                      # native tools report through exit codes, checked below
Set-StrictMode -Version 1

$OnWindows = ($env:OS -eq 'Windows_NT')
$Curl = 'curl'
if ($OnWindows) { $Curl = 'curl.exe' }                   # Windows 10/11 ship curl.exe; "curl" is an alias in 5.1
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$Console = "http://127.0.0.1:$ConsolePort"
$Glm = 'http://glm-serve.lab.svc:8000/'

$script:Pass = 0
$script:Fail = 0
$script:Skipped = 0
$script:LastOk = $false
$script:PortForwards = @()
$script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('rancher-dev-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$script:AuthFile = $null
$script:WrongAuth = $null
$script:User = $LabUser
$script:LabPassword = $null
$script:Runtime = ''
$script:HasTraefik = $false
$script:ConsoleOk = $false
$script:CopilotOk = $false
$script:Models = @{}
$script:Retrieval = ''
$script:VolumesStuck = $false
$script:LocalPath = $true                                # the default StorageClass is k3s's local-path (preflight)

# ------------------------------------------------------------------------------------------------ output
function Section([string]$Title) { Write-Host ''; Write-Host "== $Title" -ForegroundColor Cyan }
function Ok([string]$Text) { $script:Pass++; Write-Host "ok   $Text" -ForegroundColor Green }
function Bad([string]$Text) { $script:Fail++; Write-Host "FAIL $Text" -ForegroundColor Red }
function Skip([string]$Text) { $script:Skipped++; Write-Host "skip $Text" -ForegroundColor Yellow }
function Note([string]$Text) { Write-Host "     $Text" -ForegroundColor DarkGray }

# Step 'name' { test }: ok when the block's last output is $true; an exception is a FAIL with its message.
# The result is in $script:LastOk.
function Step([string]$StepName, [scriptblock]$StepTest) {
    $stepResult = $false
    try { $stepResult = ((& $StepTest | Select-Object -Last 1) -eq $true) }
    catch { Note ('error: ' + $_.Exception.Message) }
    if ($stepResult) { Ok $StepName } else { Bad $StepName }
    $script:LastOk = $stepResult
}

# Wait-For seconds { condition } [every]: $true as soon as the condition's last output is $true
function Wait-For([int]$WaitSeconds, [scriptblock]$WaitCond, [int]$WaitEvery = 2) {
    $waitUntil = (Get-Date).AddSeconds($WaitSeconds)
    do {
        $waitOk = $false
        try { $waitOk = ((& $WaitCond | Select-Object -Last 1) -eq $true) } catch { }
        if ($waitOk) { return $true }
        Start-Sleep -Seconds $WaitEvery
    } while ((Get-Date) -lt $waitUntil)
    return $false
}

# ------------------------------------------------------------------------------------------------ programs
# Exe 'program' @('arg', ...): its output as one string (stdout and stderr, or stdout only with -Out); never throws.
# $LASTEXITCODE holds its exit code. Arguments go as an array, so "--" and "-n" reach the program untouched.
function Exe([string]$Program, [string[]]$A, [switch]$Out) {
    $r = $null
    try {
        if ($Out) { $r = & $Program @A 2>$null } else { $r = & $Program @A 2>&1 }
    } catch {                                            # not installed: a result, not a crash
        $global:LASTEXITCODE = 127
        return "$($_.Exception.Message)"
    }
    return ((@($r) | ForEach-Object { "$_" }) -join "`n")
}
function kc([string[]]$A) { return (Exe 'kubectl' (@('--context', $Context) + $A)) }
function kcOut([string[]]$A) { return (Exe 'kubectl' (@('--context', $Context) + $A) -Out) }
function kcJson([string[]]$A) {
    $t = kcOut $A
    if ($LASTEXITCODE -ne 0 -or -not $t) { return $null }
    try { return ($t | ConvertFrom-Json) } catch { return $null }
}

# Http -Url ... [-Method POST] [-Json object | -File path] [-Header 'K: v'] [-NoAuth]: @{ Code; Text; Json }.
# The login comes from a curl config file (-K), so the password is never on a command line.
function Http {
    param(
        [string]$Url,
        [string]$Method = 'GET',
        $Json = $null,
        [string]$File = '',
        [string[]]$Header = @(),
        [switch]$NoAuth,
        [string]$AuthFile = $script:AuthFile,
        [int]$MaxSeconds = 120
    )
    $outFile = Join-Path $script:Tmp 'http-out'
    if (Test-Path $outFile) { Remove-Item $outFile -Force }
    $a = @('-sS', '-o', $outFile, '-w', '%{http_code}', '-X', $Method, '-m', "$MaxSeconds")
    if (-not $NoAuth -and $AuthFile) { $a += @('-K', $AuthFile) }
    foreach ($h in $Header) { $a += @('-H', $h) }
    if ($null -ne $Json) {
        $bodyFile = Join-Path $script:Tmp 'http-body.json'
        [IO.File]::WriteAllText($bodyFile, ($Json | ConvertTo-Json -Depth 10 -Compress), $Utf8)
        $a += @('-H', 'Content-Type: application/json', '--data-binary', "@$bodyFile")
    } elseif ($File) {
        $a += @('-H', 'Content-Type: application/octet-stream', '--data-binary', "@$File")
    }
    $a += $Url
    $code = "$(& $Curl @a 2>$null | Select-Object -Last 1)"
    if (-not $code) { $code = '000' }
    $text = ''
    if (Test-Path $outFile) { $text = [IO.File]::ReadAllText($outFile, $Utf8) }
    $obj = $null
    if ($text) { try { $obj = $text | ConvertFrom-Json } catch { } }
    return @{ Code = $code; Text = $text; Json = $obj }
}
function Api([string]$Method, [string]$Path, $Body = $null) {
    if ($Method -eq 'GET') { return (Http -Url ($Console + '/api' + $Path)) }
    if ($null -eq $Body) { $Body = @{} }
    return (Http -Url ($Console + '/api' + $Path) -Method $Method -Json $Body)
}

function Write-CurlUser([string]$Path, [string]$User, [string]$Password) {
    $v = ($User + ':' + $Password).Replace('\', '\\').Replace('"', '\"')
    [IO.File]::WriteAllText($Path, "user = `"$v`"`n", $Utf8)
}
function Set-Auth([string]$User, [string]$Password) {
    $script:AuthFile = Join-Path $script:Tmp 'auth'
    $script:WrongAuth = Join-Path $script:Tmp 'auth-wrong'
    Write-CurlUser $script:AuthFile $User $Password
    Write-CurlUser $script:WrongAuth $User ($Password + '-wrong')
}

# A secret from the environment, else asked for (hidden). -Confirm asks twice.
function Read-Secret([string]$Prompt, [string]$EnvName, [switch]$Confirm) {
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if ($v) { return $v }
    if ($NonInteractive) { throw "$EnvName is not set (needed with -NonInteractive)" }
    while ($true) {
        $p1 = (New-Object System.Net.NetworkCredential('', (Read-Host -AsSecureString $Prompt))).Password
        if (-not $p1) { Write-Host 'Empty; again.'; continue }
        if (-not $Confirm) { return $p1 }
        $p2 = (New-Object System.Net.NetworkCredential('', (Read-Host -AsSecureString 'Again, to confirm'))).Password
        if ($p1 -eq $p2) { return $p1 }
        Write-Host 'They differ; again.'
    }
}

function Test-Port([int]$Port) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(500)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch { return $false } finally { $c.Close() }
}

# kubectl port-forward in the background until the script ends
function Start-Forward([string]$Ns, [string]$Svc, [int]$Local, [int]$Remote) {
    if (Test-Port $Local) { throw "port $Local is in use (an old port-forward?): stop it, or pick another port (-ConsolePort / -N8nPort)" }
    $o = Join-Path $script:Tmp "pf-$Svc.out"
    $e = Join-Path $script:Tmp "pf-$Svc.err"
    $p = Start-Process -FilePath 'kubectl' -ArgumentList @('--context', $Context, '-n', $Ns, 'port-forward', "svc/$Svc", "${Local}:${Remote}") `
        -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
    $script:PortForwards += $p
    $until = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $until) {
        if ($p.HasExited) { break }
        if (Test-Port $Local) { return }
        Start-Sleep -Milliseconds 500
    }
    $why = ''
    if (Test-Path $e) { $why = (Get-Content $e -Raw) }
    throw "port-forward to $Ns/$Svc did not come up: $why"
}

function Find-Python {
    foreach ($cand in @('py -3', 'python3', 'python')) {
        $parts = @($cand -split ' ')
        if (-not (Get-Command $parts[0] -ErrorAction SilentlyContinue)) { continue }
        $v = Exe $parts[0] (@($parts | Select-Object -Skip 1) + @('--version'))
        if ($LASTEXITCODE -eq 0 -and $v -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 8) { return , $parts }
    }
    return $null
}

function ConvertTo-GiB([string]$Q) {                  # a Kubernetes memory quantity (e.g. 16303436Ki) in GiB
    if (-not ($Q -match '^(\d+)(Ki|Mi|Gi|Ti|k|M|G|T)?$')) { return 0 }
    $n = [double]$Matches[1]
    $unit = "$($Matches[2])"
    switch -CaseSensitive ($unit) {
        'Ki' { $n *= 1KB }
        'Mi' { $n *= 1MB }
        'Gi' { $n *= 1GB }
        'Ti' { $n *= 1TB }
        'k' { $n *= 1e3 }
        'M' { $n *= 1e6 }
        'G' { $n *= 1e9 }
        'T' { $n *= 1e12 }
    }
    return [math]::Round($n / 1GB, 1)
}
function ConvertTo-Cpu([string]$Q) {
    if ($Q -match '^(\d+)m$') { return [double]$Matches[1] / 1000 }
    if ($Q -match '^\d+(\.\d+)?$') { return [double]$Q }
    return 0
}

# The CLI that builds images Kubernetes can see: docker with Rancher Desktop's dockerd (moby), nerdctl with containerd.
function Get-BuildEngine {
    if ($script:Runtime -like 'docker://*') { return @{ Exe = 'docker'; Pre = @() } }
    return @{ Exe = 'nerdctl'; Pre = @('--namespace', 'k8s.io') }
}
# Any CLI that can run a throwaway container (for the password hash)
function Get-AnyEngine {
    foreach ($e in @('docker', 'nerdctl')) {
        if (Get-Command $e -ErrorAction SilentlyContinue) {
            $null = Exe $e @('version') -Out
            if ($LASTEXITCODE -eq 0) { return $e }
        }
    }
    return $null
}

# ------------------------------------------------------------------------------------------------ diagnosis
# PowerShell 7 turns JSON dates into DateTime values, Windows PowerShell 5.1 leaves them strings.
function ConvertTo-Utc($V) {
    if ($null -eq $V) { return $null }
    if ($V -is [datetime]) { return $V.ToUniversalTime() }
    $s = "$V"
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}
# When an event last happened. Controllers fill lastTimestamp; the scheduler's events (events.k8s.io) carry only
# eventTime and series, so "kubectl get events --sort-by=.lastTimestamp" sorts them first and a "last 10" cut drops them.
function Get-EventTime($E) {
    foreach ($t in @($E.lastTimestamp, $E.series.lastObservedTime, $E.eventTime, $E.firstTimestamp, $E.metadata.creationTimestamp)) {
        $u = ConvertTo-Utc $t
        if ($null -ne $u) { return $u }
    }
    return [datetime]::MinValue
}
function Format-Age([datetime]$T) {
    if ($T -eq [datetime]::MinValue) { return '?' }
    $s = [int][math]::Max(0, ((Get-Date).ToUniversalTime() - $T).TotalSeconds)
    if ($s -lt 120) { return "${s}s" }
    if ($s -lt 7200) { return ('{0}m' -f [int][math]::Floor($s / 60)) }
    if ($s -lt 172800) { return ('{0}h' -f [int][math]::Floor($s / 3600)) }
    return ('{0}d' -f [int][math]::Floor($s / 86400))
}
function Format-Event($E) {
    $n = 1
    # the scheduler's events count in series; PowerShell 7 gives every object an intrinsic .count of 1, so ask for a real one
    if ($E.series -and $E.series.count) { $n = [int]$E.series.count }
    elseif ($E.PSObject.Properties['count'] -and $E.count) { $n = [int]$E.count }
    $times = ''
    if ($n -gt 1) { $times = " (x$n)" }
    $obj = ("$($E.involvedObject.kind)/$($E.involvedObject.name)").ToLower()
    $msg = ("$($E.message)" -replace '\s+', ' ').Trim()
    if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + ' ...' }
    return ('{0,-5} {1} {2} {3}{4}: {5}' -f (Format-Age (Get-EventTime $E)), $E.type, $E.reason, $obj, $times, $msg)
}
# A namespace's events, oldest first: every Warning (up to 12) and the last few others. Returns all reasons and
# messages as text for the hints below.
function Show-Events([string]$Ns, [int]$Others = 6) {
    $j = kcJson @('-n', $Ns, 'get', 'events', '-o', 'json')
    if (-not $j) { Note "| (no events from kubectl -n $Ns get events)"; return '' }
    $all = @(@($j.items) | Where-Object { $_ } | Sort-Object { Get-EventTime $_ })
    $warn = @($all | Where-Object { $_.type -ne 'Normal' } | Select-Object -Last 12)
    $other = @($all | Where-Object { $_.type -eq 'Normal' } | Select-Object -Last $Others)
    foreach ($e in @(@($warn + $other) | Sort-Object { Get-EventTime $_ })) { Note ('| ' + (Format-Event $e)) }
    return (($all | ForEach-Object { "$($_.reason) $($_.message)" }) -join "`n")
}
# A pod that runs with every container ready (and is not being deleted).
function Test-PodReady($P) {
    if ($P.metadata.deletionTimestamp -or "$($P.status.phase)" -ne 'Running') { return $false }
    $cs = @(@($P.status.containerStatuses) | Where-Object { $_ })
    return ($cs.Count -gt 0 -and @($cs | Where-Object { -not $_.ready }).Count -eq 0)
}
# Why a pod is not running and ready: the waiting or terminated reason of a container, 'not ready', or its phase. $null
# when it runs, when it finished (the helm-install Jobs of k3s), or when it is on its way out (being deleted, or Failed:
# its controller makes a new pod, which counts instead).
function Get-PodProblem($P) {
    $phase = "$($P.status.phase)"
    if ($phase -eq 'Succeeded' -or $phase -eq 'Failed' -or $P.metadata.deletionTimestamp) { return $null }
    if (Test-PodReady $P) { return $null }
    foreach ($c in @(@($P.status.containerStatuses) | Where-Object { $_ -and -not $_.ready })) {
        if ($c.state.waiting.reason) { return "$($c.state.waiting.reason)" }
        if ($c.state.terminated.reason) { return "$($c.state.terminated.reason)" }
    }
    if ($phase -eq 'Running') { return 'not ready' }
    if ($phase) { return $phase }
    return 'unknown'
}
# k3s's own pods in kube-system (CoreDNS, the volume provisioner, Traefik, metrics-server) that do not run: "name: why".
function Get-SystemProblems {
    $pods = kcJson @('-n', 'kube-system', 'get', 'pods', '-o', 'json')
    if (-not $pods) { return @('kube-system: no answer from kubectl') }
    $out = @()
    foreach ($p in @(@($pods.items) | Where-Object { $_ })) {
        $why = Get-PodProblem $p
        if ($why) { $out += "$($p.metadata.name): $why" }
    }
    return $out
}
# "pod or component: why" when no pod of a component runs and is ready; $null when one does (a pod being replaced
# does not count against it).
function Get-ComponentProblem([string]$Name, $Pods) {
    $mine = @(@($Pods) | Where-Object { $_ })
    if (@($mine | Where-Object { Test-PodReady $_ }).Count) { return $null }
    foreach ($p in $mine) {
        $why = Get-PodProblem $p
        if ($why) { return "$($p.metadata.name): $why" }
    }
    if ($mine.Count) { return "${Name}: not ready" }
    return "${Name}: no pod"
}
# The components the stack cannot start without: CoreDNS, and the local-path provisioner when it backs the default
# StorageClass. No pod at all, or no answer from kubectl, counts as broken. Returns one "pod or component: why" each.
function Get-CriticalProblems {
    $dns = kcJson @('-n', 'kube-system', 'get', 'pods', '-l', 'k8s-app=kube-dns', '-o', 'json')
    if (-not $dns) { return @('kube-system: no answer from kubectl') }
    $out = @()
    $why = Get-ComponentProblem 'coredns' $dns.items
    if ($why) { $out += $why }
    if ($script:LocalPath) {
        # k3s runs it in kube-system, kind and upstream installs in local-path-storage; both label it app=local-path-provisioner
        $lp = kcJson @('get', 'pods', '-A', '-l', 'app=local-path-provisioner', '-o', 'json')
        if (-not $lp) { $out += 'local-path-provisioner: no answer from kubectl' }
        else {
            $why = Get-ComponentProblem 'local-path-provisioner' $lp.items
            if ($why) { $out += $why }
        }
    }
    return $out
}
# Prints each system pod that does not run with the newest Warning about it; returns the pods and all their Warnings
# as text for Show-SystemHints.
function Show-SystemPods {
    $problems = @(Get-SystemProblems)
    if (-not $problems.Count) { return '' }
    $ev = kcJson @('-n', 'kube-system', 'get', 'events', '-o', 'json')
    $text = ''
    foreach ($pr in $problems) {
        Note "| kube-system/$pr"
        $name = ($pr -split ':')[0]
        $text += "`n$pr"
        if (-not $ev) { continue }
        $warns = @(@($ev.items) | Where-Object { $_ -and $_.type -ne 'Normal' -and "$($_.involvedObject.name)" -eq $name } |
            Sort-Object { Get-EventTime $_ })
        if ($warns.Count) {                             # the newest on screen; all of them for the hints
            Note ('|   ' + (Format-Event $warns[-1]))
            $text += "`n" + (($warns | ForEach-Object { "$($_.message)" }) -join "`n")
        }
    }
    return $text.Trim()
}
function Show-SystemHints([string]$Text) {
    if ($Text -match 'is already in use by container|ResolvConfPath') {
        Note 'hint: the container engine kept stale Kubernetes containers (seen after an unclean stop, e.g. Windows sleep):'
        Note '      1. quit Rancher Desktop, run "wsl --shutdown", start it again'
        Note '      2. if they stay: docker rm -f $(docker ps -aq --filter "name=k8s_")   (removes only what Kubernetes created)'
        Note '      3. last resort: Rancher Desktop > Troubleshooting > Reset Kubernetes (deletes every workload in this cluster)'
    }
    if ($Text -match 'ports are not available') {
        Note 'hint: Traefik cannot open port 80 or 443 on Windows. Which program holds it:'
        Note '      Get-NetTCPConnection -LocalPort 80,443 -State Listen | Select-Object LocalPort,OwningProcess'
    }
    if ($Text -match 'ErrImagePull|ImagePullBackOff') {
        Note 'hint: the node cannot pull an image of k3s itself: check the network inside WSL (VPN, proxy, DNS)'
    }
}
# Claims of a namespace that still have no volume.
function Get-PendingClaims([string]$Ns) {
    $j = kcJson @('-n', $Ns, 'get', 'pvc', '-o', 'json')
    if (-not $j) { return @() }
    return @(@($j.items) | Where-Object { $_ -and "$($_.status.phase)" -eq 'Pending' } | ForEach-Object { "$($_.metadata.name)" })
}

function Show-Trouble([string]$Ns) {
    $pods = kcOut @('-n', $Ns, 'get', 'pods', '-o', 'wide')
    ($pods -split "`n") | ForEach-Object { Note "| $_" }
    $ev = Show-Events $Ns
    $all = $pods + "`n" + $ev
    $pending = @(Get-PendingClaims $Ns)
    # -HostOllama: no pod uses the in-cluster Ollama's claim, and local-path gives a claim its volume only for a pod
    if ($HostOllama -and $Ns -eq 'lab-copilot') { $pending = @($pending | Where-Object { $_ -ne 'ollama' }) }
    if ($pending.Count) {
        Note ("claims without a volume in ${Ns}: " + ($pending -join ', ') + '; the provisioner and the rest of kube-system:')
        $sys = Show-SystemPods
        if (-not $sys) { Note '| (every pod in kube-system runs)' }
        Show-SystemHints $sys
        # the remaining waits are skipped only when the provisioner the claims use is down, by the preflight's rule
        if ($script:LocalPath -and @(Get-CriticalProblems | Where-Object { $_ -like 'local-path-provisioner*' }).Count) {
            $script:VolumesStuck = $true
        }
    }
    if ($all -match 'untolerated taint') {
        Note 'hint: the node carries a taint the pods do not tolerate (kubectl describe node): disk or memory pressure, or not ready'
    }
    if ($all -match 'Insufficient (memory|cpu)') {
        Note 'hint: the node lacks memory or CPU for these requests: give WSL more in %UserProfile%\.wslconfig ([wsl2] memory=16GB) and restart Rancher Desktop'
    }
    if ($all -match 'ErrImagePull|ImagePullBackOff|ErrImageNeverPull') {
        Note "hint: an image could not be pulled. Kubernetes uses the local build of ${Image}: run -Setup without -SkipBuild"
    }
}

# ------------------------------------------------------------------------------------------------ cluster helpers
function Get-State { $j = (Api 'GET' '/control').Json; if ($j) { return "$($j.state)" }; return '' }
function Get-ModelPods {
    $j = kcJson @('-n', 'lab', 'get', 'pods', '-l', 'lab-role=glm-serve', '-o', 'json')
    if (-not $j) { return -1 }
    return @($j.items).Count
}
function Get-ModelContainers {   # the runtime's view, with Rancher Desktop's dockerd (cri-dockerd keeps these labels)
    $ids = Exe 'docker' @('ps', '-q', '--filter', 'label=io.kubernetes.pod.namespace=lab', '--filter', 'label=io.kubernetes.container.name=server') -Out
    return @(($ids -split "`n") | Where-Object { $_.Trim() }).Count
}
# exit code of curl in a probe pod: 0 = an HTTP answer came back (any status); 7 or 28 = refused or timed out
function Get-Reach([string]$Pod, [string]$Url) {
    $null = kc @('-n', 'lab', 'exec', $Pod, '--', 'curl', '-s', '-o', '/dev/null', '-m', '5', $Url)
    return $LASTEXITCODE
}
function Start-Probes {
    foreach ($role in @('console', 'intruder')) {
        $null = kc @('-n', 'lab', 'delete', 'pod', "probe-$role", '--ignore-not-found', '--wait=true')
        $null = kc @('-n', 'lab', 'run', "probe-$role", '--image=curlimages/curl:8.23.0', '--restart=Never', "--labels=lab-role=$role",
                     '--command', '--', 'sleep', '3600')
    }
    $null = kc @('-n', 'lab', 'wait', '--for=condition=Ready', 'pod/probe-console', 'pod/probe-intruder', '--timeout=180s')
    return ($LASTEXITCODE -eq 0)
}
function Get-Doc([string]$Rel) {
    $k = (Api 'GET' '/knowledge').Json
    if (-not $k) { return $null }
    return (@($k.docs) | Where-Object { $_.doc -eq $Rel } | Select-Object -First 1)
}
function Get-LabUser {
    $b64 = kcOut @('-n', 'lab', 'get', 'secret', 'basic-auth', '-o', 'jsonpath={.data.user}')
    if ($b64) { try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64.Trim())) } catch { } }
    return $LabUser
}

# ------------------------------------------------------------------------------------------------ host Ollama
# -HostOllama: the judge and the embeddings come from Ollama for Windows. Pods reach it at -HostOllamaUrl: Rancher
# Desktop NATs 192.168.127.254 to this machine's 127.0.0.1, port for port. This script asks it on 127.0.0.1 directly.
function Get-HostOllamaLocal {
    $port = 11434
    try { $port = ([Uri]$HostOllamaUrl).Port } catch { }
    return "http://127.0.0.1:$port"
}
# The models the copilot takes from it: the judge, and the embeddings n8n searches with.
function Get-HostModels { return @($JudgeModel, 'nomic-embed-text') }
# Does an /api/tags answer list the model? A name without a tag means :latest, as for "ollama pull".
function Test-HasModel($Tags, [string]$Model) {
    $want = $Model
    if ($want -notmatch ':') { $want += ':latest' }
    return (@(@($Tags.models) | Where-Object { $_ -and ("$($_.name)" -eq $want -or "$($_.name)" -eq $Model) }).Count -gt 0)
}
# GET -HostOllamaUrl plus a path from the console pod, the way the console and n8n reach it: the answer, or $null.
function Get-HostOllama([string]$Path) {
    return (kcJson @('-n', 'lab', 'exec', 'deploy/console', '-c', 'app', '--', 'curl', '-sS', '-m', '10', ($HostOllamaUrl.TrimEnd('/') + $Path)))
}
# Where the host's Ollama runs the models it has loaded, worked out as "ollama ps" does for its PROCESSOR column.
function Show-HostOllamaPs {
    $running = (Http -Url ((Get-HostOllamaLocal) + '/api/ps') -NoAuth -MaxSeconds 10).Json
    $loaded = @(@($running.models) | Where-Object { $_ })
    if (-not $loaded.Count) { Note 'the host''s Ollama has no model loaded right now ("ollama ps" on Windows)'; return }
    foreach ($m in $loaded) {
        $size = [double]$m.size
        $vram = [double]$m.size_vram
        $proc = '100% GPU'
        if ($vram -le 0) { $proc = '100% CPU' }
        elseif ($size -gt $vram) {
            $cpuPct = [int][math]::Round(100 * ($size - $vram) / $size)
            $proc = "$cpuPct%/$(100 - $cpuPct)% CPU/GPU"
        }
        Note ("the host's Ollama runs $($m.name) on $proc" + ' (PROCESSOR in "ollama ps")')
    }
}

# ------------------------------------------------------------------------------------------------ preflight
function Invoke-Preflight {
    Section 'Preflight'
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Bad 'kubectl on PATH (Rancher Desktop puts it in ~\.rd\bin; open a new terminal after installing)'
        return $false
    }
    $contexts = @((Exe 'kubectl' @('config', 'get-contexts', '-o', 'name') -Out) -split "`n" | Where-Object { $_ })
    if ($contexts -notcontains $Context) {
        Bad ("kubectl context $Context (found: " + ($contexts -join ', ') + '); enable Kubernetes in Rancher Desktop, or pass -Context')
        return $false
    }
    Ok "kubectl context $Context"
    $nodes = kcJson @('get', 'nodes', '-o', 'json')
    if (-not $nodes) { Bad "the cluster answers (kubectl --context $Context get nodes)"; return $false }
    $items = @($nodes.items)
    $ready = @($items | Where-Object { @($_.status.conditions | Where-Object { $_.type -eq 'Ready' -and $_.status -eq 'True' }).Count -gt 0 })
    $info = $items[0].status.nodeInfo
    $script:Runtime = "$($info.containerRuntimeVersion)"
    if ($ready.Count -eq $items.Count) { Ok "nodes Ready: $($items.Count); Kubernetes $($info.kubeletVersion), runtime $($script:Runtime)" }
    else { Bad "nodes Ready: $($ready.Count) of $($items.Count)" }
    $mem = 0.0
    $cpu = 0.0
    foreach ($i in $items) { $mem += ConvertTo-GiB "$($i.status.allocatable.memory)"; $cpu += ConvertTo-Cpu "$($i.status.allocatable.cpu)" }
    # dev requests: the stack 2.05 CPU / 5.1 GiB, the largest Job 1 CPU / 2 GiB, k3s's own pods about 0.2 CPU
    if ($cpu -ge 3.5) { Ok "CPUs for pods: $cpu" } else { Bad "CPUs for pods: $cpu (the stack and a pipeline Job request ~3.3: let Rancher Desktop / WSL use more)" }
    if ($mem -lt 5.5) { Bad "memory for pods: $mem GiB (the stack requests 5 GiB: pods would stay Pending)" }
    else {
        Ok "memory for pods: $mem GiB"
        if ($mem -lt 7.5) { Note 'a pipeline Job requests 2 GiB more: Jobs may wait for memory' }
        if ($mem -lt 14 -and -not $HostOllama) { Note 'the judge (qwen3:8b) and a CPU scan of GLM-Edge-1.5B together need ~16 GB: %UserProfile%\.wslconfig, [wsl2] memory=16GB' }
    }
    # The default StorageClass and k3s's own pods. Without CoreDNS and the volume provisioner every pod of the stack
    # would wait 10 to 15 minutes for nothing (seen on a Rancher Desktop whose engine kept stale containers after an
    # unclean stop). -Teardown needs neither: deleting the namespaces works on such a cluster too.
    if (-not $Teardown) {
        $scs = kcJson @('get', 'storageclass', '-o', 'json')
        $default = @(@($scs.items) | Where-Object { $_ -and ($_.metadata.annotations.'storageclass.kubernetes.io/is-default-class' -eq 'true' -or
                    $_.metadata.annotations.'storageclass.beta.kubernetes.io/is-default-class' -eq 'true') } |
                    Sort-Object { ConvertTo-Utc $_.metadata.creationTimestamp })
        if (-not $default.Count) { Bad 'a default StorageClass: the stack''s claims name none (Rancher Desktop''s k3s ships local-path)'; return $false }
        $sc = $default[-1]                              # Kubernetes gives a claim without a class the newest default
        if ($default.Count -gt 1) { Note "$($default.Count) StorageClasses are marked default; claims without a class get the newest, $($sc.metadata.name)" }
        $script:LocalPath = ("$($sc.provisioner)" -eq 'rancher.io/local-path')
        Ok "default StorageClass $($sc.metadata.name) ($($sc.provisioner))"
        $critical = @(Get-CriticalProblems)
        if ($critical.Count) {
            Note ('waiting up to 90 s for k3s''s own pods: ' + ($critical -join '; '))
            $null = Wait-For 90 { @(Get-CriticalProblems).Count -eq 0 } 5
            $critical = @(Get-CriticalProblems)
        }
        if ($critical.Count) {
            Show-SystemHints (Show-SystemPods)
            Bad ('k3s system pods: ' + ($critical -join '; ') + ' (without them no pod of the stack gets DNS or a volume)')
            return $false
        }
        if ($script:LocalPath) { Ok 'k3s system pods: CoreDNS and the volume provisioner run' } else { Ok 'k3s system pods: CoreDNS runs' }
        $others = @(Get-SystemProblems)
        if ($others.Count) {
            Show-SystemHints (Show-SystemPods)
            Note ('not running in kube-system: ' + ($others -join '; ') + ' (the stack can start; the Ingress check may fail)')
        }
    }
    $script:HasTraefik = [bool](kcJson @('-n', 'kube-system', 'get', 'svc', 'traefik', '-o', 'json'))
    if ($script:HasTraefik) { Ok 'Traefik (the overlays'' Ingress class)' }
    else { Note 'no Traefik in kube-system: the Ingress check is skipped (Rancher Desktop: Preferences > Kubernetes > Traefik)' }
    if ($HostOllama -and -not $Teardown) { Invoke-HostPreflight }
    if (-not (Test-Path (Join-Path $Repo $Overlay))) { Bad "overlay $Overlay in $Repo"; return $false }
    return $true
}

# -HostOllama: Ollama for Windows answers here and has the copilot's models. The setup does not need it, so a FAIL
# does not stop the script: the judge (~5 GB) can download while the image builds.
function Invoke-HostPreflight {
    $localUrl = Get-HostOllamaLocal
    $missing = @(Get-HostModels)
    $v = Http -Url "$localUrl/api/version" -NoAuth -MaxSeconds 10
    if ($v.Code -eq '200' -and $v.Json -and $v.Json.version) {
        Ok "Ollama on this machine answers ($localUrl, version $($v.Json.version))"
        $tags = (Http -Url "$localUrl/api/tags" -NoAuth -MaxSeconds 10).Json
        $missing = @(Get-HostModels | Where-Object { -not (Test-HasModel $tags $_) })
        if ($missing.Count) { Bad ('the host''s Ollama has the copilot''s models; missing: ' + ($missing -join ', ')) }
        else { Ok ('the host''s Ollama has the copilot''s models: ' + ((Get-HostModels) -join ', ')) }
    } else {
        Bad "Ollama for Windows answers on $localUrl (got HTTP $($v.Code)): install it from https://ollama.com/download and start it"
    }
    foreach ($m in $missing) { Note "on Windows: ollama pull $m" }
    Note '"ollama ps" shows GPU in its PROCESSOR column (e.g. "100% GPU") for a model loaded on the GPU'
}

# ------------------------------------------------------------------------------------------------ setup
function Invoke-Build {
    $engine = Get-BuildEngine
    if (-not (Get-Command $engine.Exe -ErrorAction SilentlyContinue)) {
        Bad "$($engine.Exe) on PATH (the CLI of the container engine Kubernetes uses: $($script:Runtime))"
        return $false
    }
    $log = Join-Path $script:Tmp 'build'
    $a = @($engine.Pre) + @('build', '-f', 'deploy/Dockerfile', '--build-arg', 'TORCH_FLAVOR=cpu', '-t', $Image, '.')
    Note "building $Image with $($engine.Exe) (CPU torch; the first build takes 5 to 15 minutes, later ones use the cache)"
    $t0 = Get-Date
    $p = Start-Process -FilePath $engine.Exe -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput "$log.out" -RedirectStandardError "$log.err"
    $null = $p.Handle                                    # keeps ExitCode readable once it ends (Windows PowerShell)
    while (-not $p.HasExited) { Start-Sleep -Seconds 15; Write-Host -NoNewline '.' }
    Write-Host ''
    $p.WaitForExit()
    if ($p.ExitCode -eq 0) { Ok ("image built in {0:N1} min: $Image" -f ((Get-Date) - $t0).TotalMinutes); return $true }
    Bad "image build (exit $($p.ExitCode)); the end of its output:"
    foreach ($f in @("$log.err", "$log.out")) { if (Test-Path $f) { Get-Content $f -Tail 15 | ForEach-Object { Note "| $_" } } }
    return $false
}

function Invoke-Secrets {
    $out = kc @('apply', '-f', 'deploy/k8s/base/namespaces.yaml')
    if ($LASTEXITCODE -ne 0) { Bad "namespaces: $out"; return $false }
    Ok 'namespaces lab and lab-copilot'
    $has = kcOut @('-n', 'lab', 'get', 'secret', 'basic-auth', '-o', 'name', '--ignore-not-found')
    if ($has) {
        $script:User = Get-LabUser
        Ok "Secret lab/basic-auth exists (user $($script:User); its password is kept)"
    } else {
        try { $pw = Read-Secret "New console password for user $LabUser (8+ characters, no double quotes)" 'LAB_PASSWORD' -Confirm }
        catch { Bad $_.Exception.Message; return $false }
        if ($pw.Length -lt 8 -or $pw.Contains('"')) { Bad 'console password: 8+ characters, no double quotes'; return $false }
        $engine = Get-AnyEngine
        if (-not $engine) { Bad 'docker or nerdctl, to hash the password (caddy hash-password)'; return $false }
        # bcrypt by the Caddy the login runs; the password is a process argument for a second, on this machine only
        $hash = (Exe $engine @('run', '--rm', 'caddy:2.11.9', 'caddy', 'hash-password', '--plaintext', $pw) -Out).Trim()
        if ($hash -notmatch '^\$2[aby]\$\d\d\$') { Bad 'the password hash (caddy hash-password gave no bcrypt hash)'; return $false }
        $out = kc @('-n', 'lab', 'create', 'secret', 'generic', 'basic-auth', "--from-literal=user=$LabUser", "--from-literal=hash=$hash")
        if ($LASTEXITCODE -ne 0) { Bad "Secret lab/basic-auth: $out"; return $false }
        Ok "Secret lab/basic-auth (user $LabUser, bcrypt hash)"
        $script:User = $LabUser
        $script:LabPassword = $pw
    }
    $has = kcOut @('-n', 'lab-copilot', 'get', 'secret', 'n8n', '-o', 'name', '--ignore-not-found')
    if ($has) { Ok 'Secret lab-copilot/n8n exists (its encryption key is kept)' }
    else {
        $bytes = New-Object byte[] 32
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $key = [Convert]::ToBase64String($bytes)
        $out = kc @('-n', 'lab-copilot', 'create', 'secret', 'generic', 'n8n', "--from-literal=encryption-key=$key")
        if ($LASTEXITCODE -ne 0) { Bad "Secret lab-copilot/n8n: $out"; return $false }
        Ok 'Secret lab-copilot/n8n (a new random encryption key: it lives only in this Secret; never change it)'
    }
    return $true
}

function Invoke-Apply {
    $out = kc @('apply', '-k', $Overlay)
    if ($LASTEXITCODE -ne 0) {
        Bad "kubectl apply -k $Overlay"
        ($out -split "`n") | Select-Object -Last 10 | ForEach-Object { Note "| $_" }
        return $false
    }
    $changed = @(($out -split "`n") | Where-Object { $_ -match ' (created|configured)$' }).Count
    Ok "applied $Overlay ($changed objects created or changed)"
    $allUp = $true
    $script:VolumesStuck = $false
    foreach ($w in @('lab-copilot deploy/n8n', 'lab-copilot deploy/ollama', 'lab-copilot statefulset/qdrant', 'lab deploy/console', 'lab deploy/glm-serve')) {
        $ns, $target = $w -split ' '
        # -HostOllama: the overlay scales the in-cluster Ollama to 0, so there is no pod to wait for
        if ($HostOllama -and $target -eq 'deploy/ollama' -and (kcOut @('-n', $ns, 'get', 'deploy', 'ollama', '-o', 'jsonpath={.spec.replicas}')).Trim() -eq '0') {
            Ok "$target ($ns) is scaled to 0: n8n and the console use the host's Ollama"
            continue
        }
        if ($script:VolumesStuck) {                     # the other pods wait for volumes as well: 10 to 15 minutes each
            Skip "$target ($ns): not waited for, no claim gets a volume (see above)"
            $allUp = $false
            continue
        }
        $t0 = Get-Date
        $out = kc @('-n', $ns, 'rollout', 'status', $target, '--timeout=900s')
        $code = $LASTEXITCODE
        $secs = ((Get-Date) - $t0).TotalSeconds
        if ($code -eq 0) { Ok ("$target ($ns) is up after {0:N0} s" -f $secs) }
        else {
            # a Deployment gives up after its progress deadline (10 minutes), before --timeout
            $lines = @(($out -split "`n") | Where-Object { $_.Trim() })
            $why = ''
            if ($lines.Count) { $why = $lines[-1].Trim() }
            Bad ("$target ($ns) did not come up (after {0:N0} s; kubectl: {1})" -f $secs, $why)
            Show-Trouble $ns
            $allUp = $false
        }
    }
    return $allUp
}

function Invoke-N8n {
    $py = Find-Python
    if (-not $py) { Bad 'Python 3 for deploy/n8n/connect_console.py (python.org, or: winget install Python.Python.3.12), then -Setup again'; return }
    Ok ('Python: ' + ($py -join ' '))
    try { Start-Forward 'lab-copilot' 'n8n' $N8nPort 5678 } catch { Bad $_.Exception.Message; return }
    # /healthz/readiness says 200 only once n8n's REST API is there. /healthz and /rest/settings are no proof: while
    # n8n migrates its database it answers every request with 200 "n8n is starting up", and its routes come after
    # that (an owner setup in between got a plain 404 in CI). connect_console.py waits for it as well.
    if (Wait-For 300 { (Http -Url "http://127.0.0.1:$N8nPort/healthz/readiness" -NoAuth).Code -eq '200' } 3) { Ok 'n8n is ready (/healthz/readiness)' }
    else { Bad 'n8n is not ready after 5 minutes (/healthz/readiness)'; Show-Trouble 'lab-copilot'; return }
    $email = $N8nEmail
    if (-not $email) {
        if ($NonInteractive) { Bad 'N8N_EMAIL is not set (needed with -NonInteractive)'; return }
        $email = Read-Host 'n8n login e-mail (a fresh n8n: the owner account to create)'
    }
    try { $pw = Read-Secret 'n8n password (a fresh n8n: 8+ characters with a number and a capital letter)' 'N8N_PASSWORD' }
    catch { Bad $_.Exception.Message; return }
    $secretFile = Join-Path $script:Tmp 'copilot-secret.json'
    $old = $env:N8N_PASSWORD
    $env:N8N_PASSWORD = $pw                              # connect_console.py reads it from there: never an argument
    try {
        $a = @($py | Select-Object -Skip 1) + @('deploy/n8n/connect_console.py', '--n8n', "http://127.0.0.1:$N8nPort", '--email', $email,
                                               '--setup-owner', '--secret-file', $secretFile)
        if ($HostOllama) { $a += @('--ollama-url', $HostOllamaUrl) }    # n8n's judge and embeddings: the host's Ollama
        $out = Exe $py[0] $a
        $code = $LASTEXITCODE
    } finally { $env:N8N_PASSWORD = $old }
    ($out -split "`n") | Where-Object { $_ } | ForEach-Object { Note "| $_" }
    if ($code -ne 0 -or -not (Test-Path $secretFile)) { Bad 'connect_console.py (n8n credentials, workflow, console key)'; return }
    Ok 'connect_console.py: n8n login, credentials, workflow published, an n8n key for the console'
    if ($HostOllama) { Note "n8n's Ollama credential (judge, embeddings): $HostOllamaUrl" }
    $out = kc @('apply', '-f', $secretFile)
    $code = $LASTEXITCODE
    Remove-Item $secretFile -Force
    if ($code -eq 0) { Ok 'Secret lab/copilot (the webhook secret and the n8n key, for the console)' } else { Bad "Secret lab/copilot: $out" }
}

function Invoke-Setup {
    Section 'Setup: the console image'
    if ($SkipBuild) { Note "-SkipBuild: $Image as it is" }
    elseif (-not (Invoke-Build)) { return $false }
    Section 'Setup: namespaces and Secrets'
    if (-not (Invoke-Secrets)) { return $false }
    Section "Setup: apply $Overlay and wait for every pod"
    if (-not (Invoke-Apply)) { return $false }
    Section 'Setup: connect n8n to the console'
    Invoke-N8n
    return $true
}

# ------------------------------------------------------------------------------------------------ console login
function Open-Console {
    Section 'Console login (Caddy in the console pod)'
    $script:User = Get-LabUser
    if (-not $script:LabPassword) {
        try { $script:LabPassword = Read-Secret "Console password for $($script:User)" 'LAB_PASSWORD' }
        catch { Bad $_.Exception.Message; return }
    }
    Set-Auth $script:User $script:LabPassword
    try { Start-Forward 'lab' 'console' $ConsolePort 8080 } catch { Bad $_.Exception.Message; return }
    Step 'login: no password -> 401' { (Http -Url "$Console/" -NoAuth).Code -eq '401' }
    Step 'login: a wrong password -> 401' { (Http -Url "$Console/" -AuthFile $script:WrongAuth).Code -eq '401' }
    Step "login: $($script:User) -> 200" { (Http -Url "$Console/").Code -eq '200' }
    $script:ConsoleOk = $script:LastOk
    if (-not $script:ConsoleOk) { Note 'the API checks need the login: is it the password in Secret lab/basic-auth?'; return }
    Step 'the console runs stages as Kubernetes Jobs (runner k8s)' { (Api 'GET' '/env').Json.runner -eq 'k8s' }
}

# ------------------------------------------------------------------------------------------------ check
function Invoke-Ingress {
    Section "Ingress: $IngressHost through Traefik"
    if (-not $script:HasTraefik) { Skip 'Ingress (no Traefik in this cluster)'; return }
    $h = "Host: $IngressHost"
    $first = Http -Url "$IngressUrl/" -NoAuth -Header $h
    if ($first.Code -eq '000') { Skip "Ingress: nothing answers on $IngressUrl (Rancher Desktop forwards Traefik to localhost:80; another program on port 80?)"; return }
    Step "Traefik routes $IngressHost to the login (401 without a password; got $($first.Code))" { $first.Code -eq '401' }
    Step "http://$IngressHost with the login -> 200" { (Http -Url "$IngressUrl/" -Header $h).Code -eq '200' }
    $two = Join-Path $script:Tmp 'two-mb.txt'
    [IO.File]::WriteAllText($two, ("nmap -sC -sV -p- 10.10.10.5`n" * 72000), $Utf8)
    Step 'a 2 MB upload (preview) passes Traefik and the login' {
        $r = Http -Method 'POST' -Url "$IngressUrl/api/knowledge/preview?source=htb&name=two-mb.txt" -Header $h -File $two
        ($r.Code -eq '200') -and ($r.Json.chunks -gt 0)
    }
    $big = Join-Path $script:Tmp 'big.txt'
    $fs = [IO.File]::Create($big)
    $fs.SetLength(51000000)
    $fs.Close()
    $r = Http -Method 'POST' -Url "$IngressUrl/api/knowledge/preview?source=htb&name=big.txt" -Header $h -File $big
    Step "a 51 MB upload is refused (413; got $($r.Code))" { $r.Code -eq '413' }
}

function Invoke-Policies {
    Section 'Network policies (k3s enforces them with its built-in controller)'
    if (-not (Start-Probes)) { Bad 'probe pods (curlimages/curl) are Ready'; Show-Trouble 'lab'; return }
    Step 'console -> model server' { Wait-For 30 { (Get-Reach 'probe-console' $Glm) -eq 0 } 1 }
    Step 'console -> n8n' { (Get-Reach 'probe-console' 'http://n8n.lab-copilot.svc:5678/healthz') -eq 0 }
    # Qdrant by its pod IP: a blocked connection must not pass for a failed name lookup
    $qip = kcOut @('-n', 'lab-copilot', 'get', 'pod', 'qdrant-0', '-o', 'jsonpath={.status.podIP}')
    foreach ($t in @("model server|$Glm", 'n8n|http://n8n.lab-copilot.svc:5678/healthz', "qdrant|http://${qip}:6333/")) {
        $label, $url = $t -split '\|', 2
        $c = Get-Reach 'probe-intruder' $url
        if ($c -eq 7 -or $c -eq 28) { Ok "stranger -/-> $label (curl exit $c)" }
        else { Bad "stranger -/-> ${label}: curl exit $c (0: it got through; 6: no DNS)" }
    }
    if ($HostOllama) {
        # the host's Ollama through Rancher Desktop's NAT: the console may reach it, a stranger may not. A refused
        # connection proves nothing while Ollama is down, so the stranger is tried only once the console got through.
        $hv = $HostOllamaUrl.TrimEnd('/') + '/api/version'
        Step "console -> the host's Ollama ($HostOllamaUrl)" { Wait-For 30 { (Get-Reach 'probe-console' $hv) -eq 0 } 2 }
        if ($script:LastOk) {
            $c = Get-Reach 'probe-intruder' $hv
            if ($c -eq 7 -or $c -eq 28) { Ok "stranger -/-> the host's Ollama (curl exit $c)" }
            else { Bad "stranger -/-> the host's Ollama: curl exit $c (0: it got through)" }
        } else { Skip 'stranger -/-> the host''s Ollama (the console does not reach it either: is Ollama running on Windows?)' }
    }
    $null = kc @('-n', 'lab', 'exec', 'deploy/glm-serve', '--', 'timeout', '5', 'bash', '-c', 'true')
    if ($LASTEXITCODE -ne 0) { Skip 'model server -/-> internet (no bash and timeout in its image)'; return }
    $null = kc @('-n', 'lab', 'exec', 'deploy/glm-serve', '--', 'timeout', '5', 'bash', '-c', '</dev/tcp/1.1.1.1/443')
    $c = $LASTEXITCODE
    Step "model server -/-> internet (exit $c)" { $c -ne 0 }
    $null = kc @('-n', 'lab', 'exec', 'deploy/glm-serve', '--', 'timeout', '5', 'bash', '-c', "</dev/tcp/$qip/6333")
    $c = $LASTEXITCODE
    Step "model server -/-> qdrant (exit $c)" { $c -ne 0 }
}

function Invoke-KillSwitch {
    Section 'Kill switch, through the console API'
    $state = Get-State
    Step "the console reads the model server through the Kubernetes API (state: $state)" { $state -in @('running', 'starting', 'isolated', 'stopping', 'killed', 'stopped') }
    if (-not $script:LastOk) { return }
    if ($state -ne 'running') {
        Note "starting it first (state $state)"
        $null = Api 'POST' '/control/start'
        $null = kc @('-n', 'lab', 'rollout', 'status', 'deploy/glm-serve', '--timeout=300s')
    }
    Step 'model server running' { (Get-State) -eq 'running' }
    $r = Api 'POST' '/control/isolate' @{ reason = 'rancher-dev: isolate' }
    Step 'isolate ok' { $r.Json.ok -eq $true }
    Step 'isolate: state isolated' { (Get-State) -eq 'isolated' }
    Step 'isolate: the console can no longer reach the model' { Wait-For 30 { (Get-Reach 'probe-console' $Glm) -ne 0 } 1 }
    Step 'isolate: the model keeps running' { (Get-ModelPods) -eq 1 }
    $r = Api 'POST' '/control/release'
    Step 'release ok' { $r.Json.ok -eq $true }
    Step 'release: the console reaches the model again' { Wait-For 30 { (Get-Reach 'probe-console' $Glm) -eq 0 } 1 }
    $t0 = Get-Date
    $r = Api 'POST' '/control/kill' @{ reason = 'rancher-dev: kill' }
    $gone = Wait-For 30 { (Get-ModelPods) -eq 0 } 0
    $ms = [int]((Get-Date) - $t0).TotalMilliseconds
    Step "kill ok: $($r.Json.message)" { $r.Json.ok -eq $true }
    Step "kill: no model server pod left after $ms ms, as kubectl sees it (< 10 s)" { $gone -and $ms -lt 10000 }
    if ($script:Runtime -like 'docker://*' -and (Get-Command docker -ErrorAction SilentlyContinue)) {
        Step 'kill: no model server container in Rancher Desktop''s engine (docker ps)' { (Get-ModelContainers) -eq 0 }
    }
    Start-Sleep -Seconds 10
    Step 'kill: nothing restarted it (10 s later)' { (Get-ModelPods) -eq 0 }
    Step 'kill: state killed' { (Get-State) -eq 'killed' }
    $r = Api 'POST' '/control/start'
    Step 'start ok' { $r.Json.ok -eq $true }
    $null = kc @('-n', 'lab', 'rollout', 'status', 'deploy/glm-serve', '--timeout=300s')
    $c = $LASTEXITCODE
    Step 'start: model server ready' { $c -eq 0 }
    Step 'start: the console reaches the model' { Wait-For 60 { (Get-Reach 'probe-console' $Glm) -eq 0 } 2 }
    $u = $script:User
    $seen = (@((Api 'GET' '/control').Json.audit) | Where-Object { $_.source -eq 'control' } | Select-Object -First 4 |
             ForEach-Object { "$($_.stage):$($_.who.user)" }) -join ','
    Step "audit: start, kill, release, isolate, each by $u ($seen)" { $seen -eq "start:$u,kill:$u,release:$u,isolate:$u" }
}

function Invoke-Models {
    Section "The copilot's models (Ollama in lab-copilot)"
    $cm = kcJson @('-n', 'lab-copilot', 'get', 'configmap', 'ollama-models', '-o', 'json')
    $want = @()
    if ($cm) { $want = @("$($cm.data.OLLAMA_PULL)" -split '\s+' | Where-Object { $_ }) }
    if (-not $want.Count) { Skip 'this overlay pulls no models'; return }
    foreach ($m in $want) {
        $wait = 20
        if ($m -like 'nomic-embed-text*') {                  # pulled first; knowledge needs it
            $wait = 900
            Note "waiting for $m (pulled when Ollama starts; up to 15 minutes)"
        }
        $have = Wait-For $wait { (kc @('-n', 'lab-copilot', 'exec', 'deploy/ollama', '--', 'ollama', 'list')) -match [regex]::Escape($m) } 10
        $script:Models[$m] = $have
        if ($have) { Ok "$m is pulled" }
        else {
            $tail = (kcOut @('-n', 'lab-copilot', 'logs', 'deploy/ollama', '--tail=3')) -split "[`r`n]" | Where-Object { $_.Trim() } | Select-Object -Last 1
            if ($tail -and $tail.Length -gt 100) { $tail = $tail.Substring(0, 100) }
            Skip "$m is not pulled yet (Ollama: $tail); its checks are skipped, run -Check again later"
        }
    }
}

# -HostOllama: the copilot's models on Ollama for Windows, as the console pod sees them. Nothing pulls them in the
# cluster, so a missing model is a FAIL with its "ollama pull", not a wait.
function Invoke-HostModels {
    Section "The copilot's models (Ollama for Windows, $HostOllamaUrl from the pods)"
    $rag = (kcOut @('-n', 'lab', 'exec', 'deploy/console', '-c', 'app', '--', 'printenv', 'RAG_OLLAMA_URL')).Trim()
    Step "the console embeds knowledge and lists judges with it (RAG_OLLAMA_URL $rag)" { $rag.TrimEnd('/') -eq $HostOllamaUrl.TrimEnd('/') }
    $ver = ''
    $answer = Get-HostOllama '/api/version'
    if ($answer) { $ver = "$($answer.version)" }
    Step "the console pod gets an answer from the host's Ollama (/api/version: $ver)" { [bool]$ver }
    if (-not $script:LastOk) { Note 'is Ollama running on Windows? Did -Setup apply the dev-host-ollama overlay (its network policies)?'; return }
    $tags = Get-HostOllama '/api/tags'
    foreach ($m in (Get-HostModels)) {
        $have = Test-HasModel $tags $m
        $script:Models[$m] = $have
        if ($have) { Ok "$m is on the host's Ollama" }
        else { Bad "$m is not on the host's Ollama; on Windows: ollama pull $m" }
    }
}

function Invoke-Copilot {
    Section 'Copilot: the console and n8n'
    $script:CopilotOk = Wait-For 180 { (Api 'GET' '/copilot').Json.configured -eq $true } 10
    if ($script:CopilotOk) { Ok 'the console is connected to n8n (Secret lab/copilot, read from its mount)' }
    else {
        $miss = @((Api 'GET' '/copilot').Json.missing) -join ', '
        Bad "the console is connected to n8n (missing: $miss); run -Setup"
    }
}

function Invoke-Knowledge {
    Section 'Knowledge: upload, retrieval in a copilot run, delete'
    $kn = (Api 'GET' '/knowledge').Json
    if (-not $kn -or -not $kn.configured) { Bad 'knowledge is configured (Qdrant and embeddings)'; return }
    $embed = @($script:Models.Keys | Where-Object { $_ -like 'nomic-embed-text*' -and $script:Models[$_] })
    if (-not $embed.Count) { Skip 'knowledge (the embedding model is not pulled yet)'; return }
    $md = Join-Path $script:Tmp 'Lame.md'
    $text = "# Lame (HTB, retired)`n`n## Recon`nnmap -sC -sV shows Samba 3.0.20 on 139/445.`n`n## Foothold`nSamba 3.0.20 usermap_script gives root.`n"
    [IO.File]::WriteAllText($md, $text, $Utf8)
    $up = Http -Method 'POST' -Url "$Console/api/knowledge/upload?source=htb&name=Lame.md" -File $md
    Step "upload a markdown writeup (HTTP $($up.Code))" { $up.Code -eq '200' -and $up.Json.doc -eq 'htb/Lame.md' }
    Step 'it is embedded into Qdrant (status indexed)' { Wait-For 300 { (Get-Doc 'htb/Lame.md').status -eq 'indexed' } 3 }
    if ($script:CopilotOk) {
        $run = Api 'POST' '/copilot/run' @{ task = 'Enumerate SMB on the box'; target = '10.10.10.5' }
        $id = "$($run.Json.id)"
        $script:Retrieval = "no run ($($run.Code))"
        if ($id) {
            $null = Wait-For 300 {
                $g = (Api 'GET' "/copilot/runs/$id").Json
                $e = @(@($g.events) | Where-Object { $_.stage -eq 'retrieval' })
                if ($e.Count) { $script:Retrieval = "$($e[0].message)"; return $true }
                return ($g.status -in @('done', 'error', 'canceled', 'lost'))
            } 3
            $g = (Api 'GET' "/copilot/runs/$id").Json
            if ($g -and $g.status -in @('running', 'waiting')) { $null = Api 'POST' "/copilot/runs/$id/stop" }
        }
        Step "a copilot run retrieves it ($($script:Retrieval))" { $script:Retrieval -like 'ok (*' }
    } else { Skip 'a copilot run retrieves it (n8n is not connected)' }
    $del = Api 'POST' '/knowledge/delete' @{ doc = 'htb/Lame.md' }
    Step 'delete it (its vectors, then the file)' { $del.Json.deleted -eq $true }
    Step 'it is gone from the list' { $null -eq (Get-Doc 'htb/Lame.md') }
}

function Invoke-Prompt {
    Section 'A free prompt to the served model'
    $envInfo = (Api 'GET' '/env').Json
    $models = @()
    if ($envInfo -and $envInfo.ollama) { $models = @($envInfo.ollama.models) }
    if (-not @($models | Where-Object { $_ -like 'glm-abl*' }).Count) { Skip 'a free prompt (glm-serve has no glm-abl yet: Promote a run, or run -Pipeline)'; return }
    $r = Http -Method 'POST' -Url "$Console/api/model/chat" -Json @{ prompt = 'Say hello.'; max_tokens = 16 } -MaxSeconds 300
    $last = @(($r.Text -split "`n") | Where-Object { $_.Trim() }) | Select-Object -Last 1
    $done = $false
    try { $done = (($last | ConvertFrom-Json).done -eq $true) } catch { }
    Step "a free prompt streams from glm-abl (HTTP $($r.Code))" { $done }
}

function Invoke-Check {
    Invoke-Ingress
    Invoke-Policies
    Invoke-KillSwitch
    if ($HostOllama) { Invoke-HostModels } else { Invoke-Models }
    Invoke-Copilot
    Invoke-Knowledge
    if ($HostOllama) { Show-HostOllamaPs }               # the upload above has just used the embedding model
    Invoke-Prompt
}

# ------------------------------------------------------------------------------------------------ pipeline
# A stage through the console's API, as the GUI starts it; waits until its Job has ended. @{ Run; Code }
function Invoke-Stage([hashtable]$Body, [int]$Minutes = 20) {
    $st = Api 'POST' '/pipeline/start' $Body
    if (-not $st.Json -or -not $st.Json.running) { Note "start refused: HTTP $($st.Code) $($st.Text)"; return @{ Run = ''; Code = -1 } }
    $until = (Get-Date).AddMinutes($Minutes)
    $logAt = 0
    $tail = @()
    $stuckSince = $null
    do {
        Start-Sleep -Seconds 3
        $s = (Api 'GET' '/pipeline/status').Json
        $l = (Api 'GET' "/pipeline/log?start=$logAt").Json  # only the lines since the last look
        if ($l) { $tail = @(@($tail) + @($l.lines) | Select-Object -Last 5); $logAt = [int]$l.next }
        $why = @($tail | Where-Object { "$_" -match 'Unschedulable' }) | Select-Object -Last 1
        if (-not $why) { $stuckSince = $null }
        elseif (-not $stuckSince) { $stuckSince = Get-Date }
        elseif (((Get-Date) - $stuckSince).TotalSeconds -gt 120) {   # no room on the node: say why instead of waiting
            Note "the Job cannot be scheduled: $why"
            Note 'give Rancher Desktop / WSL more CPUs or memory, or lower the requests in the overlay''s jobs.json'
            $null = Api 'POST' '/pipeline/stop'
            return @{ Run = "$($s.run_id)"; Code = -2 }
        }
    } while ($s -and $s.running -and (Get-Date) -lt $until)
    $code = -1
    if ($s -and $null -ne $s.exit_code) { $code = [int]$s.exit_code }
    if ($code -ne 0) {
        $log = (Api 'GET' '/pipeline/log?start=0').Json
        if ($log) { @($log.lines) | Select-Object -Last 20 | ForEach-Object { Note "| $_" } }
    }
    return @{ Run = "$($s.run_id)"; Code = $code }
}

function Invoke-Pipeline {
    Section 'Pipeline: a tiny random GLM through every stage as Kubernetes Jobs'
    $pod = kcOut @('-n', 'lab', 'get', 'pods', '-l', 'lab-role=console', '-o', 'jsonpath={.items[0].metadata.name}')
    if (-not $pod) { Bad 'the console pod'; return }
    $null = kc @('-n', 'lab', 'cp', 'deploy/k8s/tests/make_tiny_glm.py', "lab/${pod}:/tmp/make_tiny_glm.py", '-c', 'app')
    $out = kc @('-n', 'lab', 'exec', $pod, '-c', 'app', '--', '/opt/venv/bin/python', '/tmp/make_tiny_glm.py', '/workspace/src/tiny-glm')
    $c = $LASTEXITCODE
    Step 'a tiny random GLM, made in the console pod (only its config and tokenizer come from Hugging Face)' { $c -eq 0 }
    if ($c -ne 0) { ($out -split "`n") | Select-Object -Last 10 | ForEach-Object { Note "| $_" }; return }
    $model = '/workspace/src/tiny-glm'
    $small = @{ device_map = 'cpu'; dtype = 'float32'; n_train = 8; n_test = 2; batch = 4; gen_batch = 2; max_new_tokens = 4; layer_range = '0.25-0.75' }
    $r = Invoke-Stage @{ engine = 'abliterate'; stage = 'download'; model = $model }
    Step 'download Job (the prompt datasets from Hugging Face)' { $r.Code -eq 0 }
    if (-not $script:LastOk) { return }
    $r = Invoke-Stage (@{ engine = 'abliterate'; stage = 'scan'; model = $model } + $small)
    $run = $r.Run
    Step "scan Job (run $run)" { $r.Code -eq 0 }
    if (-not $script:LastOk) { return }
    foreach ($s in @('apply', 'validate', 'deploy')) {
        $b = @{ engine = 'abliterate'; stage = $s; run_id = $run }
        if ($s -eq 'apply') { $b['layer'] = 1 }
        $r = Invoke-Stage $b
        Step "$s Job" { $r.Code -eq 0 }
        if (-not $script:LastOk) { return }
    }
    $jobs = kcJson @('-n', 'lab', 'get', 'jobs', '-l', 'app=lab-job', '-o', 'json')
    $tokens = @(@($jobs.items) | ForEach-Object { "$($_.spec.template.spec.automountServiceAccountToken)" } | Sort-Object -Unique)
    Step 'the Jobs ran without a ServiceAccount token' { ($tokens -join ',') -eq 'False' }
    $p = Api 'POST' '/serving/promote' @{ run_id = $run }
    Step "promote run $run (HTTP $($p.Code))" { $p.Code -like '2*' }
    $null = Wait-For 300 { $s = (Api 'GET' '/serving').Json; $s -and $null -eq $s.busy } 3
    $s = (Api 'GET' '/serving').Json
    Step "glm-serve serves run $run as glm-abl" { $s -and $null -eq $s.error -and "$($s.current.run_id)" -eq "$run" }
}

# ------------------------------------------------------------------------------------------------ teardown
function Invoke-Teardown {
    Section 'Teardown'
    if (-not $Force) {
        if ($NonInteractive) { Bad 'teardown needs -Force with -NonInteractive'; return }
        $answer = Read-Host 'Delete the namespaces lab and lab-copilot with all their data (models, runs, n8n, Qdrant)? Type yes'
        if ($answer -ne 'yes') { Skip 'teardown (not confirmed)'; return }
    }
    $out = kc @('delete', 'namespace', 'lab', 'lab-copilot', '--ignore-not-found', '--wait=true', '--timeout=600s')
    if ($LASTEXITCODE -eq 0) { Ok 'namespaces lab and lab-copilot deleted (the console image stays in the engine)' } else { Bad "teardown: $out" }
}

function Invoke-EvalJudge {
    Section "The judge on rules of engagement ($JudgeModel, copilot/eval_judge.py)"
    $ollama = 'http://ollama.lab-copilot.svc:11434'
    $pace = 'one line per command, 10 to 30 seconds each on a CPU'
    if ($HostOllama) {                                   # Ollama for Windows, as the console pod reaches it
        $ollama = $HostOllamaUrl
        $pace = 'one line per command; on the GPU usually a few seconds each'
        if (-not (Test-HasModel (Get-HostOllama '/api/tags') $JudgeModel)) {
            Skip "$JudgeModel is not on the host's Ollama as the console pod sees it (on Windows: ollama pull $JudgeModel)"
            return
        }
    } else {
        $have = (kc @('-n', 'lab-copilot', 'exec', 'deploy/ollama', '--', 'ollama', 'list')) -match [regex]::Escape($JudgeModel)
        if (-not $have) { Skip "$JudgeModel is not pulled in the copilot's Ollama yet (-Check shows the pull); run -EvalJudge again later"; return }
    }
    $out = '/workspace/eval/judge-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
    Note $pace
    $a = @('--context', $Context, '-n', 'lab', 'exec', 'deploy/console', '-c', 'app', '--', '/opt/venv/bin/python', '-m',
           'copilot.eval_judge', '--ollama', $ollama, '--model', $JudgeModel, '--out', $out)
    & kubectl @a                                         # live output: the eval prints each verdict as it comes
    $code = $global:LASTEXITCODE
    if ($code -eq 0) { Ok "judge eval done; the full report is in the workspace: $out" }
    else { Bad "judge eval: exit $code (is the console pod running? kubectl -n lab get pods)" }
    if ($HostOllama) { Show-HostOllamaPs }               # where the judge ran
}

# ------------------------------------------------------------------------------------------------ main
if (-not ($Setup -or $Check -or $Pipeline -or $Teardown -or $EvalJudge)) { $Setup = $true; $Check = $true }
# -HostOllama brings its overlay, unless -Overlay names another
if ($HostOllama -and -not $PSBoundParameters.ContainsKey('Overlay')) { $Overlay = 'deploy/k8s/overlays/dev-host-ollama' }
$what = @()
if ($Setup) { $what += 'Setup' }
if ($Pipeline) { $what += 'Pipeline' }
if ($Check) { $what += 'Check' }
if ($Teardown) { $what += 'Teardown' }
if ($EvalJudge) { $what += 'EvalJudge' }
$log = Join-Path (Get-Location).Path ('rancher-dev-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$null = New-Item -ItemType Directory -Path $script:Tmp -Force
if (-not $OnWindows) { $null = Exe 'chmod' @('700', $script:Tmp) }
try { $null = Start-Transcript -Path $log } catch { }
Push-Location $Repo
try {
    $banner = "rancher-dev.ps1: " + ($what -join ', ') + " | context $Context | overlay $Overlay | PowerShell " + $PSVersionTable.PSVersion
    if ($HostOllama) { $banner += " | host Ollama $HostOllamaUrl" }
    Write-Host $banner
    if (Invoke-Preflight) {
        if ($Teardown) { Invoke-Teardown }
        else {
            $setupOk = $true
            if ($Setup) { $setupOk = Invoke-Setup }
            if (-not $setupOk) { Note 'fix the setup step above first; the checks need it' }
            elseif ($Pipeline -or $Check) {
                Open-Console
                if ($script:ConsoleOk -and $Pipeline) { Invoke-Pipeline }
                if ($script:ConsoleOk -and $Check) { Invoke-Check }
            }
            if ($setupOk -and $EvalJudge) { Invoke-EvalJudge }
        }
    }
} finally {
    foreach ($p in $script:PortForwards) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch { } }
    if (-not $Teardown) { try { $null = kc @('-n', 'lab', 'delete', 'pod', 'probe-console', 'probe-intruder', '--ignore-not-found', '--wait=false') } catch { } }
    Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue
    Pop-Location
    Write-Host ''
    Write-Host ('{0} passed, {1} failed, {2} skipped' -f $script:Pass, $script:Fail, $script:Skipped)
    Write-Host "log: $log"
    try { $null = Stop-Transcript } catch { }
}
if ($script:Fail -gt 0) { exit 1 }
exit 0
