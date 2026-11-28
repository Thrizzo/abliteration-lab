<#
Runs rancher-dev.ps1's own port-forward functions (Start-Forward, Stop-Forward, Get-OldForward, Get-PortListener,
Get-PortHolder, taken from the script as they are) against a faked Windows process table, as Rancher Desktop leaves it:
its kubectl is a wrapper (kuberlr) that runs the version-matched kubectl as a child, so a port-forward is two processes,
and stopping only the wrapper left the child holding the port (the owner's second run found 15678 and 18080 in use).
A port-forward that an earlier run left is stopped and started afresh; anything else on the port is named and left
alone; stopping this run's forwards takes the kubectl child along but no unrelated process. CI's k3s job runs it:

    pwsh deploy/k8s/tests/test-rancher-dev-forward.ps1
#>
$ErrorActionPreference = 'Continue'                      # as rancher-dev.ps1 runs
Set-StrictMode -Version 1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $here 'rancher-dev.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Output 'rancher-dev.ps1 does not parse'; exit 1 }
foreach ($name in @('Start-Forward', 'Stop-Forward', 'Get-PortListener', 'Get-PortHolder', 'Get-OldForward')) {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { Write-Output "rancher-dev.ps1 has no function $name"; exit 1 }
    . ([scriptblock]::Create($fn.Extent.Text))
}

# ------------------------------------------------------------------------------------------------ a faked Windows
$script:Procs = @{}                                      # process id -> Win32_Process-like object
$script:Listeners = @{}                                  # port -> process id
$script:Stopped = New-Object System.Collections.Generic.List[int]
$script:Notes = New-Object System.Collections.Generic.List[string]
$script:Started = New-Object System.Collections.Generic.List[string]
$t0 = Get-Date
function Proc([int]$Id, [int]$Parent, [string]$Name, [string]$Cmd, [int]$AgeSeconds = 60) {
    $script:Procs[$Id] = [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = $Name; CommandLine = $Cmd; CreationDate = $t0.AddSeconds(-$AgeSeconds) }
}
function Reset { $script:Procs = @{}; $script:Listeners = @{}; $script:Stopped.Clear(); $script:Notes.Clear(); $script:Started.Clear(); $script:PortForwards = @() }

function Note([string]$Text) { $script:Notes.Add($Text) }
function Start-Sleep { param($Milliseconds, $Seconds) }
function Test-Port([int]$Port) { return $script:Listeners.ContainsKey($Port) }
function Get-NetTCPConnection {
    [CmdletBinding()] param([int]$LocalPort, [string]$State)
    if (-not $script:Listeners.ContainsKey($LocalPort)) { throw 'No matching MSFT_NetTCPConnection objects found' }
    return [pscustomobject]@{ LocalPort = $LocalPort; State = 'Listen'; OwningProcess = $script:Listeners[$LocalPort] }
}
function Get-CimInstance {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName, [string]$Filter)
    if ($ClassName -ne 'Win32_Process') { throw "unexpected class $ClassName" }
    if ($Filter -match '^ProcessId=(\d+)$') { $id = [int]$Matches[1]; if ($script:Procs.ContainsKey($id)) { return $script:Procs[$id] }; return }
    if ($Filter -match '^ParentProcessId=(\d+)$') { $id = [int]$Matches[1]; return @($script:Procs.Values | Where-Object { $_.ParentProcessId -eq $id }) }
    throw "unexpected filter $Filter"
}
function Stop-Process {
    [CmdletBinding()] param([int]$Id, [switch]$Force)
    $script:Stopped.Add($Id)
    $script:Procs.Remove($Id)
    foreach ($port in @($script:Listeners.Keys)) { if ($script:Listeners[$port] -eq $Id) { $script:Listeners.Remove($port) } }
}
function Start-Process {
    [CmdletBinding()] param([string]$FilePath, [string[]]$ArgumentList, [switch]$NoNewWindow, [switch]$PassThru, [string]$RedirectStandardOutput, [string]$RedirectStandardError)
    $script:Started.Add(($ArgumentList -join ' '))
    $local = [int](($ArgumentList[-1] -split ':')[0])
    Proc 900 1 'kubectl.exe' ("kubectl " + ($ArgumentList -join ' ')) 0
    $script:Listeners[$local] = 900
    return [pscustomobject]@{ Id = 900; HasExited = $false }
}

$Context = 'rancher-desktop'
$script:Tmp = [IO.Path]::GetTempPath()
$script:Failed = 0
function Expect([string]$Case, [bool]$Cond, [string]$What) {
    if ($Cond) { return }
    $script:Failed++
    Write-Output "FAIL $Case : $What"
    Write-Output ("    stopped: {0} | notes: {1} | started: {2}" -f ($script:Stopped -join ','), ($script:Notes -join ' / '), ($script:Started -join ' / '))
}
function Try-Forward([string]$Ns, [string]$Svc, [int]$Local, [int]$Remote) {
    try { Start-Forward $Ns $Svc $Local $Remote; return '' } catch { return $_.Exception.Message }
}
$pf = '--context rancher-desktop -n lab-copilot port-forward svc/n8n 15678:5678'
$pfc = '--context rancher-desktop -n lab port-forward svc/console 18080:8080'

# ------------------------------------------------------------------------------------------------ cases
$OnWindows = $true

$k = 'the kubectl child an earlier run left (its wrapper stopped) is stopped, then a fresh forward starts'
Reset
Proc 500 400 'kubectl1.34.3.exe' ('C:\Users\x\.kuberlr\windows-amd64\kubectl1.34.3.exe ' + $pf)
$script:Listeners[15678] = 500
$err = Try-Forward 'lab-copilot' 'n8n' 15678 5678
Expect $k ($err -eq '') "it threw: $err"
Expect $k (($script:Stopped -join ',') -eq '500') 'what it stopped'
Expect $k ($script:Notes -contains 'port 15678: stopped a port-forward to svc/n8n that an earlier run left (kubectl, pid 500)') 'the note'
Expect $k ($script:Started.Count -eq 1 -and $script:Started[0] -eq $pf) 'the fresh forward'
Expect $k (@($script:PortForwards).Count -eq 1) 'the forward is kept for the end'

$k = 'a whole earlier forward, wrapper and child, is stopped; the shell above them is not'
Reset
Proc 300 1 'powershell.exe' 'powershell -ExecutionPolicy Bypass -File .\deploy\k8s\tests\rancher-dev.ps1'
Proc 400 300 'kubectl.exe' ('kubectl ' + $pfc)
Proc 500 400 'kubectl1.34.3.exe' ('C:\Users\x\.kuberlr\windows-amd64\kubectl1.34.3.exe ' + $pfc)
$script:Listeners[18080] = 500
$err = Try-Forward 'lab' 'console' 18080 8080
Expect $k ($err -eq '') "it threw: $err"
Expect $k (($script:Stopped -join ',') -eq '500,400') 'what it stopped'
Expect $k ($script:Procs.ContainsKey(300)) 'the shell'

$k = 'something else on the port is named and left alone'
Reset
Proc 600 1 'svchost.exe' 'C:\Windows\system32\svchost.exe -k LocalService'
$script:Listeners[15678] = 600
$err = Try-Forward 'lab-copilot' 'n8n' 15678 5678
Expect $k ($err -eq 'port 15678 is in use by svchost.exe, pid 600 (an old port-forward?): stop it, or pick another port (-ConsolePort / -N8nPort)') "the error: $err"
Expect $k ($script:Stopped.Count -eq 0 -and $script:Started.Count -eq 0) 'it stopped or started something'

$k = "a kubectl port-forward of another service on the port is not this script's: left alone"
Reset
Proc 700 1 'kubectl.exe' 'kubectl -n lab-copilot port-forward svc/qdrant 15678:6333'
$script:Listeners[15678] = 700
$err = Try-Forward 'lab-copilot' 'n8n' 15678 5678
Expect $k ($err -like 'port 15678 is in use by kubectl.exe, pid 700 *') "the error: $err"
Expect $k ($script:Stopped.Count -eq 0) 'it stopped something'

$k = "the end of a run stops the wrapper's kubectl child and the wrapper, nothing else"
Reset
$since = $t0.AddSeconds(-10)
Proc 800 300 'kubectl.exe' ('kubectl ' + $pf) 10
Proc 801 800 'kubectl1.34.3.exe' ('kubectl1.34.3.exe ' + $pf) 9
Proc 802 800 'conhost.exe' 'conhost.exe 0x4' 9
Proc 803 800 'kubectl1.30.0.exe' 'kubectl1.30.0.exe get pods' 3600     # older than the wrapper: its parent was another process with id 800
Stop-Forward ([pscustomobject]@{ Process = [pscustomobject]@{ Id = 800; HasExited = $false }; Since = $since })
Expect $k (($script:Stopped -join ',') -eq '801,800') "what it stopped: $($script:Stopped -join ',')"

$k = 'a wrapper that has exited: only its kubectl child is stopped, not whatever has its id now'
Reset
Proc 801 800 'kubectl1.34.3.exe' ('kubectl1.34.3.exe ' + $pf) 9
Stop-Forward ([pscustomobject]@{ Process = [pscustomobject]@{ Id = 800; HasExited = $true }; Since = $since })
Expect $k (($script:Stopped -join ',') -eq '801') "what it stopped: $($script:Stopped -join ',')"

$OnWindows = $false
$k = 'not Windows: the port in use is reported as before, nothing is looked up or stopped'
Reset
Proc 500 400 'kubectl' $pf
$script:Listeners[15678] = 500
$err = Try-Forward 'lab-copilot' 'n8n' 15678 5678
Expect $k ($err -eq 'port 15678 is in use (an old port-forward?): stop it, or pick another port (-ConsolePort / -N8nPort)') "the error: $err"
Expect $k ($script:Stopped.Count -eq 0) 'it stopped something'
Reset
Stop-Forward ([pscustomobject]@{ Process = [pscustomobject]@{ Id = 900; HasExited = $false }; Since = $since })
Expect $k (($script:Stopped -join ',') -eq '900') 'the end of a run stops the forward it started'

if ($script:Failed) { Write-Output "$($script:Failed) failed"; exit 1 }
Write-Output 'rancher-dev.ps1 port-forwards: 7 cases as expected'
exit 0                                                   # not the last stub's exit code: CI's pwsh step ends with exit $LASTEXITCODE
