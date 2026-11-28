<#
Runs rancher-dev.ps1's own console-password steps (Invoke-Secrets, Invoke-Setup, Restart-Console, Open-Console,
Show-LoginTrouble and Step, taken from the script as they are) with kubectl, the prompts and HTTP stubbed. A new Secret
lab/basic-auth while the console runs gets the console restarted after the apply (Caddy reads the user and hash from
environment variables when it starts), and a failed login says whether the password was refused (401) or the console
answered something else. CI's k3s job runs it:

    pwsh deploy/k8s/tests/test-rancher-dev-login.ps1
#>
$ErrorActionPreference = 'Continue'                      # as rancher-dev.ps1 runs
Set-StrictMode -Version 1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $here 'rancher-dev.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Output 'rancher-dev.ps1 does not parse'; exit 1 }
foreach ($name in @('Invoke-Secrets', 'Invoke-Setup', 'Restart-Console', 'Open-Console', 'Show-LoginTrouble', 'Step')) {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { Write-Output "rancher-dev.ps1 has no function $name"; exit 1 }
    . ([scriptblock]::Create($fn.Extent.Text))
}

# ------------------------------------------------------------------------------------------------ stubs
$script:Log = New-Object System.Collections.Generic.List[string]
$script:Kc = New-Object System.Collections.Generic.List[string]
function Ok([string]$Text) { $script:Log.Add("ok $Text") }
function Bad([string]$Text) { $script:Log.Add("FAIL $Text") }
function Note([string]$Text) { $script:Log.Add("note $Text") }
function Section([string]$Text) { }
function Get-LabUser { return 'admin' }
function Read-Secret { return 'NewPassw0rd' }
function Get-AnyEngine { return 'docker' }
function Exe([string]$Program, [string[]]$A, [switch]$Out) { return ('$2a$14$' + ('x' * 53)) }
function Start-Forward { }
function Set-Auth { }
function Invoke-Build { return $true }
function Invoke-Apply { $script:Log.Add('applied'); return $true }
function Invoke-N8n { $script:Log.Add('n8n') }
function kc([string[]]$A) {
    $line = $A -join ' '
    $script:Kc.Add($line)
    $global:LASTEXITCODE = 0
    if ($line -like '*rollout restart*') { $global:LASTEXITCODE = $script:RestartExit }
    return ''
}
function kcOut([string[]]$A) {
    $line = $A -join ' '
    $global:LASTEXITCODE = 0
    if ($line -like '*get secret basic-auth*') { if ($script:HasAuth) { return 'secret/basic-auth' }; return '' }
    if ($line -like '*get deploy console*') { if ($script:HasConsole) { return 'deployment.apps/console' }; return '' }
    if ($line -like '*get secret n8n*') { return 'secret/n8n' }
    throw "unexpected kcOut $line"
}
function Http {
    param([string]$Url, [switch]$NoAuth, [string]$AuthFile)
    if ($NoAuth -or $AuthFile) { return @{ Code = '401'; Text = ''; Json = $null } }
    return @{ Code = $script:LoginReply; Text = ''; Json = $null }
}
function Api([string]$Method, [string]$Path) { return @{ Code = '200'; Json = [pscustomobject]@{ runner = 'k8s' } } }

$LabUser = 'admin'
$SkipBuild = $true
$Image = 'ghcr.io/thrizzo/redteam-llm-lab:latest'
$Overlay = 'deploy/k8s/overlays/dev'
$Context = 'rancher-desktop'
$Console = 'http://127.0.0.1:18080'
$ConsolePort = 18080
$script:WrongAuth = 'auth-wrong'
$script:Failed = 0
function Expect([string]$Case, [bool]$Cond, [string]$What) {
    if ($Cond) { return }
    $script:Failed++
    Write-Output "FAIL $Case : $What"
    $script:Log | ForEach-Object { Write-Output "    | $_" }
    $script:Kc | ForEach-Object { Write-Output "    kubectl $_" }
}
function Has([string]$Line) { return ($script:Log -contains $Line) }
function Like([string]$Pattern) { return [bool]($script:Log | Where-Object { $_ -like $Pattern }) }
function Setup([bool]$HasAuth, [bool]$HasConsole, [int]$RestartExit = 0) {
    $script:Log.Clear(); $script:Kc.Clear()
    $script:HasAuth = $HasAuth; $script:HasConsole = $HasConsole; $script:RestartExit = $RestartExit
    $script:RestartConsole = $false; $script:LabPassword = ''
    $script:SetupResult = Invoke-Setup
}

# ------------------------------------------------------------------------------------------------ cases
$k = 'a new Secret lab/basic-auth while the console runs: the console restarts after the apply, then n8n'
Setup $false $true
Expect $k ($script:SetupResult -eq $true) 'the setup failed'
Expect $k ((($script:Kc | Where-Object { $_ -like '*rollout*' }) -join ' | ') -eq '-n lab rollout restart deploy/console | -n lab rollout status deploy/console --timeout=300s') 'the restart and its wait'
Expect $k ($script:Log.IndexOf('applied') -lt $script:Log.IndexOf('ok console restarted: it reads the new password from Secret lab/basic-auth')) 'the restart after the apply'
Expect $k ($script:Log.IndexOf('ok console restarted: it reads the new password from Secret lab/basic-auth') -lt $script:Log.IndexOf('n8n')) 'n8n after the restart'

$k = 'a first setup (no console yet): no restart'
Setup $false $false
Expect $k ($script:SetupResult -eq $true) 'the setup failed'
Expect $k (-not ($script:Kc | Where-Object { $_ -like '*rollout*' })) 'a restart'
Expect $k (Has 'ok Secret lab/basic-auth (user admin, bcrypt hash)') 'the new Secret'

$k = 'the Secret kept: no restart'
Setup $true $true
Expect $k ($script:SetupResult -eq $true) 'the setup failed'
Expect $k (-not ($script:Kc | Where-Object { $_ -like '*rollout*' })) 'a restart'
Expect $k (Has 'ok Secret lab/basic-auth exists (user admin; its password is kept)') 'the kept Secret'

$k = 'a restart that fails stops the setup before n8n'
Setup $false $true 1
Expect $k ($script:SetupResult -eq $false) 'the setup went on'
Expect $k (Like 'FAIL console restart, so that it reads the new password*') 'the FAIL'
Expect $k (-not (Has 'n8n')) 'n8n ran'

$k = 'a refused password (401): the reason and how to set a new one'
$script:Log.Clear(); $script:LabPassword = ''; $script:LoginReply = '401'
Open-Console
Expect $k (Has 'FAIL login: admin -> 200') 'the FAIL'
Expect $k (Like 'note Caddy refused this password: it is not the one Secret lab/basic-auth was made with*') 'the reason'
Expect $k (Like 'note       Forgotten? kubectl --context rancher-desktop -n lab delete secret basic-auth   then -Setup again*') 'the way out'
Expect $k ($script:ConsoleOk -eq $false) 'the console counted as reachable'

$k = 'another answer (502): it is named, with where to look'
$script:Log.Clear(); $script:LabPassword = ''; $script:LoginReply = '502'
Open-Console
Expect $k (Like 'note the console answered HTTP 502 to the login (a wrong password gets 401)*') 'the note'
Expect $k (-not (Like 'note Caddy refused*')) 'blamed the password'

$k = 'the right password'
$script:Log.Clear(); $script:LabPassword = ''; $script:LoginReply = '200'
Open-Console
Expect $k ((Has 'ok login: admin -> 200') -and $script:ConsoleOk) 'the login'
Expect $k (Has 'ok the console runs stages as Kubernetes Jobs (runner k8s)') 'the runner check'

if ($script:Failed) { Write-Output "$($script:Failed) failed"; exit 1 }
Write-Output 'rancher-dev.ps1 console password: 7 cases as expected'
