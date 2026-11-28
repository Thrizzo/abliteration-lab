<#
Runs rancher-dev.ps1's own n8n login step (Invoke-N8n, Read-Secret and n8n's owner rules, taken from the script as
they are) with everything around them stubbed: the prompts get scripted answers, n8n's settings are faked, and
connect_console.py is not started. A fresh n8n's login must fit n8n's rules for its owner account and is asked again
when it does not; an n8n that has its owner is not checked. The rules themselves go through
deploy/n8n/owner_rule_cases.json, whose answers came from n8n's own schema. CI's k3s job runs it with pwsh:

    pwsh deploy/k8s/tests/test-rancher-dev-n8n.ps1
#>
$ErrorActionPreference = 'Continue'                      # as rancher-dev.ps1 runs
Set-StrictMode -Version 1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $here 'rancher-dev.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Output 'rancher-dev.ps1 does not parse'; exit 1 }
foreach ($name in @('Read-Secret', 'Get-N8nPasswordProblem', 'Test-N8nEmail', 'Get-N8nOwnerRule', 'Invoke-N8n')) {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { Write-Output "rancher-dev.ps1 has no function $name"; exit 1 }
    . ([scriptblock]::Create($fn.Extent.Text))
}

# ------------------------------------------------------------------------------------------------ stubs
$script:Log = New-Object System.Collections.Generic.List[string]
$script:Answers = New-Object System.Collections.Generic.List[string]
$script:Calls = New-Object System.Collections.Generic.List[object]
$script:Settings = $null
function Ok([string]$Text) { $script:Log.Add("ok $Text") }
function Bad([string]$Text) { $script:Log.Add("FAIL $Text") }
function Note([string]$Text) { $script:Log.Add("note $Text") }
function Write-Host { param([Parameter(Position = 0)]$Object, $ForegroundColor) $script:Log.Add("say $Object") }
function Show-Trouble { }
function Find-Python { return @('python3') }
function Start-Forward { }
function Wait-For($Seconds, [scriptblock]$Until, $Every) { return (& $Until) }
function Http {
    param([string]$Url, [switch]$NoAuth)
    if ($Url -like '*/healthz/readiness') { return @{ Code = '200'; Text = '{"status":"ok"}'; Json = $null } }
    if ($Url -like '*/rest/settings') { return $script:Settings }
    throw "unexpected request: $Url"
}
function Exe([string]$Program, [string[]]$A) {
    $script:Calls.Add([pscustomobject]@{ Args = ($A -join ' '); Password = $env:N8N_PASSWORD })
    [IO.File]::WriteAllText($A[[array]::IndexOf($A, '--secret-file') + 1], '{}')
    $global:LASTEXITCODE = 0
    return 'connect_console.py: done'
}
function kc([string[]]$A) { $global:LASTEXITCODE = 0; return '' }
function Read-Host {
    param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
    $script:Log.Add("ask $Prompt")
    if ($script:Answers.Count -eq 0) { throw "no answer left for: $Prompt" }
    $a = $script:Answers[0]
    $script:Answers.RemoveAt(0)
    if (-not $AsSecureString) { return $a }
    $s = New-Object System.Security.SecureString
    foreach ($ch in $a.ToCharArray()) { $s.AppendChar($ch) }
    return $s
}

# what a fresh n8n 2.48.7 says about accounts, one that has its owner, and one whose settings do not say
function Settings([string]$Json) {
    if (-not $Json) { return @{ Code = '200'; Text = 'n8n is starting up. Please wait'; Json = $null } }
    return @{ Code = '200'; Text = $Json; Json = ($Json | ConvertFrom-Json) }
}
$fresh = Settings '{"data":{"settingsMode":"public","userManagement":{"showSetupOnFirstLoad":true,"passwordMinLength":8}}}'
$fresh12 = Settings '{"data":{"settingsMode":"public","userManagement":{"showSetupOnFirstLoad":true,"passwordMinLength":12}}}'
$owned = Settings '{"data":{"settingsMode":"public","userManagement":{"showSetupOnFirstLoad":false,"passwordMinLength":8}}}'
$unsaid = Settings ''

$script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('rancher-dev-n8n-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:Tmp
$N8nPort = 15678
$HostOllama = $false
$HostOllamaUrl = 'http://192.168.127.254:11434'
$NonInteractive = $false
$N8nEmail = ''
$script:Failed = 0

function Expect([string]$Case, [bool]$Cond, [string]$What) {
    if ($Cond) { return }
    $script:Failed++
    Write-Output "FAIL $Case : $What"
    $script:Log | ForEach-Object { Write-Output "    | $_" }
}
function Has([string]$Line) { return ($script:Log -contains $Line) }

# Invoke-N8n with these answers and settings; $Env* stand for N8N_EMAIL and N8N_PASSWORD (then -NonInteractive)
function Run($Settings, [string[]]$Answers = @(), [string]$EnvEmail = '', [string]$EnvPassword = '') {
    $script:Log.Clear(); $script:Calls.Clear(); $script:Answers.Clear()
    foreach ($a in $Answers) { $script:Answers.Add($a) }
    $script:Settings = $Settings
    $script:N8nEmail = $EnvEmail
    $script:NonInteractive = [bool]$EnvPassword
    if ($EnvPassword) { $env:N8N_PASSWORD = $EnvPassword } else { Remove-Item Env:N8N_PASSWORD -ErrorAction SilentlyContinue }
    try { Invoke-N8n } catch { $script:Log.Add("threw $($_.Exception.Message)") }
    Remove-Item Env:N8N_PASSWORD -ErrorAction SilentlyContinue
}
function Posted([string]$Case, [string]$Email, [string]$Password) {
    Expect $Case ($script:Calls.Count -eq 1) "connect_console.py ran $($script:Calls.Count) times, not once"
    if ($script:Calls.Count -ne 1) { return }
    Expect $Case ($script:Calls[0].Args -like "*--email $Email --setup-owner*") "its e-mail: $($script:Calls[0].Args)"
    Expect $Case ($script:Calls[0].Password -ceq $Password) 'it got another password'
    Expect $Case ($script:Answers.Count -eq 0) "$($script:Answers.Count) answers left over"
    Expect $Case (-not ($script:Log | Where-Object { $_ -like 'FAIL *' -or $_ -like 'threw *' })) 'a FAIL'
}

# ------------------------------------------------------------------------------------------------ the rules
$cases = Get-Content -Raw -Encoding UTF8 (Join-Path $here '../../n8n/owner_rule_cases.json') | ConvertFrom-Json
if (@($cases.password).Count -lt 20 -or @($cases.email).Count -lt 20) { Write-Output 'deploy/n8n/owner_rule_cases.json: too few cases read'; exit 1 }
foreach ($c in $cases.password) {
    $got = Get-N8nPasswordProblem $c.password $c.min
    Expect 'password rule' ($got -ceq $c.problem) ("{0} (min {1}): '{2}', n8n: '{3}'" -f $c.password, $c.min, $got, $c.problem)
}
foreach ($c in $cases.email) {
    $got = Test-N8nEmail $c.email
    Expect 'e-mail rule' ($got -eq $c.ok) ("'{0}': {1}, n8n: {2}" -f $c.email, $got, $c.ok)
}

# ------------------------------------------------------------------------------------------------ the prompts
$k = 'fresh n8n: a wrong e-mail and a password without number or capital are asked again'
Run $fresh @('owner@lab', 'owner@lab.test', 'abcdefgh', 'Abcdefg1', 'Abcdefg1')
Posted $k 'owner@lab.test' 'Abcdefg1'
Expect $k (Has "ask E-mail for n8n's new owner account") 'the owner-account prompt'
Expect $k (Has 'say n8n would refuse that e-mail address for its owner account (name@domain.tld); again.') 'the e-mail asked again'
Expect $k (Has 'say n8n would refuse it for its owner account: it needs a number, a capital letter; again.') 'the password asked again'
Expect $k (Has "ask Password for n8n's new owner account") 'the password prompt'
Expect $k (Has 'ask Again, to confirm') 'the password confirmed'
Expect $k (Has 'note n8n has no owner account yet: the login you give now becomes it (password: 8 to 64 characters with a number and a capital letter)') 'the note'

$k = 'fresh n8n: two different passwords are asked again'
Run $fresh @('owner@lab.test', 'Abcdefg1', 'Abcdefg2', 'Abcdefg9', 'Abcdefg9')
Posted $k 'owner@lab.test' 'Abcdefg9'
Expect $k (Has 'say They differ; again.') 'the mismatch'

$k = 'fresh n8n: a confirmation that differs only in case is asked again'
Run $fresh @('owner@lab.test', 'Abcdefg1', 'abcdefg1', 'Abcdefg1', 'Abcdefg1')
Posted $k 'owner@lab.test' 'Abcdefg1'
Expect $k (Has 'say They differ; again.') 'the mismatch'

$k = "fresh n8n: n8n's own minimum length"
Run $fresh12 @('owner@lab.test', 'Abcdefgh1', 'Abcdefgh1234', 'Abcdefgh1234')
Posted $k 'owner@lab.test' 'Abcdefgh1234'
Expect $k (Has 'say n8n would refuse it for its owner account: it needs 12 to 64 characters (it has 9); again.') 'the length'

$k = 'fresh n8n: an empty e-mail is asked again, spaces around it go'
Run $fresh @('', '  owner@lab.test ', 'Abcdefg1', 'Abcdefg1')
Posted $k 'owner@lab.test' 'Abcdefg1'

$k = 'an n8n with its owner: the login is a login, not checked, asked once'
Run $owned @('someone@lab.test', 'x')
Posted $k 'someone@lab.test' 'x'
Expect $k ((Has 'ask n8n login e-mail') -and (Has 'ask n8n password')) 'the login prompts'
Expect $k (-not (Has 'ask Again, to confirm')) 'no confirmation'

$k = 'settings that do not say: the hints, n8n decides'
Run $unsaid @('someone@lab.test', 'x')
Posted $k 'someone@lab.test' 'x'
Expect $k (Has 'ask n8n password (a fresh n8n: 8+ characters with a number and a capital letter)') 'the hint prompt'

$k = 'unattended, fresh n8n: N8N_PASSWORD that n8n would refuse'
Run $fresh -EnvEmail 'ci@example.com' -EnvPassword 'ci-only-pass'
Expect $k ($script:Calls.Count -eq 0) 'connect_console.py ran'
Expect $k (Has 'FAIL N8N_PASSWORD: n8n would refuse it for its owner account: it needs a number, a capital letter') 'the FAIL'
Expect $k (-not ($script:Log | Where-Object { $_ -like 'ask *' })) 'a prompt'

$k = 'unattended, fresh n8n: N8N_EMAIL that n8n would refuse'
Run $fresh -EnvEmail 'ci@example' -EnvPassword 'Ci-only-pass1'
Expect $k ($script:Calls.Count -eq 0) 'connect_console.py ran'
Expect $k (Has 'FAIL -N8nEmail (N8N_EMAIL) is not an e-mail address n8n takes for its owner account (name@domain.tld)') 'the FAIL'

$k = "unattended, fresh n8n: CI's login"
Run $fresh -EnvEmail 'ci@example.com' -EnvPassword 'Ci-only-pass1'
Posted $k 'ci@example.com' 'Ci-only-pass1'
Expect $k (-not ($script:Log | Where-Object { $_ -like 'ask *' })) 'a prompt'

Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue
if ($script:Failed) { Write-Output "$($script:Failed) failed"; exit 1 }
Write-Output ('rancher-dev.ps1 n8n login: {0} password and {1} e-mail cases as n8n answers them, 10 prompt runs as expected' -f @($cases.password).Count, @($cases.email).Count)
exit 0                                                   # not the last stub's exit code: CI's pwsh step ends with exit $LASTEXITCODE
