param(
  [string]$RjdPath = ".\target\release\rjd.exe",
  [string]$MinVersion = "21"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $RjdPath)) {
  Write-Error "rjd binary not found: $RjdPath"
}

function Invoke-Rjd {
  param([string[]]$Args)
  & $RjdPath @Args | Out-Host
  return $LASTEXITCODE
}

function Invoke-RjdExpect {
  param(
    [string]$Label,
    [string[]]$Args,
    [int[]]$Allowed
  )

  Write-Host "`n-- $Label --"
  $code = Invoke-Rjd $Args
  Write-Host "exit: $code"
  if ($Allowed -notcontains $code) {
    throw "Unexpected exit code for '$Label'. Allowed: $($Allowed -join ', '), got: $code"
  }
}

Write-Host "== rjd Windows smoke test =="
Write-Host "Binary: $RjdPath"

Invoke-RjdExpect "doctor --strict-json --loader-check" `
  @("doctor", "--strict-json", "--loader-check") `
  @(0)

Invoke-RjdExpect "compat --javainstalled --quiet" `
  @("compat", "--javainstalled", "--quiet") `
  @(0, 2)

Invoke-RjdExpect "compat --javahome --quiet" `
  @("compat", "--javahome", "--quiet") `
  @(0, 2)

Invoke-RjdExpect "compat --javadll --quiet" `
  @("compat", "--javadll", "--quiet") `
  @(0, 2)

Invoke-RjdExpect "compat --javais64bit --quiet" `
  @("compat", "--javais64bit", "--quiet") `
  @(0, 1, 2)

Invoke-RjdExpect "compat --javaminversion $MinVersion --quiet" `
  @("compat", "--javaminversion", $MinVersion, "--quiet") `
  @(0, 1, 2)

Invoke-RjdExpect "compat --javaminversion bad.version --quiet" `
  @("compat", "--javaminversion", "bad.version", "--quiet") `
  @(87)

Write-Host "`nSmoke test completed."
