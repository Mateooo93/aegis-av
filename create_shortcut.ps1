# Creates Start Menu AND Desktop shortcuts for Aegis AV.
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Get-Location }

$WshShell = New-Object -ComObject WScript.Shell
$IconPath = Join-Path $ScriptDir "icon.ico"
$VbsPath  = Join-Path $ScriptDir "aegis.vbs"

function New-AegisShortcut($linkPath) {
    $sc = $WshShell.CreateShortcut($linkPath)
    $sc.TargetPath       = "wscript.exe"
    $sc.Arguments        = "`"$VbsPath`""
    $sc.WorkingDirectory = $ScriptDir
    $sc.Description      = "Aegis AV Security Suite"
    if (Test-Path $IconPath) { $sc.IconLocation = $IconPath }
    $sc.Save()
    Write-Output "Shortcut created: $linkPath"
}

$StartMenuLink = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Aegis AV.lnk"
$DesktopLink   = Join-Path ([Environment]::GetFolderPath("Desktop")) "Aegis AV.lnk"

New-AegisShortcut $StartMenuLink
New-AegisShortcut $DesktopLink
