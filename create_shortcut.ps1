$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}
$WshShell = New-Object -ComObject WScript.Shell
$ShortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Aegis AV.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = """$ScriptDir\aegis.vbs"""
$Shortcut.WorkingDirectory = "$ScriptDir"
$Shortcut.Description = "Aegis AV Security Suite"
$Shortcut.IconLocation = "$ScriptDir\icon.ico"
$Shortcut.Save()
Write-Output "Start Menu shortcut created successfully at: $ShortcutPath"
