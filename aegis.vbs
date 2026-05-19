' Aegis AV silent launcher.
' Self-locating: works no matter where the project is moved to.

Set fso      = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
mainPy    = fso.BuildPath(scriptDir, "main.py")

If Not fso.FileExists(mainPy) Then
    MsgBox "Aegis AV: main.py not found in " & scriptDir, vbCritical, "Aegis AV"
    WScript.Quit 1
End If

' Resolve Python: prefer the user's Python 3.10 install, fall back to PATH "python"
python310 = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python310\python.exe")
If fso.FileExists(python310) Then
    pythonExe = python310
Else
    pythonExe = "python.exe"
End If

WshShell.CurrentDirectory = scriptDir
WshShell.Run """" & pythonExe & """ """ & mainPy & """", 0, False
