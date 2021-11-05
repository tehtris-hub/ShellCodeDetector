REM Disable defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

REM Create single user
net user /add user user
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "user" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "user" /f

REM Stop big brother
powershell -Command Set-ExecutionPolicy Bypass -Force -Scope CurrentUser
powershell -Command (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/hahndorf/Set-Privacy/master/Set-Privacy.ps1')^|out-file %temp%\set-provacy.ps1
powershell -File %temp%\set-provacy.ps1 -strong
del /f %temp%\set-provacy.ps1

REM Pintools dependancies 32/64 bits

powershell -Command Invoke-WebRequest -Uri 'https://aka.ms/vs/16/release/vc_redist.x86.exe' -OutFile '%temp%\vc_redist.x86.exe'
%temp%\vc_redist.x86.exe /install /passive
del %temp%\vc_redist.x86.exe

powershell -Command Invoke-WebRequest -Uri 'https://aka.ms/vs/16/release/vc_redist.x64.exe' -OutFile '%temp%\vc_redist.x64.exe'
%temp%\vc_redist.x64.exe /install /passive
del %temp%\vc_redist.x64.exe
