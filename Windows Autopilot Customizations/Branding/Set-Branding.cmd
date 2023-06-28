@ECHO OFF

REM Set current working directory
set loc=%~dp0

REM Set OMA-URI for lock screen image
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /T REG_SZ /V "LockScreenImagePath" /D "C:\ProgramData\Branding\LockScreen.jpg" /f

REM Set OMA-URL for desktop background
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /T REG_SZ /V "DesktopImagePath" /D "C:\Windows\Web\4K\Wallpaper\Windows\img0_3840x2160.jpg" /f

cmd.exe /c xcopy "LockScreen.jpg" "C:\ProgramData\Branding\" /E /F /Y

REM Take ownership of the orignal wallpaper files
takeown /f "%windir%\WEB\wallpaper\Windows\img0.jpg"
takeown /f "%windir%\Web\4K\Wallpaper\Windows\*.*"
icacls "%windir%\WEB\Wallpaper\Windows\img0.jpg" /Grant System:(F)
icacls "%windir%\Web\4K\Wallpaper\Windows\*.*" /Grant System:(F)

REM Delete the original wallpaper files
del "%windir%\WEB\Wallpaper\Windows\img0.jpg"
del /q "%windir%\Web\4K\Wallpaper\Windows\*.*"

REM Copy the new wallpaper files
copy "%loc%img0.jpg" "%windir%\WEB\Wallpaper\Windows\img0.jpg"
xcopy "%loc%4k\*.*" "%windir%\Web\4K\Wallpaper\Windows" /Y