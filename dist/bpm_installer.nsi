; Bare Password Manager Installer Script

Name "Bare Password Manager"
OutFile "BarePasswordManagerInstaller.exe"
InstallDir "$PROGRAMFILES\BarePasswordManager"
RequestExecutionLevel admin
SetCompress auto
SetCompressor lzma

Section "Install"

    SetOutPath "$INSTDIR"
    File "bare_password_manager.exe"
    File "logo.png"

    ; Create Desktop Shortcut
    CreateShortcut "$DESKTOP\Bare Password Manager.lnk" "$INSTDIR\bare_password_manager.exe" "" "$INSTDIR\logo.png"

SectionEnd

Section "Uninstall"

    Delete "$INSTDIR\bare_password_manager.exe"
    Delete "$INSTDIR\logo.png"
    Delete "$DESKTOP\Bare Password Manager.lnk"
    RMDir "$INSTDIR"

SectionEnd
