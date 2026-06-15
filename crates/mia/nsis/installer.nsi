; NSIS source for the FerroGate Machine Identity Agent (MIA) Windows installer.
;
; Built by `make pkg-win`, which passes these defines on the command line:
;   /DVERSION=x.y.z   crate version from Cargo.toml
;   /DBINDIR=path     directory holding the built mia.exe
;   /DOUTFILE=path    output path for the generated setup .exe
;
; The installer drops mia.exe under "Program Files\FerroGate\MIA", adds that
; directory to the system PATH, and registers an entry under Add/Remove
; Programs. MIA is configured via environment variables (see docs/mia.md); on
; Windows the helper API is exposed over a named pipe.

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"

; Instantiate the StrFunc helpers we use (installer: StrStr; uninstaller: StrRep).
${StrStr}
${UnStrRep}

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef BINDIR
  !define BINDIR "..\..\..\target\release"
!endif

!define PRODUCT_NAME      "FerroGate Machine Identity Agent"
!define PRODUCT_PUBLISHER "FerroGate contributors"
!define PRODUCT_HELP      "https://github.com/ffquintella/FerroGate"
!define UNINST_KEY        "Software\Microsoft\Windows\CurrentVersion\Uninstall\FerroGate-MIA"
!define APP_REG_KEY       "Software\FerroGate\MIA"
!define ENV_REG           "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

Name "${PRODUCT_NAME}"
!ifdef OUTFILE
  OutFile "${OUTFILE}"
!else
  OutFile "ferrogate-mia-${VERSION}-x64-setup.exe"
!endif

InstallDir "$PROGRAMFILES64\FerroGate\MIA"
InstallDirRegKey HKLM "${APP_REG_KEY}" "InstallDir"
RequestExecutionLevel admin

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName"    "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName"    "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} installer"
VIAddVersionKey "FileVersion"    "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "${PRODUCT_PUBLISHER}"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "FerroGate MIA requires 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

; Append $INSTDIR to the system PATH if it is not already present.
Function AddToPath
  ReadRegStr $0 HKLM "${ENV_REG}" "Path"
  ${StrStr} $1 "$0" "$INSTDIR"
  StrCmp $1 "" 0 done
  StrCmp $0 "" 0 +3
    StrCpy $0 "$INSTDIR"
    Goto write
  StrCpy $0 "$0;$INSTDIR"
  write:
  WriteRegExpandStr HKLM "${ENV_REG}" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  done:
FunctionEnd

; Remove $INSTDIR from the system PATH.
Function un.RemoveFromPath
  ReadRegStr $0 HKLM "${ENV_REG}" "Path"
  ${UnStrRep} $0 "$0" ";$INSTDIR" ""
  ${UnStrRep} $0 "$0" "$INSTDIR;" ""
  ${UnStrRep} $0 "$0" "$INSTDIR" ""
  WriteRegExpandStr HKLM "${ENV_REG}" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

Section "FerroGate MIA" SecMia
  SectionIn RO
  SetRegView 64
  SetOutPath "$INSTDIR"
  File "${BINDIR}\mia.exe"

  WriteRegStr HKLM "${APP_REG_KEY}" "InstallDir" "$INSTDIR"

  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayName"     "${PRODUCT_NAME}"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKLM "${UNINST_KEY}" "Publisher"       "${PRODUCT_PUBLISHER}"
  WriteRegStr   HKLM "${UNINST_KEY}" "HelpLink"        "${PRODUCT_HELP}"
  WriteRegStr   HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"

  Call AddToPath
SectionEnd

Section "Uninstall"
  SetRegView 64
  Call un.RemoveFromPath

  Delete "$INSTDIR\mia.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  RMDir "$PROGRAMFILES64\FerroGate"

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "${APP_REG_KEY}"
SectionEnd
