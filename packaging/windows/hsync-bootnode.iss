; HSYNC Bootnode — Windows installer (Inno Setup 6)
;
; Per-machine install (admin): the frozen daemon under Program Files, registered
; as a Windows service through WinSW (hsync-bootnode-service.exe + the frozen
; service XML shipped next to this script).
;
; Built by .github/workflows/release.yml (windows-amd64 matrix entry), which
; compiles the .exe and downloads WinSW first, passing:
;   /DAppVersion=<semver>   /DSourceExe=<path to hsync-bootnode.exe>
;   /DWinSWPath=<path to WinSW-x64.exe>   /DOutDir=<output dir>

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceExe
  #define SourceExe "hsync-bootnode.exe"
#endif
#ifndef WinSWPath
  #define WinSWPath "WinSW-x64.exe"
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
AppId={{A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D}
AppName=HSYNC Bootnode
AppVersion={#AppVersion}
AppVerName=HSYNC Bootnode {#AppVersion}
AppPublisher=HSYNC
AppPublisherURL=https://github.com/albertsdk/hsync-bootnode
DefaultDirName={autopf}\HSYNC Bootnode
DisableDirPage=no
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir={#OutDir}
OutputBaseFilename=hsync-bootnode-{#AppVersion}-windows-amd64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=HSYNC Bootnode
UninstallDisplayIcon={app}\hsync-bootnode.exe

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#WinSWPath}"; DestDir: "{app}"; DestName: "hsync-bootnode-service.exe"; Flags: ignoreversion
Source: "hsync-bootnode-service-frozen.xml"; DestDir: "{app}"; \
    DestName: "hsync-bootnode-service.xml"; Flags: ignoreversion

[Dirs]
; Machine-wide, writable data dir for the TLS identity (see the service XML).
Name: "{commonappdata}\hsync-bootnode"

[Run]
; Grant the LocalService account (SID S-1-5-19) modify rights on the data dir.
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\hsync-bootnode"" /grant *S-1-5-19:(OI)(CI)M /T"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Preparing the HSYNC bootnode data directory..."
Filename: "{app}\hsync-bootnode-service.exe"; Parameters: "install"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Installing the HSYNC bootnode service..."
Filename: "{app}\hsync-bootnode-service.exe"; Parameters: "start"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Starting the HSYNC bootnode service..."

[UninstallRun]
Filename: "{app}\hsync-bootnode-service.exe"; Parameters: "stop"; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\hsync-bootnode-service.exe"; Parameters: "uninstall"; \
    Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
