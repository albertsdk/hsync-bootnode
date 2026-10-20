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
; Numeric file version (up to four dot-separated numbers). The workflow passes
; the SemVer stripped of its prerelease/build suffix.
#ifndef VersionInfoVersion
  #define VersionInfoVersion "0.0.0.0"
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
VersionInfoVersion={#VersionInfoVersion}
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
; Machine-wide, writable data dir for the TLS identity and the service logs
; (see the service XML); LocalService gets modify rights below.
Name: "{commonappdata}\hsync-bootnode"
Name: "{commonappdata}\hsync-bootnode\logs"

[Run]
; Grant the LocalService account (SID S-1-5-19) modify rights on the data dir.
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\hsync-bootnode"" /grant *S-1-5-19:(OI)(CI)M /T"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Preparing the HSYNC bootnode data directory..."
; The group-keys file is created empty by [Code] before this section runs.
; Administrators/SYSTEM keep full control, LocalService only reads it, and
; inherited permissions are removed so the data-dir grant cannot widen it.
Filename: "{sys}\icacls.exe"; \
    Parameters: """{commonappdata}\hsync-bootnode\group-keys"" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F *S-1-5-19:R"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Protecting the HSYNC bootnode group keys file..."
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

[Code]
{ The frozen service always passes --keys-file, so the file must exist before
  the service starts: an empty file means open mode (no protected buckets). }
procedure CurStepChanged(CurStep: TSetupStep);
var
  KeysFile: String;
begin
  if CurStep = ssPostInstall then
  begin
    KeysFile := ExpandConstant('{commonappdata}\hsync-bootnode\group-keys');
    if not FileExists(KeysFile) then
      SaveStringToFile(KeysFile, '', False);
  end;
end;
