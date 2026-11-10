; Script generated for Inno Setup 6
; Kelan Community Edition Windows x64 Installer

#define MyAppName "Kelan Community"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Tanush Jain"
#define MyAppURL "https://github.com/Tanush-Jain/kelan"
#define MyAppExeName "kelan.exe"

[Setup]
AppId={{D37D3E5B-0F88-4F7C-904D-4E9A7B31792B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Kelan
DefaultGroupName=Kelan
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\dist
OutputBaseFilename=KelanSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
InfoBeforeFile=install_notice.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add Kelan to System PATH (recommended)"; GroupDescription: "System Integration:"
Name: "desktopicon"; Description: "Create a &desktop shortcut for Kelan CLI"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Source is the PyInstaller onedir dist output
Source: "..\..\dist\kelan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Kelan CLI"; Filename: "{cmd}"; Parameters: "/K ""{app}\{#MyAppExeName}"" --help"; WorkingDir: "{userdesktop}"
Name: "{group}\Kelan Dashboard"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--dashboard"; WorkingDir: "{app}"
Name: "{group}\Kelan Setup Wizard"; Filename: "{app}\{#MyAppExeName}"; Parameters: "setup"; WorkingDir: "{app}"
Name: "{group}\Uninstall Kelan"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Kelan CLI"; Filename: "{cmd}"; Parameters: "/K ""{app}\{#MyAppExeName}"" --help"; WorkingDir: "{userdesktop}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "setup --yes"; Description: "Run initial Kelan setup (initialize directories and intelligence store)"; Flags: postinstall nowait skipifsilent unchecked

[Registry]
; Add to system PATH if selected
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: addtopath

[Code]
// Helper to avoid duplicate PATH entries
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + UpperCase(Param) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
end;

// Remove from PATH on uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AppDir, OrigPath, NewPath: string;
  P: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    AppDir := ExpandConstant('{app}');
    if RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', OrigPath) then
    begin
      P := Pos(';' + UpperCase(AppDir), ';' + UpperCase(OrigPath));
      if P > 0 then
      begin
        NewPath := Copy(OrigPath, 1, P - 1) + Copy(OrigPath, P + Length(AppDir) + 1, Length(OrigPath));
        RegWriteStringValue(HKEY_LOCAL_MACHINE,
          'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
          'Path', NewPath);
      end;
    end;

    // Prompt user to retain or purge user data
    if MsgBox('Do you want to retain your Kelan scan history and vulnerability intelligence database? Click Yes to keep your data, or No to permanently delete it.', mbConfirmation, MB_YESNO) = IDNO then
    begin
      DelTree(ExpandConstant('{localappdata}\kelan'), True, True, True);
      DelTree(ExpandConstant('{appdata}\kelan'), True, True, True);
    end;
  end;
end;

