; Instalador de RedVisión para Windows (Inno Setup 6).
; ISCC /DAppVersion=0.1.0 /DSourceExe=ruta\redvision.exe /DOutputDir=dist redvision.iss

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\target\release\redvision.exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{6E1B6B2C-5B8E-4E58-9A51-7A4D3C0F2B11}
AppName=RedVisión
AppVersion={#AppVersion}
AppPublisher=AsturTorQue
AppPublisherURL=https://github.com/AsturTorQue/Redvision
DefaultDirName={autopf}\RedVision
DefaultGroupName=RedVisión
UninstallDisplayIcon={app}\redvision.exe
SetupIconFile=..\..\assets\icon.ico
OutputDir={#OutputDir}
OutputBaseFilename=RedVision-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\RedVisión"; Filename: "{app}\redvision.exe"
Name: "{group}\Desinstalar RedVisión"; Filename: "{uninstallexe}"
Name: "{autodesktop}\RedVisión"; Filename: "{app}\redvision.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\redvision.exe"; Description: "{cm:LaunchProgram,RedVisión}"; Flags: nowait postinstall skipifsilent
