[Setup]
AppName=NetWatch
AppVersion=1.1.0
AppPublisher=NetWatch Security
AppPublisherURL=https://netwatch.app
DefaultDirName={autopf}\NetWatch
DefaultGroupName=NetWatch
OutputDir=D:\Prog\NetSnitch\installer_output
OutputBaseFilename=NetWatch_Setup_1.1.0
SetupIconFile=D:\Prog\NetSnitch\NetWatch\Assets\netwatch.ico
UninstallDisplayIcon={app}\NetWatch.exe
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
DisableProgramGroupPage=yes
LicenseFile=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "D:\Prog\NetSnitch\v8\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\NetWatch"; Filename: "{app}\NetWatch.exe"; IconFilename: "{app}\netwatch.ico"
Name: "{autodesktop}\NetWatch"; Filename: "{app}\NetWatch.exe"; IconFilename: "{app}\netwatch.ico"; Tasks: desktopicon
Name: "{autostartup}\NetWatch"; Filename: "{app}\NetWatch.exe"; IconFilename: "{app}\netwatch.ico"; Tasks: startup

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"
Name: "startup"; Description: "Запускать при старте Windows"; GroupDescription: "Автозагрузка:"

[Run]
Filename: "{app}\NetWatch.exe"; Description: "Запустить NetWatch"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\NetWatch"
