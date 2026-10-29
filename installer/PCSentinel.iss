; Inno Setup 6.3+; use scripts/build-installer.ps1 (folder payload, pinned driver, optional signing).
#define AppName "PC Sentinel"
#define AppVersion "0.3.2"
#ifndef AppSource
  #define AppSource "..\..\PCSentinel-Build\publish\v0.3.2-Folder"
#endif
#ifndef PawnIoSetup
  #define PawnIoSetup "deps\PawnIO_setup.exe"
#endif
#define PawnIoSha256 "1f519a22e47187f70a1379a48ca604981c4fcf694f4e65b734aaa74a9fba3032"

[Setup]
AppId={{33407B1E-7E84-4342-A600-F09B8B23D757}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion} (Installer build 1)
VersionInfoVersion=0.3.2.1
AppPublisher=PolDoma
DefaultDirName={commonpf64}\PC Sentinel
UsePreviousAppDir=no
DisableDirPage=yes
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=Output
OutputBaseFilename=PCSentinel-{#AppVersion}-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE-PC-Sentinel.txt
UninstallDisplayIcon={app}\PCSentinel.exe
; Mutex is checked explicitly after the graceful-exit event, not before it.
CloseApplications=yes
RestartApplications=no
#ifdef SigningEnabled
SignTool=pcsentinel
SignedUninstaller=yes
#endif

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "pawnio"; Description: "Установить официальный драйвер PawnIO 2.2.0 для аппаратных температур"; Flags: unchecked; Check: NeedPawnIo
Name: "sensors"; Description: "Установить службу температур CPU/GPU (нужен PawnIO; без UAC при запуске программы)"; Check: SupportedCpu
Name: "desktop"; Description: "Ярлык на рабочем столе"; Flags: unchecked

[Files]
Source: "{#AppSource}\*"; DestDir: "{app}"; Excludes: "*.pdb"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PawnIoSetup}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Tasks: pawnio

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\PCSentinel.exe"
Name: "{group}\Удалить {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\PCSentinel.exe"; Tasks: desktop

[Run]
Filename: "{app}\PCSentinel.exe"; Parameters: "--enable-hardware-temperatures"; Description: "Запустить {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: ServiceReady
Filename: "{app}\PCSentinel.exe"; Description: "Запустить {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: NoServiceReady

[UninstallRun]
Filename: "{app}\Service\PCSentinel.SensorService.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSensorServiceAndAutostart"

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
type
  TServiceStatus = record
    ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
    ServiceSpecificExitCode, CheckPoint, WaitHint: LongWord;
  end;
  TDirectorySecurity = record
    Length: LongWord;
    Descriptor: THandle;
    InheritHandle: LongWord;
  end;
var
  SensorServiceReady: Boolean;
  InstallCompleted: Boolean;
  HadRunningService: Boolean;
  PreviousDirectory: String;

function ConvertDescriptor(Text: String; Revision: LongWord; var Descriptor: THandle; Size: LongWord): Boolean;
external 'ConvertStringSecurityDescriptorToSecurityDescriptorW@advapi32.dll stdcall';
function CreateSecureDirectory(Name: String; var Security: TDirectorySecurity): Boolean;
external 'CreateDirectoryW@kernel32.dll stdcall';
function LocalFree(Memory: THandle): THandle;
external 'LocalFree@kernel32.dll stdcall';

function OpenEvent(Access: LongWord; Inherit: Boolean; Name: String): THandle;
external 'OpenEventW@kernel32.dll stdcall';
function SetEvent(Event: THandle): Boolean;
external 'SetEvent@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): Boolean;
external 'CloseHandle@kernel32.dll stdcall';
function GetFileAttributes(Name: String): Integer;
external 'GetFileAttributesW@kernel32.dll stdcall';
function OpenSCManager(Machine, Database: LongWord; Access: LongWord): THandle;
external 'OpenSCManagerW@advapi32.dll stdcall';
function OpenService(Manager: THandle; Name: String; Access: LongWord): THandle;
external 'OpenServiceW@advapi32.dll stdcall';
function QueryServiceStatus(Service: THandle; var Status: TServiceStatus): Boolean;
external 'QueryServiceStatus@advapi32.dll stdcall';
function ControlService(Service: THandle; Control: LongWord; var Status: TServiceStatus): Boolean;
external 'ControlService@advapi32.dll stdcall';
function CloseServiceHandle(Handle: THandle): Boolean;
external 'CloseServiceHandle@advapi32.dll stdcall';
function StartService(Service: THandle; Count, Arguments: LongWord): Boolean;
external 'StartServiceW@advapi32.dll stdcall';

function SupportedCpu: Boolean;
var Vendor, Identifier: String;
begin
  Result := False;
  if not RegQueryStringValue(HKLM, 'HARDWARE\DESCRIPTION\System\CentralProcessor\0', 'VendorIdentifier', Vendor) then Exit;
  if Vendor = 'GenuineIntel' then Result := True
  else if Vendor = 'AuthenticAMD' then begin
    if RegQueryStringValue(HKLM, 'HARDWARE\DESCRIPTION\System\CentralProcessor\0', 'Identifier', Identifier) then
      Result := (Pos('Family 23 ', Identifier) > 0) or (Pos('Family 24 ', Identifier) > 0) or (Pos('Family 25 ', Identifier) > 0) or (Pos('Family 26 ', Identifier) > 0);
  end;
end;
function PawnIoPresent: Boolean;
begin
  Result := RegKeyExists(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO');
end;
function NeedPawnIo: Boolean;
begin Result := SupportedCpu and not PawnIoPresent; end;
function ServiceReady: Boolean;
begin Result := SensorServiceReady; end;
function NoServiceReady: Boolean;
begin Result := not SensorServiceReady; end;

function CloseDesktop: Boolean;
var Event: THandle; I: Integer;
begin
  Result := True;
  if not CheckForMutexes('Local\PCSentinel.Desktop') then Exit;
  Event := OpenEvent(2, False, 'Local\PCSentinel.RequestExit');
  if Event <> 0 then begin SetEvent(Event); CloseHandle(Event); end;
  for I := 0 to 199 do begin
    if not CheckForMutexes('Local\PCSentinel.Desktop') then Exit;
    Sleep(100);
  end;
  Result := False;
end;

function StopSensors: Boolean;
var Manager, Service: THandle; Status: TServiceStatus; I: Integer;
begin
  Result := True;
  Manager := OpenSCManager(0, 0, 1);
  if Manager = 0 then begin Result := False; Exit; end;
  Service := OpenService(Manager, 'PCSentinelSensors', $24);
  if Service <> 0 then begin
    if QueryServiceStatus(Service, Status) and (Status.CurrentState <> 1) then begin
      HadRunningService := True;
      ControlService(Service, 1, Status);
      Result := False;
      for I := 0 to 299 do begin
        if QueryServiceStatus(Service, Status) and (Status.CurrentState = 1) then begin Result := True; Break; end;
        Sleep(100);
      end;
    end;
    CloseServiceHandle(Service);
  end;
  CloseServiceHandle(Manager);
end;

function InitializeSetup: Boolean;
begin
  Result := CloseDesktop;
  if not Result then MsgBox('Завершите PC Sentinel через «Выход» в трее. Старая переносная версия не поддерживает автоматический запрос выхода.', mbError, MB_OK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Target, Parent: String; Descriptor: THandle; Security: TDirectorySecurity;
begin
  Result := '';
  Log('Prepare: begin');
  Target := RemoveBackslash(ExpandFileName(ExpandConstant('{app}')));
  Parent := RemoveBackslash(ExpandFileName(ExpandConstant('{commonpf64}')));
  if CompareText(Target, Parent + '\PC Sentinel') <> 0 then begin Result := 'Разрешена установка только в Program Files\PC Sentinel.'; Exit; end;
  if not CloseDesktop then begin Result := 'Закройте PC Sentinel через «Выход» в трее.'; Exit; end;
  Log('Prepare: desktop closed');
  if not StopSensors then begin Result := 'Не удалось остановить службу датчиков.'; Exit; end;
  Log('Prepare: service stopped');
  if DirExists(Target) then begin
    Log('Prepare: checking existing directory attributes');
    if (GetFileAttributes(Target) and $400) <> 0 then begin Result := 'Каталог установки является reparse point; установка остановлена.'; Exit; end;
    Log('Prepare: existing directory is not a reparse point');
    { Separator arguments are Char, not String; empty strings cause a Pascal Script runtime type error. }
    PreviousDirectory := Target + '.previous-' + GetDateTimeString('yyyymmddhhnnss', '-', ':') + '-' + Copy(GetSHA256OfString(ExpandConstant('{tmp}')), 1, 8);
    if CompareText(ExtractFileDir(PreviousDirectory), Parent) <> 0 then begin Result := 'Неверный путь резервной копии.'; Exit; end;
    if not RenameFile(Target, PreviousDirectory) then begin Result := 'Не удалось сохранить предыдущую папку установки.'; Exit; end;
  end;
  Descriptor := 0;
  if not ConvertDescriptor('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)', 1, Descriptor, 0) then begin Result := 'Не удалось создать защищённые разрешения каталога.'; Exit; end;
  { Inno Setup 6 is a 32-bit host: SECURITY_ATTRIBUTES is 12 bytes. }
  Security.Length := 12; Security.Descriptor := Descriptor; Security.InheritHandle := 0;
  if not CreateSecureDirectory(Target, Security) then Result := 'Не удалось создать новый защищённый каталог установки.';
  LocalFree(Descriptor);
end;

procedure InstallDriver;
var Setup: String; Code: Integer;
begin
  Setup := ExpandConstant('{tmp}\PawnIO_setup.exe');
  if Lowercase(GetSHA256OfFile(Setup)) <> '{#PawnIoSha256}' then begin
    MsgBox('SHA256 PawnIO не совпадает с проверенной версией. Драйвер не установлен.', mbError, MB_OK); Exit;
  end;
  Code := -1;
  if not Exec(Setup, '-install -silent', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    MsgBox('PawnIO не установлен; код: ' + IntToStr(Code), mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer; ServiceExe: String;
begin
  if CurStep = ssDone then begin InstallCompleted := True; Exit; end;
  if CurStep <> ssPostInstall then Exit;
  if WizardIsTaskSelected('pawnio') and NeedPawnIo then InstallDriver;
  ServiceExe := ExpandConstant('{app}\Service\PCSentinel.SensorService.exe');
  Code := -1;
  if WizardIsTaskSelected('sensors') and PawnIoPresent then begin
    SensorServiceReady := Exec(ServiceExe, '--install', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
    if not SensorServiceReady then MsgBox('Не удалось настроить службу температур, код: ' + IntToStr(Code) + '. Основная программа установлена.', mbError, MB_OK);
  end else Exec(ServiceExe, '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if PreviousDirectory <> '' then begin
    Code := -1;
    if not Exec(ServiceExe, '--prune-backup "' + PreviousDirectory + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      Log('Previous directory retained (safety/permissions): ' + PreviousDirectory);
  end;
end;

procedure DeinitializeSetup;
var Target: String; Manager, Service: THandle;
begin
  if InstallCompleted then Exit;
  if (PreviousDirectory <> '') and DirExists(PreviousDirectory) then begin
    Target := ExpandConstant('{app}');
    { RemoveDir removes only an empty directory; never recursively delete an unknown tree. }
    if DirExists(Target) then RemoveDir(Target);
    if not DirExists(Target) then RenameFile(PreviousDirectory, Target)
    else Log('Previous installation retained for recovery: ' + PreviousDirectory);
  end;
  if HadRunningService then begin
    Manager := OpenSCManager(0, 0, 1);
    if Manager <> 0 then begin
      Service := OpenService(Manager, 'PCSentinelSensors', $10);
      if Service <> 0 then begin StartService(Service, 0, 0); CloseServiceHandle(Service); end;
      CloseServiceHandle(Manager);
    end;
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := CloseDesktop;
  if not Result then MsgBox('Завершите PC Sentinel через «Выход» в трее перед удалением.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and PawnIoPresent then begin
    if not UninstallSilent then MsgBox('История и настройки сохранены в LocalAppData\PCSentinel. PawnIO оставлен: его могут использовать другие программы. При необходимости удалите PawnIO отдельно через Приложения Windows.', mbInformation, MB_OK);
  end;
end;
