; Установщик SessionVault. Вся логика (учётка vault, права, служба, откат, возврат данных при удалении) живёт в самой
; программе (sessionvault install / uninstall); здесь только копирование файла и вызов этих команд.

[Setup]
AppId={{B6F1E3E2-9A7C-4D55-8B7E-5C2E7F3A9D10}
AppName=SessionVault
AppVersion=1.1.0
AppPublisher=SessionVault
DefaultDirName={autopf}\SessionVault
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=SessionVaultSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\sessionvault.exe

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.HardenTask=Тихие меры защиты: шифровать файл подкачки, отключить гибернацию и дампы памяти (нужна перезагрузка)
english.HardenTask=Quiet hardening: encrypt the page file, turn off hibernation and memory dumps (restart required)
russian.StartTray=Запустить SessionVault и открыть мастер первой настройки
english.StartTray=Start SessionVault and open the first-time setup
russian.HardenFailed=Не удалось включить тихие меры защиты. SessionVault установлен; повторить можно командой "sessionvault harden" от администратора.
english.HardenFailed=Could not turn on the quiet hardening. SessionVault is installed; you can retry with "sessionvault harden" as administrator.
russian.AdminAccount=Учётная запись, в которой вы работаете, входит в группу администраторов. Администратор обходит права доступа к файлам, поэтому SessionVault не сможет её защитить. Работайте в обычной учётной записи и повторите установку.
english.AdminAccount=The account you are using is in the Administrators group. An administrator bypasses file permissions, so SessionVault cannot protect it. Use a regular account and run the setup again.
russian.InstallFailed=Не удалось установить службу SessionVault (код %1). Подробности покажет команда "sessionvault install" в консоли администратора.
english.InstallFailed=Could not install the SessionVault service (code %1). Run "sessionvault install" in an administrator console for details.
russian.UninstallFailed=Данные не возвращены, поэтому SessionVault не удалён. Проверьте мастер-пароль и повторите.
english.UninstallFailed=Your data was not restored, so SessionVault was not removed. Check the master password and try again.

[Tasks]
Name: "harden"; Description: "{cm:HardenTask}"

[Files]
Source: "..\dist\sessionvault.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\sessionvault.exe"; Parameters: "tray"; Description: "{cm:StartTray}"; Flags: postinstall nowait runasoriginaluser skipifsilent

[Code]
function RunSV(const Params: String; Show: Integer; var Code: Integer): Boolean;
begin
  Result := Exec(ExpandConstant('{app}\sessionvault.exe'), Params, '', Show, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  if RunSV('install', SW_HIDE, Code) and (Code = 0) then
  begin
    if WizardIsTaskSelected('harden') and not (RunSV('harden', SW_HIDE, Code) and (Code = 0)) then
      MsgBox(CustomMessage('HardenFailed'), mbInformation, MB_OK);
    Exit;
  end;
  if Code = 3 then
    MsgBox(CustomMessage('AdminAccount'), mbError, MB_OK)
  else
    MsgBox(FmtMessage(CustomMessage('InstallFailed'), [IntToStr(Code)]), mbError, MB_OK);
  Abort;
end;

{ Данные возвращаются до удаления файлов: если пароль неверен или возврат не удался, удаление отменяется. }
function InitializeUninstall(): Boolean;
var
  Code: Integer;
begin
  Result := RunSV('uninstall -pause', SW_SHOW, Code) and (Code = 0);
  if not Result then
    MsgBox(CustomMessage('UninstallFailed'), mbError, MB_OK);
end;
