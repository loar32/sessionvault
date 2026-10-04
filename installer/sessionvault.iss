; Установщик SessionVault. Вся логика (учётка vault, права, служба, откат, возврат данных при удалении) живёт в самой
; программе (sessionvault install / uninstall); здесь только копирование файла и вызов этих команд.

[Setup]
AppId={{B6F1E3E2-9A7C-4D55-8B7E-5C2E7F3A9D10}
AppName=SessionVault
AppVersion=0.9
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

[Tasks]
Name: "harden"; Description: "Тихие меры защиты: шифровать файл подкачки, отключить гибернацию и дампы памяти (нужна перезагрузка)"

[Files]
Source: "..\dist\sessionvault.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\sessionvault.exe"; Parameters: "import-tdata -pause"; Description: "Защитить сессию Telegram (задать мастер-пароль)"; Flags: postinstall skipifsilent waituntilterminated

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
      MsgBox('Не удалось включить тихие меры защиты. SessionVault установлен; повторить можно командой "sessionvault harden" от администратора.', mbInformation, MB_OK);
    Exit;
  end;
  if Code = 3 then
    MsgBox('Учётная запись, в которой вы работаете, входит в группу администраторов. ' +
      'Администратор обходит права доступа к файлам, поэтому SessionVault не сможет её защитить. ' +
      'Работайте в обычной учётной записи и повторите установку.', mbError, MB_OK)
  else
    MsgBox('Не удалось установить службу SessionVault (код ' + IntToStr(Code) + '). ' +
      'Подробности покажет команда "sessionvault install" в консоли администратора.', mbError, MB_OK);
  Abort;
end;

{ Данные возвращаются до удаления файлов: если пароль неверен или возврат не удался, удаление отменяется. }
function InitializeUninstall(): Boolean;
var
  Code: Integer;
begin
  Result := RunSV('uninstall -pause', SW_SHOW, Code) and (Code = 0);
  if not Result then
    MsgBox('Данные не возвращены, поэтому SessionVault не удалён. Проверьте мастер-пароль и повторите.', mbError, MB_OK);
end;
