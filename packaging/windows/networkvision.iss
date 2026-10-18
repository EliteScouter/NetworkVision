; Inno Setup 6 script for the NetworkVision Windows installer.
;
;   iscc /DAppVersion=1.2.3 /DSourceDir=<pyinstaller one-folder dir> /DOutputDir=<out> packaging\windows\networkvision.iss
;
; SourceDir must contain networkvision.exe (+ _internal), static\ (the web UI),
; NetworkVisionService.exe (WinSW) and NetworkVisionService.xml. build.ps1 prepares it.
; Silent install: setup.exe /VERYSILENT /PORT=8080

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\windows\NetworkVision"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{7861963A-5F34-48C6-BCFF-80CBF17C60A4}
AppName=NetworkVision
AppVersion={#AppVersion}
AppVerName=NetworkVision {#AppVersion}
AppPublisher=NetworkVision
AppPublisherURL=https://github.com/EliteScouter/NetworkVision
AppSupportURL=https://github.com/EliteScouter/NetworkVision/issues
DefaultDirName={autopf}\NetworkVision
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=NetworkVision-{#AppVersion}-windows-x64-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
UninstallDisplayName=NetworkVision
UninstallDisplayIcon={app}\networkvision.exe
CloseApplications=no
SetupLogging=yes

[Dirs]
Name: "{commonappdata}\NetworkVision"
Name: "{commonappdata}\NetworkVision\data"
Name: "{commonappdata}\NetworkVision\logs"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\networkvision.env"; DestDir: "{app}"; DestName: "networkvision.env.template"; Flags: ignoreversion

[Run]
; The data folder holds the generated secret key and the config may hold passwords:
; only SYSTEM (the service) and Administrators may read it.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\NetworkVision"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /T /Q"; Flags: runhidden waituntilterminated; StatusMsg: "Securing the data folder..."
Filename: "http://localhost:{code:GetWebPort}/"; Description: "Open NetworkVision in your browser to create the admin account"; Flags: postinstall shellexec nowait skipifsilent

[UninstallRun]
Filename: "{app}\NetworkVisionService.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\NetworkVisionService.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetworkVision Web"""; Flags: runhidden; RunOnceId: "FwWeb"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetworkVision Syslog (UDP)"""; Flags: runhidden; RunOnceId: "FwSyslogUdp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetworkVision Syslog (TCP)"""; Flags: runhidden; RunOnceId: "FwSyslogTcp"

[Code]
var
  PortPage: TInputQueryWizardPage;

function ConfigFile: String;
begin
  Result := ExpandConstant('{commonappdata}\NetworkVision\networkvision.env');
end;

{ Value of KEY=value in the config file, or Default. }
function ConfigValue(Key, Default: String): String;
var
  Lines: TArrayOfString;
  I: Integer;
  Line: String;
begin
  Result := Default;
  if LoadStringsFromFile(ConfigFile, Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
    begin
      Line := Trim(Lines[I]);
      if Pos(Key + '=', Line) = 1 then
        Result := Trim(Copy(Line, Length(Key) + 2, Length(Line)));
    end;
end;

function GetWebPort(Param: String): String;
begin
  Result := Trim(PortPage.Values[0]);
end;

procedure InitializeWizard;
begin
  PortPage := CreateInputQueryPage(wpSelectDir, 'Web interface port',
    'Which TCP port should the NetworkVision dashboard listen on?',
    'You will open http://<this computer>:<port>/ in a browser. Windows Firewall is opened for this port and for syslog (UDP/TCP 514).');
  PortPage.Add('Web port:', False);
  PortPage.Values[0] := ExpandConstant('{param:PORT|' + ConfigValue('NV_PORT', '8080') + '}');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Port: Integer;
begin
  Result := True;
  if CurPageID = PortPage.ID then
  begin
    Port := StrToIntDef(GetWebPort(''), 0);
    if (Port < 1) or (Port > 65535) then
    begin
      MsgBox('Enter a port number between 1 and 65535.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function ServiceWrapper: String;
begin
  Result := ExpandConstant('{app}\NetworkVisionService.exe');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  { Upgrade: stop the running service so its files can be replaced. }
  if FileExists(ServiceWrapper) then
  begin
    Exec(ServiceWrapper, 'stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Sleep(1500);
  end;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM networkvision.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

{ Create the config from the template on first install; always set NV_PORT to the chosen port. }
procedure WriteConfig;
var
  Lines: TArrayOfString;
  I: Integer;
  Found: Boolean;
begin
  if not FileExists(ConfigFile) then
    LoadStringsFromFile(ExpandConstant('{app}\networkvision.env.template'), Lines)
  else
    LoadStringsFromFile(ConfigFile, Lines);
  Found := False;
  for I := 0 to GetArrayLength(Lines) - 1 do
    if Pos('NV_PORT=', Trim(Lines[I])) = 1 then
    begin
      Lines[I] := 'NV_PORT=' + GetWebPort('');
      Found := True;
    end;
  if not Found then
  begin
    SetArrayLength(Lines, GetArrayLength(Lines) + 1);
    Lines[GetArrayLength(Lines) - 1] := 'NV_PORT=' + GetWebPort('');
  end;
  SaveStringsToFile(ConfigFile, Lines, False);
end;

procedure Netsh(Params: String);
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall ' + Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure OpenFirewall;
var
  Syslog: String;
begin
  Syslog := ConfigValue('NV_SYSLOG_PORT', '514');
  Netsh('delete rule name="NetworkVision Web"');
  Netsh('add rule name="NetworkVision Web" dir=in action=allow protocol=TCP localport=' + GetWebPort(''));
  Netsh('delete rule name="NetworkVision Syslog (UDP)"');
  Netsh('add rule name="NetworkVision Syslog (UDP)" dir=in action=allow protocol=UDP localport=' + Syslog);
  Netsh('delete rule name="NetworkVision Syslog (TCP)"');
  Netsh('add rule name="NetworkVision Syslog (TCP)" dir=in action=allow protocol=TCP localport=' + Syslog);
end;

{ Poll /api/health so the browser opens on a running app, not a connection error. }
procedure WaitForWebUI;
var
  Http: Variant;
  I: Integer;
begin
  for I := 1 to 60 do
  begin
    try
      Http := CreateOleObject('WinHttp.WinHttpRequest.5.1');
      Http.SetTimeouts(1000, 1000, 1000, 1000);
      Http.Open('GET', 'http://127.0.0.1:' + GetWebPort('') + '/api/health', False);
      Http.Send('');
      if Http.Status = 200 then
        Exit;
    except
    end;
    Sleep(500);
  end;
  Log('NetworkVision did not answer within 30 seconds; see ' + ExpandConstant('{commonappdata}\NetworkVision\logs'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WizardForm.StatusLabel.Caption := 'Writing configuration...';
    WriteConfig;
    WizardForm.StatusLabel.Caption := 'Opening Windows Firewall ports...';
    OpenFirewall;
    WizardForm.StatusLabel.Caption := 'Starting the NetworkVision service...';
    Exec(ServiceWrapper, 'install', '', SW_HIDE, ewWaitUntilTerminated, Code); { fails harmlessly if it exists }
    Exec(ServiceWrapper, 'start', '', SW_HIDE, ewWaitUntilTerminated, Code);
    WaitForWebUI;
  end;
end;
