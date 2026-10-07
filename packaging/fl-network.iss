; Build with Inno Setup 6.3 or later on Windows. Paths can be supplied by ISCC /D.
#ifndef AppVersion
  #define AppVersion "0.4.0"
#endif
#ifndef BuildDir
  #define BuildDir "..\dist\GNetwork"
#endif
#ifndef OutputSuffix
  #define OutputSuffix ""
#endif
#ifndef ReleaseDir
  #define ReleaseDir "..\release"
#endif

[Setup]
AppId={{5E89F57F-2F8C-47B0-9787-3C9D5A8AE6AB}
AppName=G-Network
AppVersion={#AppVersion}
AppVerName=G-Network {#AppVersion}
AppPublisher=Gloria
DefaultDirName={localappdata}\Programs\GNetwork
DefaultGroupName=G-Network
; Show the folder picker on first install and on upgrades. Inno Setup otherwise
; hides it when the same AppId has already been installed (the default is auto).
DisableDirPage=no
UsePreviousAppDir=yes
AlwaysShowDirOnReadyPage=yes
LicenseFile=installer-license.txt
InfoAfterFile=PRIVACY.txt
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#ReleaseDir}
OutputBaseFilename=G-Network-{#AppVersion}-windows-x64{#OutputSuffix}-Setup
SetupIconFile=fl-network.ico
UninstallDisplayIcon={app}\GNetwork.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName=G-Network
VersionInfoCompany=Gloria
VersionInfoDescription=G-Network Desktop Installer
LanguageDetectionMethod=uilanguage
UsePreviousLanguage=no
ShowLanguageDialog=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
; Exact upstream source from jrsoftware/issrc tag is-6_7_3, commit 4adf37ed.
; The upstream file is a user-contributed translation shipped in that source tag.
Name: "chinesesimp"; MessagesFile: "languages\ChineseSimplified.isl"

[Messages]
english.SelectDirLabel3=Setup selects an installation folder automatically. You can choose another folder.
chinesesimp.SelectDirLabel3=安装器已自动选择安装目录。你也可以点击“浏览”更改位置。

[CustomMessages]
english.FLDesktopIcon=Create a desktop shortcut
chinesesimp.FLDesktopIcon=创建桌面快捷方式
english.FLAdditionalIcons=Additional shortcuts:
chinesesimp.FLAdditionalIcons=附加快捷方式：
english.FLLaunch=Launch G-Network
chinesesimp.FLLaunch=启动 G-Network
english.FLUninstall=Uninstall G-Network
chinesesimp.FLUninstall=卸载 G-Network
english.FLWebViewDownload=Get WebView2 Runtime
chinesesimp.FLWebViewDownload=安装 WebView2 运行时
english.FLWebViewRequired=G-Network requires the Microsoft Edge WebView2 Runtime.
chinesesimp.FLWebViewRequired=G-Network 需要 Microsoft Edge WebView2 运行时才能运行。
english.FLWebViewGuidance=Click "Get WebView2 Runtime" to open Microsoft's download page. Install the Evergreen Runtime, then retry.
chinesesimp.FLWebViewGuidance=点击“安装 WebView2 运行时”打开 Microsoft 官方下载页面，安装 Evergreen Runtime 后重试。

[Tasks]
Name: "desktopicon"; Description: "{cm:FLDesktopIcon}"; GroupDescription: "{cm:FLAdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BuildDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#ifdef WebView2Bootstrapper
Source: "{#WebView2Bootstrapper}"; DestName: "MicrosoftEdgeWebview2Setup.exe"; Flags: dontcopy
#endif
#ifdef WebView2Standalone
Source: "{#WebView2Standalone}"; DestName: "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; Flags: dontcopy
#endif

[Icons]
Name: "{group}\G-Network"; Filename: "{app}\GNetwork.exe"; WorkingDir: "{app}"
Name: "{group}\{cm:FLUninstall}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\G-Network"; Filename: "{app}\GNetwork.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\GNetwork.exe"; Description: "{cm:FLLaunch}"; Flags: nowait postinstall skipifsilent; Check: HasWebView2

[InstallDelete]
; The old executable belongs to this AppId. Personal data remains untouched.
Type: files; Name: "{app}\FLNetwork.exe"
Type: files; Name: "{group}\FLNetwork.lnk"
Type: files; Name: "{userdesktop}\FLNetwork.lnk"

; No UninstallDelete entry touches LOCALAPPDATA\FLNetwork\data or \webview.
; Updating/uninstalling the application preserves the user's settings.

[Code]
const
  WebView2Key = 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2Download = 'https://developer.microsoft.com/microsoft-edge/webview2/';

function ValidWebView2Version(RootKey: Integer): Boolean;
var Version: String;
begin
  Result := RegQueryStringValue(RootKey, WebView2Key, 'pv', Version) and
    (Version <> '') and (Version <> '0.0.0.0');
end;

function HasWebView2: Boolean;
begin
  { HKLM32 is the documented WOW6432Node registration on Windows x64. }
  Result := ValidWebView2Version(HKCU) or ValidWebView2Version(HKLM32);
end;

procedure OpenWebView2Download(Sender: TObject);
var ResultCode: Integer;
begin
  ShellExec('open', WebView2Download, '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
end;

procedure InitializeWizard;
var DownloadButton: TNewButton;
begin
  if not HasWebView2 then begin
    DownloadButton := TNewButton.Create(WizardForm);
    DownloadButton.Parent := WizardForm;
    DownloadButton.Left := ScaleX(8);
    DownloadButton.Top := WizardForm.NextButton.Top;
    DownloadButton.Width := ScaleX(165);
    DownloadButton.Height := WizardForm.NextButton.Height;
    DownloadButton.Caption := CustomMessage('FLWebViewDownload');
    DownloadButton.OnClick := @OpenWebView2Download;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
#if defined(WebView2Bootstrapper) || defined(WebView2Standalone)
var ResultCode: Integer;
#endif
begin
  Result := '';
  if (FindWindowByWindowName('G-Network · 服务器管家') <> 0) or
     (FindWindowByWindowName('FL Network · 服务器管家') <> 0) then begin
    Result := '请先等待服务器任务完成并关闭 G-Network，再继续安装或升级。';
    exit;
  end;
  if HasWebView2 then exit;
#ifdef WebView2Standalone
  ExtractTemporaryFile('MicrosoftEdgeWebView2RuntimeInstallerX64.exe');
  if Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe'), '/silent /install',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    if ((ResultCode = 0) or (ResultCode = 3010)) and HasWebView2 then exit;
  end;
#endif
#ifdef WebView2Bootstrapper
  ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
  if Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    if (ResultCode = 0) and HasWebView2 then exit;
  end;
#endif
  Result := CustomMessage('FLWebViewRequired') + #13#10 +
    CustomMessage('FLWebViewGuidance') + #13#10 +
    WebView2Download;
end;
