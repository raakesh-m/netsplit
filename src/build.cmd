@echo off
rem Builds ..\NetSplit.exe with the C# compiler that ships with Windows (.NET Framework 4).
setlocal
cd /d "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set REFS=/r:System.Management.dll /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll
if not exist netsplit.ico (
  "%CSC%" /nologo /codepage:65001 /target:winexe /out:icon-tmp.exe %REFS% NetSplit.cs || exit /b 1
  .\icon-tmp.exe --write-icon netsplit.ico || exit /b 1
  del icon-tmp.exe
)
"%CSC%" /nologo /codepage:65001 /optimize+ /target:winexe /out:..\NetSplit.exe %REFS% /win32manifest:app.manifest /win32icon:netsplit.ico NetSplit.cs || exit /b 1
echo Built %~dp0..\NetSplit.exe
