@echo off
set cmd=
if exist "%ProgramFiles%\Notepad++\notepad++.exe" set cmd="%ProgramFiles%\Notepad++\notepad++.exe"
if exist "%ProgramFiles(x86)%\Notepad++\notepad++.exe" set cmd="%ProgramFiles(x86)%\Notepad++\notepad++.exe"


if "%1"=="" (
	echo %0: Missing XML/BAK file argument
	pause
	goto :eof
)
python %~dp0\clavister_annotate_config_xml.py %1
if errorlevel 1 (
	pause
	goto :eof
)
@echo on
REM done from python now: start "opening result" %cmd% "%1-annotated.xml"

:eof