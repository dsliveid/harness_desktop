@echo off
rem ===========================================================================
rem build.cmd - Windows entry point for build.sh
rem
rem Logic lives in build.sh (single source of truth). This file only locates a
rem bash interpreter and forwards all arguments.
rem
rem WHY ASCII-ONLY
rem   cmd / PowerShell 5.1 decode BOM-less UTF-8 as ANSI; CJK bytes here would
rem   break parsing. Chinese messages live inside build.sh.
rem
rem USAGE
rem   build.cmd                -> powershell -File scripts\build-exe.ps1
rem   build.cmd --with-web     -> rebuild web UI first
rem   build.cmd --help         -> full help (Chinese, from build.sh)
rem ===========================================================================

setlocal
set "SCRIPT_DIR=%~dp0"

set "BASH_EXE="
for %%B in (bash.exe) do if not defined BASH_EXE if exist "%%~$PATH:B" set "BASH_EXE=%%~$PATH:B"

if not defined BASH_EXE if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%LocalAppData%\Programs\Git\bin\bash.exe" set "BASH_EXE=%LocalAppData%\Programs\Git\bin\bash.exe"
if not defined BASH_EXE if exist "D:\Program Files\Git\bin\bash.exe" set "BASH_EXE=D:\Program Files\Git\bin\bash.exe"
if not defined BASH_EXE if exist "D:\Program Files\Git\usr\bin\bash.exe" set "BASH_EXE=D:\Program Files\Git\usr\bin\bash.exe"

if not defined BASH_EXE (
  echo [ERROR] bash not found.
  echo         Install Git for Windows ^(it ships bash^), or run build.sh
  echo         manually from Git Bash.
  exit /b 1
)

"%BASH_EXE%" "%SCRIPT_DIR%build.sh" %*
exit /b %ERRORLEVEL%
