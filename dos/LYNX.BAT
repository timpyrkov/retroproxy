@echo off
if "%1"=="" goto usage

rem --------------------------------------------------
rem Ensure mTCP config
rem --------------------------------------------------
if "%MTCPCFG%"=="" set MTCPCFG=C:\MTCP\MTCP.CFG

set URL=%1
set OUT=C:\LYNX\PAGE.HTM
set REF=C:\LYNX\EMPTY.HTM

rem --------------------------------------------------
rem CONFIGURE PROXY SERVER HERE
rem --------------------------------------------------
set PROXYBASE=http://192.168.1.2:8080
set TARGET=%PROXYBASE%/%URL%

rem ==================================================
rem 1) Try via proxy
rem ==================================================
echo.
echo [1/2] Fetching via proxy:
echo   %TARGET%

if exist %OUT% del %OUT%
C:\MTCP\HTGET.EXE %TARGET% > %OUT%

if not exist %OUT% goto PROXY_FAIL

fc /b %OUT% %REF% > nul
if not errorlevel 1 goto PROXY_FAIL

goto OPEN


:PROXY_FAIL
echo.
echo --------------------------------------------------
echo WARNING:
echo Proxy download failed or returned empty content.
echo If proxy runs on another machine, check:
echo   %PROXYBASE%
echo Edit LYNX.BAT if proxy IP or port has changed.
echo --------------------------------------------------


rem ==================================================
rem 2) Fallback: direct fetch
rem ==================================================
echo.
echo [2/2] Fetching directly:
echo   %URL%

if exist %OUT% del %OUT%
C:\MTCP\HTGET.EXE %URL% > %OUT%

if not exist %OUT% goto FAIL

fc /b %OUT% %REF% > nul
if not errorlevel 1 goto FAIL

goto OPEN


:OPEN
echo.
echo Opening page in DosLynx...
C:\LYNX\DOSLYNX.EXE /PC:\LYNX %OUT%
goto END


:FAIL
echo.
echo ERROR:
echo Download failed via proxy and directly.
goto END


:usage
echo Usage:
echo   LYNX http://example.com/

:END