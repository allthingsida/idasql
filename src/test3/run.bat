@echo off
REM run.bat - Run test3 with proper PATH for IDA DLLs
REM Usage: run.bat database.i64

if "%IDASDK%"=="" (
    echo ERROR: IDASDK environment variable not set
    echo Please set IDASDK to your IDA SDK directory
    exit /b 1
)

set PATH=%IDASDK%\bin;%PATH%

if "%1"=="" (
    echo Usage: run.bat ^<database.i64^>
    exit /b 1
)

build\Release\test3.exe %*
