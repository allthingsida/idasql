@echo off
set PATH=C:\Users\elias\Projects\ida\idasdk92\bin;%PATH%
cd /d C:\Users\elias\Projects\github\allthingsida\idasql
src\cli\build\Release\idasql.exe -s wizmo32.exe.i64 -f test_query.sql
echo Exit code: %ERRORLEVEL%
