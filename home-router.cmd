@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
pushd "%~dp0"
python -m home_router_lab %*
set "HRL_EXIT=%ERRORLEVEL%"
popd
exit /b %HRL_EXIT%
