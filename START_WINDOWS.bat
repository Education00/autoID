@echo off
setlocal
cd /d "%~dp0"
title Apple No2FA Setup

if not exist ".venv\Scripts\python.exe" goto install
if not exist ".venv\.setup_complete" goto install
goto run

:install
echo.
echo [1/3] Dang tao moi truong...
where py >nul 2>&1
if errorlevel 1 (
  echo Chua co Python. Cai Python 3.10 tro len roi chay lai file nay.
  pause
  exit /b 1
)
py -3 -m venv .venv
if errorlevel 1 goto failed

echo [2/3] Dang cai Playwright...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto failed

echo [3/3] Dang tai Chromium...
".venv\Scripts\python.exe" -m playwright install chromium
if errorlevel 1 goto failed
type nul > ".venv\.setup_complete"

:run
echo.
echo Dang mo giao dien...
".venv\Scripts\python.exe" server.py
if errorlevel 1 (
  echo.
  echo Tool da dung do co loi.
  pause
)
exit /b 0

:failed
echo.
echo Setup khong thanh cong, kiem tra mang va thu lai.
pause
exit /b 1
