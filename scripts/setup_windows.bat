@echo off
setlocal
cd /d "%~dp0\.."

if not exist .venv (
    python -m venv .venv
    if errorlevel 1 exit /b 1
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo Installation failed.
    exit /b 1
)

echo.
echo Setup completed successfully.
endlocal
