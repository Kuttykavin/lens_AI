@echo off
echo.
echo  ============================================
echo   ScreenSentry - Auto Setup
echo  ============================================
echo.

echo [1/3] Checking Python...
python --version
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo.
echo [2/3] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [3/3] Setup complete!
echo.
echo  To start ScreenSentry, run:
echo     python launch.py
echo.
echo  For mobile access, run in a separate terminal:
echo     ngrok http 5000
echo.
pause
