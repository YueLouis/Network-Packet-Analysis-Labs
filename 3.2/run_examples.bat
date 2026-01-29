@echo off
echo ========================================
echo Lab 3.2: AI-Powered Dissectors
echo ========================================
echo.

REM Check if API key is set
if "%GROQ_API_KEY%"=="" (
    echo ERROR: GROQ_API_KEY environment variable not set!
    echo.
    echo Please set it first:
    echo   set GROQ_API_KEY=your_key_here
    echo.
    echo Or get a free API key from: https://console.groq.com/keys
    echo.
    pause
    exit /b 1
)

echo Running AI Dissector Examples...
echo.
cd /d "%~dp0"
cd examples
python examples.py

echo.
pause
