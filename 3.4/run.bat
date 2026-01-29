@echo off
echo ========================================
echo Lab 3.4: Real-time Analyzer
echo ========================================
echo.
echo NOTE: Using simple_analyzer.py for Windows compatibility
echo (realtime_analyzer.py requires Linux for multiprocessing)
echo.

if "%1"=="" (
    echo Running demo with synthetic data...
    python simple_analyzer.py
) else (
    echo Analyzing PCAP file: %1
    python simple_analyzer.py %1
)

echo.
pause
