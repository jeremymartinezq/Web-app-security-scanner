@echo off
title CyberSec Scan - Web Application Security Scanner

:: Create logs directory
mkdir logs 2>nul

echo Starting CyberSec Scan...
echo.
echo Please ensure you have activated your Python virtual environment first
echo.

:: Start API server in a new window
start "CyberSec Scan API" cmd /k "cd websec-scanner\backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

:: Wait for the API to start
echo Waiting for API server to start...
timeout /t 5 /nobreak >nul

:: Start Streamlit frontend in a new window
start "CyberSec Scan UI" cmd /k "cd websec-scanner\frontend && streamlit run app.py"

echo.
echo Services started:
echo  - API Server: http://localhost:8000
echo  - Frontend UI: http://localhost:8501
echo.
echo Close this window to stop all services.
echo.

pause 