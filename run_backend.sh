#!/bin/bash

# CyberSec Scan - Backend API Server Launcher

# Create logs directory if it doesn't exist
mkdir -p logs

echo "Starting CyberSec Scan API server..."
cd websec-scanner/backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload 