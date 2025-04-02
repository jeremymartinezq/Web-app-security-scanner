FROM python:3.9-slim-bullseye

LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="CyberSec Scan - Web Application Security Scanner"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    curl \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Install Chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports

# Set environment variables
ENV DB_TYPE=sqlite \
    DB_NAME=websec_scanner \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DEBUG_MODE=False \
    HEADLESS_BROWSER=True

# Create entrypoint script
RUN echo '#!/bin/bash\n\
# Start backend API\n\
cd /app/websec-scanner/backend\n\
uvicorn main:app --host ${API_HOST} --port ${API_PORT} & \n\
# Wait for API to start\n\
sleep 5\n\
# Start frontend\n\
cd /app/websec-scanner/frontend\n\
streamlit run app.py\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose ports
EXPOSE 8000 8501

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"] 