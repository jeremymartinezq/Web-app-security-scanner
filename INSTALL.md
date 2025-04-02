# CyberSec Scan - Installation Guide

This guide provides detailed instructions for setting up the CyberSec Scan Web Application Security Scanner on various platforms.

## System Requirements

- Python 3.8 or higher
- Chrome/Chromium browser (for Selenium-based scanning)
- 4GB RAM or more recommended
- 1GB free disk space

## Installation Steps

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/cybersec-scan.git
cd cybersec-scan
```

### Step 2: Create a Virtual Environment

#### On Windows:
```cmd
python -m venv venv
venv\Scripts\activate
```

#### On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required dependencies including FastAPI, Streamlit, Selenium, BeautifulSoup, and other libraries.

### Step 4: Configure Environment

Copy the example environment file and customize if needed:

```bash
cp .env.example .env
```

Edit the `.env` file to configure:
- Database settings (SQLite by default)
- API settings
- Email notifications
- Report paths

### Step 5: Initialize the Database

The database will be automatically created on first run, but you can also initialize it manually:

```bash
python -c "from websec-scanner.backend.database import init_db; init_db()"
```

## Running the Application

### Method 1: Using the Launcher Scripts

#### On Windows:
Simply run the batch file:
```cmd
run_scanner.bat
```

#### On macOS/Linux:
Run the backend and frontend in separate terminals:
```bash
# Terminal 1
chmod +x run_backend.sh
./run_backend.sh

# Terminal 2
chmod +x run_frontend.sh
./run_frontend.sh
```

### Method 2: Manual Startup

#### Start the Backend API:
```bash
cd websec-scanner/backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Start the Frontend UI:
```bash
cd websec-scanner/frontend
streamlit run app.py
```

### Method 3: Using the CLI

For command-line only usage:
```bash
cd websec-scanner/cli
python scanner_cli.py --help
python scanner_cli.py https://example.com --depth 2 --output results.json
```

## Access the Application

After starting the application:

- Frontend UI: http://localhost:8501
- API Documentation: http://localhost:8000/api/docs

## Optional: Docker Installation

### Build the Docker Image:
```bash
docker build -t cybersec-scan .
```

### Run the Docker Container:
```bash
docker run -p 8000:8000 -p 8501:8501 cybersec-scan
```

## Troubleshooting

### Chrome/ChromeDriver Issues:
If you encounter issues with Selenium and ChromeDriver:

1. Make sure Chrome is installed
2. The WebDriver Manager should automatically download the appropriate driver
3. If problems persist, you may need to manually specify the Chrome/ChromeDriver path in the `.env` file

### Database Errors:
If database errors occur:

1. Delete the SQLite database file (if using SQLite) and restart
2. Check database connection parameters in the `.env` file
3. Ensure proper permissions for the database directory

### API Connection Issues:
If the frontend can't connect to the API:

1. Verify the API is running (http://localhost:8000)
2. Check if the API_URL in the frontend configuration is correct
3. Verify no firewall is blocking the connection

## Upgrading

To upgrade to the latest version:

```bash
git pull
pip install -r requirements.txt --upgrade
```

## Contact & Support

For issues or support, please create an issue on the GitHub repository or contact the maintainer at support@example.com. 