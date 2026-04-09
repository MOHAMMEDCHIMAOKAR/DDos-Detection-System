# DoS Detection System

A real-time web-based DoS (Denial of Service) detection dashboard with simulated traffic monitoring and alerting.

## Architecture

```
[Traffic Generator (simulated)] → [Detection Engine] → [FastAPI Backend] → [Web Dashboard]
```

## Features

- **Real-time Monitoring**: Live statistics for packets/sec, total packets, and active connections
- **Attack Detection**: Automatic detection of DDoS attacks and SYN floods
- **Alert System**: Color-coded alerts with severity levels (LOW, MEDIUM, HIGH)
- **Traffic Visualization**: Real-time graph showing packet rate over time
- **Modern UI**: Professional cybersecurity dashboard design

## Tech Stack

- **Backend**: FastAPI (Python)
- **Frontend**: HTML, CSS, JavaScript, Chart.js
- **Architecture**: RESTful API with real-time polling

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server

```bash
uvicorn backend.main:app --reload
```

The backend will start on `http://localhost:8000`

### 3. Open the Frontend

Open `frontend/index.html` in your web browser

Alternatively, you can serve the frontend using a local server:
```bash
cd frontend
python -m http.server 3000
```

Then open `http://localhost:3000`

## Usage

1. Click the **Start** button to begin traffic simulation and detection
2. Monitor the real-time statistics in the dashboard
3. View alerts in the Security Alerts panel when attacks are detected
4. Click **Stop** to halt the detection system

## Detection Thresholds

- **Packets/sec Threshold**: 100 packets/second
- **Connection Threshold**: 50 active connections

## API Endpoints

- `GET /` - Health check
- `POST /start` - Start detection system
- `POST /stop` - Stop detection system
- `GET /stats` - Get current statistics
- `GET /alerts` - Get recent alerts
- `GET /history` - Get packet history for graph
- `GET /status` - Get system running status

## Project Structure

```
PP/
├── backend/
│   └── main.py          # FastAPI backend with detection logic
├── frontend/
│   ├── index.html       # Dashboard UI
│   ├── style.css        # Modern styling
│   └── script.js        # Real-time updates
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Alert Types

- **DDoS Attack - High Volume**: >200 packets/sec (HIGH severity)
- **DDoS Attack - Medium Volume**: 150-200 packets/sec (MEDIUM severity)
- **DDoS Attack - Low Volume**: 100-150 packets/sec (LOW severity)
- **SYN Flood - High Connections**: >80 connections (HIGH severity)
- **SYN Flood - Medium Connections**: 60-80 connections (MEDIUM severity)
- **SYN Flood - Low Connections**: 50-60 connections (LOW severity)

## Notes

- Traffic is simulated using random generation with periodic attack spikes
- No external dependencies on Scapy or packet capture libraries
- All data is stored in-memory (reset on restart)
- Frontend polls the backend every second for updates
