"""
DoS Detection System - FastAPI Backend
Implements traffic simulation, detection logic, and API endpoints
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import random
from datetime import datetime

app = FastAPI(title="DoS Detection System")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ DATA MODELS ============

class Alert(BaseModel):
    timestamp: str
    ip: str
    attack_type: str
    severity: str

class Stats(BaseModel):
    total_packets: int
    packets_per_second: int
    active_connections: int
    total_alerts: int

# ============ GLOBAL STATE ============

class DetectionState:
    def __init__(self):
        self.running = False
        self.total_packets = 0
        self.packets_per_second = 0
        self.active_connections = 0
        self.alerts: List[Alert] = []
        self.packet_history = []  # For graph data
        self._detection_task = None
    
    def reset(self):
        self.total_packets = 0
        self.packets_per_second = 0
        self.active_connections = 0
        self.alerts = []
        self.packet_history = []

state = DetectionState()

# Detection thresholds
PACKETS_PER_SECOND_THRESHOLD = 100
CONNECTION_THRESHOLD = 50

# ============ TRAFFIC SIMULATION ============

def generate_fake_ip():
    """Generate a random fake IP address"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate_traffic():
    """Simulate network traffic with random spikes"""
    # Base traffic: 10-50 packets per second normally
    base_rate = random.randint(10, 50)
    
    # Random attack spike (10% chance)
    if random.random() < 0.1:
        # Attack spike: 100-300 packets per second
        spike = random.randint(100, 300)
        base_rate += spike
    
    return base_rate

def simulate_connections():
    """Simulate active connections with random spikes"""
    # Base connections: 5-20 normally
    base_connections = random.randint(5, 20)
    
    # Random connection spike (10% chance)
    if random.random() < 0.1:
        # Connection spike: 50-100 connections
        spike = random.randint(50, 100)
        base_connections += spike
    
    return base_connections

# ============ DETECTION LOGIC ============

def detect_attack(packets_per_sec: int, connections: int) -> Optional[Alert]:
    """
    Detect potential DoS attacks based on thresholds
    Returns an Alert if attack detected, None otherwise
    """
    attack_detected = False
    attack_type = ""
    severity = "LOW"
    
    # Check packets per second threshold
    if packets_per_sec > PACKETS_PER_SECOND_THRESHOLD:
        attack_detected = True
        if packets_per_sec > 200:
            attack_type = "DDoS Attack - High Volume"
            severity = "HIGH"
        elif packets_per_sec > 150:
            attack_type = "DDoS Attack - Medium Volume"
            severity = "MEDIUM"
        else:
            attack_type = "DDoS Attack - Low Volume"
            severity = "LOW"
    
    # Check connection threshold
    if connections > CONNECTION_THRESHOLD:
        attack_detected = True
        if connections > 80:
            attack_type = "SYN Flood - High Connections"
            severity = "HIGH"
        elif connections > 60:
            attack_type = "SYN Flood - Medium Connections"
            severity = "MEDIUM"
        else:
            attack_type = "SYN Flood - Low Connections"
            severity = "LOW"
    
    if attack_detected:
        return Alert(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip=generate_fake_ip(),
            attack_type=attack_type,
            severity=severity
        )
    
    return None

# ============ DETECTION LOOP ============

async def detection_loop():
    """
    Main detection loop that runs every second
    Simulates traffic, detects attacks, and updates stats
    """
    while state.running:
        # Simulate traffic
        packets_this_second = simulate_traffic()
        state.packets_per_second = packets_this_second
        state.total_packets += packets_this_second
        
        # Simulate connections
        state.active_connections = simulate_connections()
        
        # Store history for graph (keep last 60 seconds)
        state.packet_history.append(packets_this_second)
        if len(state.packet_history) > 60:
            state.packet_history.pop(0)
        
        # Detect attacks
        alert = detect_attack(packets_this_second, state.active_connections)
        if alert:
            state.alerts.append(alert)
            # Keep only last 100 alerts
            if len(state.alerts) > 100:
                state.alerts.pop(0)
        
        # Wait for 1 second
        await asyncio.sleep(1)

# ============ API ENDPOINTS ============

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "DoS Detection System",
        "version": "1.0.0"
    }

@app.post("/start")
async def start_detection():
    """Start the detection system"""
    if state.running:
        return {"status": "already_running"}
    
    state.running = True
    state._detection_task = asyncio.create_task(detection_loop())
    
    return {
        "status": "started",
        "message": "Detection system started successfully"
    }

@app.post("/stop")
async def stop_detection():
    """Stop the detection system"""
    if not state.running:
        return {"status": "already_stopped"}
    
    state.running = False
    if state._detection_task:
        state._detection_task.cancel()
        try:
            await state._detection_task
        except asyncio.CancelledError:
            pass
    
    return {
        "status": "stopped",
        "message": "Detection system stopped successfully"
    }

@app.get("/stats")
async def get_stats():
    """Get current statistics"""
    return Stats(
        total_packets=state.total_packets,
        packets_per_second=state.packets_per_second,
        active_connections=state.active_connections,
        total_alerts=len(state.alerts)
    )

@app.get("/alerts")
async def get_alerts():
    """Get recent alerts (last 20)"""
    return state.alerts[-20:] if state.alerts else []

@app.get("/history")
async def get_history():
    """Get packet history for graph (last 60 seconds)"""
    return state.packet_history

@app.get("/status")
async def get_status():
    """Get system running status"""
    return {"running": state.running}

# ============ MAIN ============

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
