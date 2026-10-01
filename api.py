import os
import json
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from experiments.step13_attack_defense import run_experiment_scenario
from src.security.attacker import AttackType, AttackIntensity

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            try:
                return json.load(f)
            except json.decoder.JSONDecodeError:
                return {"_error": "malformed"}
    return None

class DemoRequest(BaseModel):
    network_size: str
    security_mode: str
    target_device: str
    attack_type: str
    intensity: str

@app.get("/api/benchmarks/step15")
def get_step15():
    res = load_json("results/step15/benchmark_results.json")
    if not res:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return res

@app.get("/api/benchmarks/step16")
def get_step16():
    res = load_json("results/step16/scalability_results.json")
    if not res:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return res

@app.get("/api/benchmarks/step17")
def get_step17():
    res = load_json("results/step17/stress_results.json")
    if not res:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return res

@app.get("/api/validation")
def get_validation():
    res = load_json("results/final/freeze_baseline.json")
    if not res:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return res

@app.post("/api/run_demo")
def run_demo(req: DemoRequest):
    type_map = {
        "NO_ATTACK": "NO_ATTACK",
        "AUTHENTICATION_ATTACK": AttackType.AUTHENTICATION_ATTACK,
        "REPLAY_ATTACK": AttackType.REPLAY_ATTACK,
        "MESSAGE_TAMPERING_ATTACK": AttackType.MESSAGE_TAMPERING_ATTACK,
        "SESSION_ABUSE_ATTACK": AttackType.SESSION_ABUSE_ATTACK,
        "RESOURCE_PRESSURE_ATTACK": AttackType.RESOURCE_PRESSURE_ATTACK
    }
    
    int_map = {
        "LOW": AttackIntensity.LOW,
        "MEDIUM": AttackIntensity.MEDIUM,
        "HIGH": AttackIntensity.HIGH
    }
    
    if req.attack_type not in type_map:
        raise HTTPException(status_code=400, detail="Invalid attack type")
    
    s_def = {
        "id": "DEMO_RUN",
        "attack_type": type_map[req.attack_type],
        "intensity": int_map[req.intensity] if req.attack_type != "NO_ATTACK" else None,
        "security_mode": req.security_mode
    }
    
    try:
        res = run_experiment_scenario(s_def, seed=random.randint(1, 10000))
        # Safely bridge the UI inputs without altering the core simulation engine
        res["demo_context"] = {
            "network_size": req.network_size,
            "security_mode": req.security_mode,
            "target_device": req.target_device
        }
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
