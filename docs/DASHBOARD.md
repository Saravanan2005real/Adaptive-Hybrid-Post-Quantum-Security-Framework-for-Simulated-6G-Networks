# AERIS-PQ6G Web Dashboard & Telemetry Platform

## Overview
The AERIS-PQ6G Web Dashboard (Step 18) provides an interactive, production-grade presentation and telemetry visualization layer for the AERIS-PQ6G simulation framework. Built with Next.js 16 (App Router), React 19, Tailwind CSS, Framer Motion, and Recharts, it connects to a high-performance Python FastAPI backend (`api.py`) to deliver:

1. **Live Scenario Demonstrations**: Real-time triggering of synthetic attack scenarios (Authentication, Replay, Message Tampering, Session Abuse, and Resource Pressure) with live visualization of risk assessment and adaptive cryptographic mode transitions.
2. **Benchmark Artifact Exploration**: Visual interactive exploration of frozen empirical research artifacts from Steps 15 (Security Benchmarks), 16 (Scalability Testing), and 17 (Stress Matrices).
3. **Architecture & Topology Mapping**: Structural visualization of 6G devices, edge base stations, core network elements, and telemetry data flows.
4. **Validation Metrics**: Frozen prototype verification metrics from `results/final/freeze_baseline.json`.

---

## 🏛 System Architecture

```text
┌──────────────────────────────────────────────┐
│       Next.js 16 Web Dashboard               │
│       React 19 + TypeScript + Tailwind CSS   │
│       Framer Motion + Recharts               │
│       (http://localhost:3000)                │
└──────────────────────┬───────────────────────┘
                       │ HTTP / JSON
                       ▼
┌──────────────────────────────────────────────┐
│       FastAPI Backend Server (api.py)        │
│       CORS-enabled REST Endpoints            │
│       (http://127.0.0.1:8000)                │
└──────────────┬───────────────────────────────┘
               │
       ┌───────┴───────────────────────────────┐
       ▼                                       ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│ Frozen Benchmark Artifacts   │ │ Isolated Scenario Runner     │
│ results/step15/              │ │ experiments.step13_          │
│ results/step16/              │ │ attack_defense.              │
│ results/step17/              │ │ run_experiment_scenario()    │
│ results/final/               │ └──────────────────────────────┘
└──────────────────────────────┘
```

---

## 🚀 Quickstart Guide

### 1. Start the FastAPI Backend

The FastAPI daemon serves the REST API on port `8000`.

```bash
# Ensure Python dependencies are installed
pip install -r requirements.txt

# Start the API server
python api.py
```
*API Swagger Documentation: `http://127.0.0.1:8000/docs`*

### 2. Start the Next.js Frontend

The frontend runs on port `3000`.

```bash
cd web-dashboard

# Install Node dependencies
npm install

# Start the Next.js dev server
npm run dev
```
*Access the Web Dashboard at: `http://localhost:3000`*

---

## 📡 API Specification

| Endpoint | Method | Description |
|---|---|---|
| `/api/run_demo` | `POST` | Executes an isolated simulation tick sequence with the specified attack type, intensity, network size, and security mode. |
| `/api/benchmarks/step15` | `GET` | Returns Step 15 comprehensive security baseline benchmark results. |
| `/api/benchmarks/step16` | `GET` | Returns Step 16 scalability benchmark matrices across S1–S5 topologies. |
| `/api/benchmarks/step17` | `GET` | Returns Step 17 stress test results and edge condition matrices. |
| `/api/validation` | `GET` | Returns frozen baseline validation metrics (`results/final/freeze_baseline.json`). |

### Demo Request Schema (`/api/run_demo`)
```json
{
  "network_size": "Small (50 nodes)",
  "security_mode": "ADAPTIVE_HYBRID",
  "target_device": "dev-0",
  "attack_type": "AUTHENTICATION_ATTACK",
  "intensity": "HIGH"
}
```

---

## 🛡 Security & Design Principles

- **Non-Invasive Architecture**: The dashboard is strictly a presentation and demonstration layer. It reads from immutable frozen benchmark artifacts and runs live demonstrations inside isolated in-memory `Simulator` instances without mutating benchmark files.
- **Zero-Secret Disclosure Policy**: The dashboard and backend explicitly sanitize all logs and responses. No cryptographic private keys, ephemeral seeds, or derived session keys are ever exposed to the API or rendered in the UI.
- **Resilient Fallback Handling**: If the FastAPI daemon is offline, the web dashboard gracefully falls back with visual status indicators rather than crashing.
