# AERIS-PQ6G Web Dashboard & Telemetry Platform

> **Step 18 Presentation & Interactive Demonstration Layer**

This directory contains the modern, commercial-grade web dashboard for the **AERIS-PQ6G** (Adaptive Hybrid Post-Quantum Security Framework for Simulated 6G Networks) platform.

---

## ⚡ Tech Stack

- **Framework**: [Next.js 16 (App Router)](https://nextjs.org/)
- **UI Library**: [React 19](https://react.dev/)
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Animations**: [Framer Motion](https://www.framer.com/motion/)
- **Data Visualization**: [Recharts](https://recharts.org/)
- **Language**: [TypeScript 5](https://www.typescriptlang.org/)

---

## ✨ Features

- **Interactive Attack/Defense Demonstrator**:
  - Live scenario triggering with configurable attack vectors: `AUTHENTICATION_ATTACK`, `REPLAY_ATTACK`, `MESSAGE_TAMPERING_ATTACK`, `SESSION_ABUSE_ATTACK`, `RESOURCE_PRESSURE_ATTACK`.
  - Configurable intensity levels: `LOW`, `MEDIUM`, `HIGH`.
  - Real-time display of simulated defense reactions, risk scoring deltas, and automated cryptographic posture transitions.
- **Dynamic Mode Orchestration Visualizer**:
  - Visual status of active security postures (`CLASSICAL`, `PQC`, `HYBRID`, `ADAPTIVE_HYBRID`).
  - Animated data flow pathways representing 6G User Equipment (UE), Edge Computing Nodes, and Core Network Functions.
- **Empirical Benchmark Exploration**:
  - Step 15 Comprehensive Security Metrics: Latency, throughput, and overhead comparisons.
  - Step 16 Scalability Visualizer: Performance curves across S1 (50 nodes) to S5 (1,000 nodes).
  - Step 17 Stress Testing Metrics: Resource saturation and error-handling verification.
- **Production-Grade Aesthetics**:
  - Sleek dark theme tailored for network operations centers (NOC).
  - Glassmorphic panels, micro-animations, and responsive layout.

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **Backend API**: The FastAPI backend (`api.py`) should be running on `http://127.0.0.1:8000`.

### 2. Install Dependencies
```bash
npm install
```

### 3. Run Development Server
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 4. Build for Production
```bash
npm run build
npm run start
```

### 5. Linting
```bash
npm run lint
```

---

## 🔌 Backend API Connection

The dashboard connects to the AERIS-PQ6G Python FastAPI backend:

| Backend Endpoint | Method | Purpose |
|---|---|---|
| `http://127.0.0.1:8000/api/run_demo` | `POST` | Executes isolated simulation attack scenarios |
| `http://127.0.0.1:8000/api/benchmarks/step15` | `GET` | Fetches frozen security baseline benchmark data |
| `http://127.0.0.1:8000/api/benchmarks/step16` | `GET` | Fetches frozen scalability benchmark data |
| `http://127.0.0.1:8000/api/benchmarks/step17` | `GET` | Fetches frozen stress testing data |
| `http://127.0.0.1:8000/api/validation` | `GET` | Fetches system freeze baseline metrics |

> **Note**: If the backend is not running, the dashboard safely enters offline fallback mode with notification alerts.

---

## 📁 Directory Structure

```text
web-dashboard/
├── app/
│   ├── favicon.ico
│   ├── globals.css         # Tailwind CSS imports & global design tokens
│   ├── layout.tsx          # Root HTML metadata and font configuration
│   └── page.tsx            # Main interactive dashboard component
├── public/                 # Static brand assets and SVGs
├── eslint.config.mjs       # ESLint configuration
├── next.config.ts          # Next.js configuration
├── package.json            # Project manifest & dependencies
├── postcss.config.mjs      # PostCSS configuration for Tailwind v4
├── README.md               # Dashboard documentation
└── tsconfig.json           # TypeScript configuration
```

---

## 🛡 Research & Security Constraints

- **Presentation Layer Only**: The dashboard is strictly read-only regarding research artifacts. It cannot modify cryptographic parameters, risk weights, or frozen benchmark JSON files.
- **Zero-Secret Handling**: No private keys, shared secrets, or ephemeral session keys are exposed to or handled by the frontend.
