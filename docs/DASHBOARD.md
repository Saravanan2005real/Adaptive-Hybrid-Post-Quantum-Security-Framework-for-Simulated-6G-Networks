# AERIS-PQ6G Dashboard

## Overview
The AERIS-PQ6G Dashboard is a presentation and demonstration layer built on top of the frozen AERIS-PQ6G simulation prototype. It provides a read-only interface to view benchmark artifacts (from Steps 15, 16, and 17) and allows for live, controlled demonstrations of the adaptive security engine against synthetic attack scenarios.

## Installation
Ensure you have `streamlit` installed in your Python environment:
```bash
pip install streamlit
```

## How to Start
From the project root directory, run:
```bash
streamlit run dashboard.py
```

## Expected Local URL
The dashboard will typically be available at:
`http://localhost:8501`

## Dashboard Architecture
The dashboard is a single-page Streamlit application with a sidebar for navigation. It imports directly from the `src` and `experiments` directories of the AERIS-PQ6G project, running simulations in isolated memory space when demonstrating attack responses.

## Data Sources
- **Live Demonstrations**: Executed via the existing `experiments.step13_attack_defense.run_experiment_scenario` pipeline.
- **Benchmark Results**: Read from immutable JSON artifacts in `results/step15/`, `results/step16/`, and `results/step17/`.
- **Validation Metrics**: Read from `results/final/freeze_baseline.json`.

## Demonstration Workflow
1. **Overview**: Project description and system status.
2. **Network Topology**: Current architectural mapping of devices, edge nodes, and core nodes.
3. **Security Status**: Current active cryptographic mode.
4. **Adaptive Security**: Real-time view of risk fusion and transition metrics.
5. **Attack / Defense Demonstration**: Interactive selection of attack types and intensities. Runs a live, isolated simulation tick sequence and displays the corresponding risk response and mode transition.
6. **Benchmark Results**: Interactive read-only view of comprehensive, scalability, and stress test artifacts.
7. **Event Log**: Searchable table of recent activities.
8. **System Validation**: Displays the frozen validation baseline metrics.

## Limitations
- **Simulation Only**: This dashboard represents a *simulated* 6G environment. Timing metrics (ticks) do not correspond to physical network latencies.
- **Read-Only**: The dashboard cannot mutate benchmark artifacts, cryptographic parameters, or core simulation configurations.
- **Synthetic ML**: The displayed ML risk metrics reflect a purely synthetic, deterministic model built for this simulation, not real-world attack predictions.

## Security Considerations
- The dashboard deliberately strips and excludes any display of private cryptographic secrets or session keys from the event logs and artifact viewers.
- Demonstration scenarios execute inside fresh `Simulator` objects explicitly isolating them from the core benchmark state.
