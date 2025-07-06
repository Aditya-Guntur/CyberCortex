"""
CyberCortex Backend Main Entry Point
Multi-agent cybersecurity platform with continuous penetration testing simulations
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("simulation.simulation_orchestrator:app", host="0.0.0.0", port=8000, reload=True) 