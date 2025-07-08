"""
CyberCortex Backend Main Entry Point
Multi-agent cybersecurity platform with continuous penetration testing simulations
"""

import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("simulation.simulation_orchestrator:app", host="0.0.0.0", port=port, reload=True) 