import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { useWebSocket } from './useWebSocket';

interface SimulationState {
  simulation: {
    running: boolean;
    simulation_id: string | null;
    start_time: string | null;
    current_phase: string;
    discovered_hosts: any[];
    discovered_vulnerabilities: any[];
    executed_exploits: any[];
    ai_services: Record<string, any>;
  };
  hosts: any[];
  vulnerabilities: any[];
  exploits: any[];
  loading: boolean;
  error: string | null;
  
  // Actions
  startSimulation: (config: any) => Promise<void>;
  stopSimulation: () => Promise<void>;
  refreshState: () => Promise<void>;
  injectVulnerability: (service: string, vulnType: string) => Promise<void>;
  
  // WebSocket handlers
  handleSimulationStarted: (data: any) => void;
  handleSimulationCompleted: (data: any) => void;
  handleHostDiscovered: (data: any) => void;
  handleVulnerabilityDiscovered: (data: any) => void;
  handleExploitGenerated: (data: any) => void;
  handlePhaseChange: (data: any) => void;
  handleSimulationState: (data: any) => void;
}

export const useSimulationState = create<SimulationState>()(
  subscribeWithSelector((set, get) => ({
    simulation: {
      running: false,
      simulation_id: null,
      start_time: null,
      current_phase: 'idle',
      discovered_hosts: [],
      discovered_vulnerabilities: [],
      executed_exploits: [],
      ai_services: {
        fetch_agents: { status: 'idle', last_activity: null },
        groq_analyzers: { status: 'idle', last_activity: null },
        coral_coordinator: { status: 'idle', last_activity: null },
        blackbox_generator: { status: 'idle', last_activity: null },
        snowflake_analyzer: { status: 'idle', last_activity: null }
      }
    },
    hosts: [],
    vulnerabilities: [],
    exploits: [],
    loading: false,
    error: null,
    
    // Start a new simulation
    startSimulation: async (config) => {
      set({ loading: true, error: null });
      
      try {
        const response = await fetch('/api/simulation/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config)
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.detail || 'Failed to start simulation');
        }
        
        const data = await response.json();
        
        set(state => ({
          loading: false,
          simulation: {
            ...state.simulation,
            running: true,
            simulation_id: data.simulation_id,
            start_time: new Date().toISOString(),
            current_phase: 'initializing',
            discovered_hosts: [],
            discovered_vulnerabilities: [],
            executed_exploits: []
          },
          hosts: [],
          vulnerabilities: [],
          exploits: []
        }));
      } catch (error) {
        console.error('Failed to start simulation:', error);
        set({ 
          loading: false, 
          error: error instanceof Error ? error.message : 'Failed to start simulation' 
        });
      }
    },
    
    // Stop the current simulation
    stopSimulation: async () => {
      set({ loading: true, error: null });
      
      try {
        const response = await fetch('/api/simulation/stop', {
          method: 'POST'
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.detail || 'Failed to stop simulation');
        }
        
        await response.json();
        
        set(state => ({
          loading: false,
          simulation: {
            ...state.simulation,
            running: false,
            current_phase: 'stopping'
          }
        }));
      } catch (error) {
        console.error('Failed to stop simulation:', error);
        set({ 
          loading: false, 
          error: error instanceof Error ? error.message : 'Failed to stop simulation' 
        });
      }
    },
    
    // Refresh simulation state
    refreshState: async () => {
      try {
        const response = await fetch('/api/status');
        
        if (!response.ok) {
          throw new Error('Failed to fetch simulation status');
        }
        
        const data = await response.json();
        
        set({
          simulation: data,
          hosts: data.discovered_hosts || [],
          vulnerabilities: data.discovered_vulnerabilities || [],
          exploits: data.executed_exploits || []
        });
      } catch (error) {
        console.error('Failed to refresh simulation state:', error);
      }
    },
    
    // Inject a vulnerability
    injectVulnerability: async (service, vulnType) => {
      try {
        const response = await fetch('/api/vulnerability/inject', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            service_name: service,
            vulnerability_type: vulnType
          })
        });
        
        if (!response.ok) {
          throw new Error('Failed to inject vulnerability');
        }
        
        await response.json();
      } catch (error) {
        console.error('Failed to inject vulnerability:', error);
      }
    },
    
    // WebSocket event handlers
    handleSimulationStarted: (data) => {
      set(state => ({
        simulation: {
          ...state.simulation,
          running: true,
          simulation_id: data.simulation_id,
          start_time: data.start_time,
          current_phase: 'initializing'
        }
      }));
    },
    
    handleSimulationCompleted: (data) => {
      set(state => ({
        simulation: {
          ...state.simulation,
          running: false,
          current_phase: 'completed'
        }
      }));
    },
    
    handleHostDiscovered: (data) => {
      set(state => ({
        hosts: [...state.hosts, data],
        simulation: {
          ...state.simulation,
          discovered_hosts: [...state.simulation.discovered_hosts, data]
        }
      }));
    },
    
    handleVulnerabilityDiscovered: (data) => {
      set(state => ({
        vulnerabilities: [...state.vulnerabilities, data],
        simulation: {
          ...state.simulation,
          discovered_vulnerabilities: [...state.simulation.discovered_vulnerabilities, data]
        }
      }));
    },
    
    handleExploitGenerated: (data) => {
      set(state => ({
        exploits: [...state.exploits, data],
        simulation: {
          ...state.simulation,
          executed_exploits: [...state.simulation.executed_exploits, data]
        }
      }));
    },
    
    handlePhaseChange: (data) => {
      set(state => ({
        simulation: {
          ...state.simulation,
          current_phase: data.phase
        }
      }));
    },

    // NEW: Handle full simulation state update from backend
    handleSimulationState: (data) => {
      set({
        simulation: data,
        hosts: data.discovered_hosts || [],
        vulnerabilities: data.discovered_vulnerabilities || [],
        exploits: data.executed_exploits || []
      });
    }
  }))
);

// Setup WebSocket message handlers
export function setupSimulationWebSocketHandlers() {
  const { 
    handleSimulationStarted,
    handleSimulationCompleted,
    handleHostDiscovered,
    handleVulnerabilityDiscovered,
    handleExploitGenerated,
    handlePhaseChange,
    handleSimulationState
  } = useSimulationState.getState();
  
  // Register WebSocket message handlers
  useWebSocket.getState().addMessageHandler('simulation_started', handleSimulationStarted);
  useWebSocket.getState().addMessageHandler('simulation_completed', handleSimulationCompleted);
  useWebSocket.getState().addMessageHandler('host_discovered', handleHostDiscovered);
  useWebSocket.getState().addMessageHandler('vulnerability_discovered', handleVulnerabilityDiscovered);
  useWebSocket.getState().addMessageHandler('exploit_generated', handleExploitGenerated);
  useWebSocket.getState().addMessageHandler('phase_change', handlePhaseChange);
  useWebSocket.getState().addMessageHandler('simulation_state', handleSimulationState);
}