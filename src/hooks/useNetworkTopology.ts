import { useState, useEffect, useCallback } from 'react';
import { useWebSocket } from './useWebSocket';
import { useSimulationState } from './useSimulationState';

interface NetworkTopology {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    ip: string;
    x: number;
    y: number;
    color: string;
    size: number;
    services?: any[];
    vulnerabilities?: number;
  }>;
  edges: Array<{
    from: string;
    to: string;
    color: string;
    width: number;
  }>;
  timestamp: string;
  node_count: number;
  edge_count: number;
}

export function useNetworkTopology() {
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const { simulation } = useSimulationState();
  const { sendMessage } = useWebSocket();

  // Fetch network topology
  const fetchTopology = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/topology');
      
      if (!response.ok) {
        throw new Error(`Failed to fetch topology: ${response.status}`);
      }
      
      const data = await response.json();
      setTopology(data);
    } catch (err) {
      console.error('Error fetching network topology:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch network topology');
      
      // Fallback to mock data for development
      setTopology(getMockTopology());
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh topology
  const refreshTopology = useCallback(() => {
    fetchTopology();
  }, [fetchTopology]);

  // Listen for topology updates via WebSocket
  useEffect(() => {
    const handleTopologyUpdate = (data: any) => {
      if (data.type === 'topology_update') {
        setTopology(data.data);
      }
    };
    
    // Register WebSocket message handler
    const unsubscribe = useWebSocket.subscribe(
      state => state.addMessageHandler,
      addHandler => addHandler('topology_update', handleTopologyUpdate)
    );
    
    return () => {
      unsubscribe();
    };
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchTopology();
    
    // Refresh topology periodically if simulation is running
    let intervalId: NodeJS.Timeout;
    
    if (simulation?.running) {
      intervalId = setInterval(fetchTopology, 10000); // Every 10 seconds
    }
    
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [fetchTopology, simulation?.running]);

  // Generate mock topology data for development
  const getMockTopology = (): NetworkTopology => {
    return {
      nodes: [
        {
          id: 'router',
          label: 'Router',
          type: 'router',
          ip: '172.20.0.5',
          x: 0,
          y: 0,
          color: 'orange',
          size: 30
        },
        {
          id: '172.20.0.2',
          label: 'Web Server',
          type: 'web_server',
          ip: '172.20.0.2',
          x: 200,
          y: 0,
          color: 'blue',
          size: 20,
          services: [
            { name: 'http', port: 80 }
          ],
          vulnerabilities: 2
        },
        {
          id: '172.20.0.3',
          label: 'SSH Server',
          type: 'ssh_server',
          ip: '172.20.0.3',
          x: 0,
          y: 200,
          color: 'green',
          size: 20,
          services: [
            { name: 'ssh', port: 22 }
          ],
          vulnerabilities: 1
        },
        {
          id: '172.20.0.4',
          label: 'Database',
          type: 'database',
          ip: '172.20.0.4',
          x: -200,
          y: 0,
          color: 'purple',
          size: 20,
          services: [
            { name: 'mysql', port: 3306 }
          ],
          vulnerabilities: 1
        },
        {
          id: '172.20.0.6',
          label: 'IoT Device',
          type: 'iot_device',
          ip: '172.20.0.6',
          x: 0,
          y: -200,
          color: 'red',
          size: 20,
          services: [
            { name: 'http', port: 8888 }
          ],
          vulnerabilities: 2
        }
      ],
      edges: [
        { from: 'router', to: '172.20.0.2', color: 'gray', width: 2 },
        { from: 'router', to: '172.20.0.3', color: 'gray', width: 2 },
        { from: 'router', to: '172.20.0.4', color: 'gray', width: 2 },
        { from: 'router', to: '172.20.0.6', color: 'gray', width: 2 }
      ],
      timestamp: new Date().toISOString(),
      node_count: 5,
      edge_count: 4
    };
  };

  return {
    topology: topology || getMockTopology(),
    loading,
    error,
    refreshTopology
  };
}