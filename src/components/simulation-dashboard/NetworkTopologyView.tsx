import React, { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network';
import { DataSet } from 'vis-data';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2, RefreshCw, ZoomIn, ZoomOut, Maximize, Download } from 'lucide-react';
import { useSimulationState } from '@/hooks/useSimulationState';
import { useNetworkTopology } from '@/hooks/useNetworkTopology';
import html2canvas from 'html2canvas';

interface NetworkTopologyViewProps {
  className?: string;
}

export function NetworkTopologyView({ className }: NetworkTopologyViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<Network | null>(null);
  const nodesRef = useRef<DataSet<any> | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [viewMode, setViewMode] = useState<'default' | 'vulnerabilities' | 'services'>('default');
  
  const { simulation } = useSimulationState();
  const { topology, loading, error, refreshTopology } = useNetworkTopology();

  // Initialize network visualization
  useEffect(() => {
    if (!containerRef.current || !topology) return;

    // Create nodes dataset
    const nodes = new DataSet(topology.nodes.map(node => ({
      id: node.id,
      label: node.label,
      title: `${node.label} (${node.ip})`,
      color: {
        background: node.color,
        border: '#ffffff',
        highlight: { background: '#8b5cf6', border: '#ffffff' }
      },
      font: { color: '#ffffff' },
      size: node.size || 25,
      shape: getNodeShape(node.type),
      x: node.x,
      y: node.y,
      fixed: { x: true, y: true },
      data: node
    })));
    nodesRef.current = nodes;

    // Create edges dataset
    const edges = new DataSet(topology.edges.map(edge => ({
      id: `${edge.from}-${edge.to}`,
      from: edge.from,
      to: edge.to,
      color: { color: edge.color || '#666666', highlight: '#8b5cf6' },
      width: edge.width || 1,
      smooth: { enabled: true, type: 'curvedCW', roundness: 0.2 }
    })));

    // Network options
    const options = {
      nodes: {
        borderWidth: 2,
        shadow: true
      },
      edges: {
        shadow: true
      },
      physics: {
        enabled: false
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        zoomView: true,
        dragView: true
      }
    };

    // Create network
    networkRef.current = new Network(
      containerRef.current,
      { nodes, edges },
      options
    );

    // Event listeners
    networkRef.current.on('click', function(params) {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = nodes.get(nodeId);
        setSelectedNode(node);
      } else {
        setSelectedNode(null);
      }
    });

    // Cleanup
    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [topology]);

  // Update node colors based on view mode
  useEffect(() => {
    if (!nodesRef.current || !topology) return;
    nodesRef.current.update(topology.nodes.map(node => {
      let color = node.color;

      if (viewMode === 'vulnerabilities') {
        // Color based on vulnerability count
        const vulnCount = node.vulnerabilities || 0;
        if (vulnCount > 5) {
          color = '#dc2626'; // Critical
        } else if (vulnCount > 2) {
          color = '#ea580c'; // High
        } else if (vulnCount > 0) {
          color = '#d97706'; // Medium
        } else {
          color = '#65a30d'; // Low/None
        }
      } else if (viewMode === 'services') {
        // Color based on service type
        const services = node.services || [];
        if (services.some(s => s.name === 'http' || s.name === 'https')) {
          color = '#3b82f6'; // Web services
        } else if (services.some(s => s.name === 'ssh')) {
          color = '#10b981'; // SSH
        } else if (services.some(s => s.name === 'mysql' || s.name === 'postgresql')) {
          color = '#8b5cf6'; // Database
        } else {
          color = '#6b7280'; // Other/None
        }
      }

      return {
        id: node.id,
        color: {
          background: color,
          border: '#ffffff',
          highlight: { background: '#8b5cf6', border: '#ffffff' }
        }
      };
    }));
  }, [viewMode, topology]);

  // Helper function to determine node shape
  const getNodeShape = (type: string): string => {
    switch (type) {
      case 'router':
        return 'diamond';
      case 'web_server':
        return 'box';
      case 'ssh_server':
        return 'box';
      case 'database':
        return 'database';
      case 'iot_device':
        return 'dot';
      case 'monitoring':
        return 'triangle';
      default:
        return 'dot';
    }
  };

  // Handle zoom in
  const handleZoomIn = () => {
    if (networkRef.current) {
      const currentScale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: currentScale * 1.2 });
    }
  };

  // Handle zoom out
  const handleZoomOut = () => {
    if (networkRef.current) {
      const currentScale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: currentScale / 1.2 });
    }
  };

  // Handle fit to screen
  const handleFitToScreen = () => {
    if (networkRef.current) {
      networkRef.current.fit();
    }
  };

  // Handle refresh
  const handleRefresh = () => {
    refreshTopology();
  };

  // Export as image
  const handleExport = async () => {
    if (containerRef.current) {
      const canvas = await html2canvas(containerRef.current);
      const dataUrl = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = `network-topology-${new Date().toISOString().slice(0, 10)}.png`;
      link.href = dataUrl;
      link.click();
    }
  };

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <div>
          <CardTitle className="text-xl font-bold">Network Topology</CardTitle>
          <CardDescription>
            Simulation network with {topology?.nodes.length || 0} hosts and {topology?.edges.length || 0} connections
          </CardDescription>
        </div>
        
        <div className="flex items-center space-x-2">
          <Select value={viewMode} onValueChange={(value: any) => setViewMode(value)}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="View Mode" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="default">Default View</SelectItem>
              <SelectItem value="vulnerabilities">Vulnerability View</SelectItem>
              <SelectItem value="services">Service View</SelectItem>
            </SelectContent>
          </Select>
          
          <Button variant="outline" size="icon" onClick={handleRefresh}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          </Button>
        </div>
      </CardHeader>
      
      <CardContent>
        {error ? (
          <div className="flex items-center justify-center h-[500px] bg-muted/50 rounded-md">
            <p className="text-muted-foreground">Error loading network topology: {error}</p>
          </div>
        ) : (
          <div className="relative">
            {/* Network visualization container */}
            <div 
              ref={containerRef} 
              className="h-[500px] bg-muted/20 rounded-md border"
              style={{ background: 'radial-gradient(circle, rgba(15,23,42,0.7) 0%, rgba(15,23,42,1) 100%)' }}
            />
            
            {/* Loading overlay */}
            {loading && (
              <div className="absolute inset-0 flex items-center justify-center bg-background/50 rounded-md">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
              </div>
            )}
            
            {/* Controls */}
            <div className="absolute bottom-4 right-4 flex space-x-2">
              <Button variant="secondary" size="icon" onClick={handleZoomIn}>
                <ZoomIn className="h-4 w-4" />
              </Button>
              <Button variant="secondary" size="icon" onClick={handleZoomOut}>
                <ZoomOut className="h-4 w-4" />
              </Button>
              <Button variant="secondary" size="icon" onClick={handleFitToScreen}>
                <Maximize className="h-4 w-4" />
              </Button>
              <Button variant="secondary" size="icon" onClick={handleExport}>
                <Download className="h-4 w-4" />
              </Button>
            </div>
            
            {/* Selected node details */}
            {selectedNode && (
              <div className="absolute top-4 left-4 w-64 bg-card rounded-md shadow-lg border p-4">
                <h3 className="font-medium text-sm mb-2">{selectedNode.data.label}</h3>
                <p className="text-xs text-muted-foreground mb-2">IP: {selectedNode.data.ip}</p>
                
                {selectedNode.data.services && selectedNode.data.services.length > 0 && (
                  <div className="mb-2">
                    <p className="text-xs font-medium mb-1">Services:</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.data.services.map((service: any, index: number) => (
                        <Badge key={index} variant="outline" className="text-xs">
                          {service.name}:{service.port}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                
                {selectedNode.data.vulnerabilities > 0 && (
                  <div className="mb-2">
                    <p className="text-xs font-medium mb-1">Vulnerabilities:</p>
                    <Badge className={`text-xs ${selectedNode.data.vulnerabilities > 3 ? 'severity-critical' : 'severity-high'}`}>
                      {selectedNode.data.vulnerabilities} found
                    </Badge>
                  </div>
                )}
                
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="w-full mt-2 text-xs"
                  onClick={() => setSelectedNode(null)}
                >
                  Close
                </Button>
              </div>
            )}
          </div>
        )}
        
        {/* Legend */}
        <div className="mt-4 flex flex-wrap gap-4 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-orange rounded-sm"></div>
            <span>Router</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-500 rounded-sm"></div>
            <span>Web Server</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded-sm"></div>
            <span>SSH Server</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-purple-500 rounded-sm"></div>
            <span>Database</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded-sm"></div>
            <span>IoT Device</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-cyan-500 rounded-sm"></div>
            <span>Monitoring</span>
          </div>
          
          {viewMode === 'vulnerabilities' && (
            <>
              <div className="flex items-center gap-2 ml-4">
                <div className="w-3 h-3 bg-red-600 rounded-sm"></div>
                <span>Critical (5+)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-orange-500 rounded-sm"></div>
                <span>High (3-4)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-yellow-500 rounded-sm"></div>
                <span>Medium (1-2)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-green-500 rounded-sm"></div>
                <span>None (0)</span>
              </div>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}