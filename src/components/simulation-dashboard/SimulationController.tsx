import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Play, 
  Square, 
  Settings, 
  RefreshCw, 
  Clock, 
  Shield, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2
} from 'lucide-react';
import { useSimulationState } from '@/hooks/useSimulationState';
import { formatDuration } from '@/lib/utils';

interface SimulationControllerProps {
  className?: string;
}

export function SimulationController({ className }: SimulationControllerProps) {
  const { 
    simulation, 
    startSimulation, 
    stopSimulation, 
    loading 
  } = useSimulationState();
  
  const [simulationConfig, setSimulationConfig] = useState({
    duration_minutes: 30,
    scan_intensity: 'medium',
    target_services: ['web', 'ssh', 'database', 'iot'],
    exploit_validation: true,
    ai_services: ['fetch', 'groq', 'coral', 'blackbox', 'snowflake']
  });

  // Calculate simulation duration
  const calculateDuration = () => {
    if (!simulation?.running || !simulation?.start_time) return null;
    
    const startTime = new Date(simulation.start_time);
    const now = new Date();
    const durationSeconds = Math.floor((now.getTime() - startTime.getTime()) / 1000);
    
    return formatDuration(durationSeconds);
  };

  // Get current phase display name
  const getCurrentPhase = () => {
    const phase = simulation?.current_phase || 'idle';
    return phase.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  // Get phase progress percentage
  const getPhaseProgress = () => {
    const phases = ['initializing', 'network_discovery', 'vulnerability_analysis', 'exploit_generation', 'ai_coordination', 'analytics', 'completed'];
    const currentPhase = simulation?.current_phase || 'idle';
    
    if (currentPhase === 'idle') return 0;
    if (currentPhase === 'error') return 100;
    
    const phaseIndex = phases.indexOf(currentPhase);
    if (phaseIndex === -1) return 0;
    
    return Math.round((phaseIndex / (phases.length - 1)) * 100);
  };

  // Get status icon
  const getStatusIcon = () => {
    if (!simulation?.running) return <Square className="w-5 h-5 text-muted-foreground" />;
    
    const phase = simulation?.current_phase;
    
    if (phase === 'error') return <XCircle className="w-5 h-5 text-status-offline" />;
    if (phase === 'completed') return <CheckCircle className="w-5 h-5 text-status-online" />;
    
    return <Play className="w-5 h-5 text-status-scanning animate-pulse" />;
  };

  // Handle start simulation
  const handleStartSimulation = async () => {
    await startSimulation(simulationConfig);
  };

  // Handle stop simulation
  const handleStopSimulation = async () => {
    await stopSimulation();
  };

  // Handle config change
  const handleConfigChange = (key: string, value: any) => {
    setSimulationConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyber-500" />
          Simulation Control
        </CardTitle>
        <CardDescription>
          Manage and monitor the self-penetration testing simulation
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="status">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="status">Status</TabsTrigger>
            <TabsTrigger value="config">Configuration</TabsTrigger>
          </TabsList>
          
          <TabsContent value="status" className="space-y-4 pt-4">
            {/* Simulation Status */}
            <div className="flex items-center justify-between p-4 border rounded-md bg-muted/20">
              <div className="flex items-center gap-3">
                {getStatusIcon()}
                <div>
                  <h3 className="font-medium">Simulation Status</h3>
                  <p className="text-sm text-muted-foreground">
                    {simulation?.running ? 'Running' : 'Stopped'}
                  </p>
                </div>
              </div>
              
              <Button
                variant={simulation?.running ? "destructive" : "default"}
                onClick={simulation?.running ? handleStopSimulation : handleStartSimulation}
                disabled={loading}
              >
                {loading ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : simulation?.running ? (
                  <Square className="w-4 h-4 mr-2" />
                ) : (
                  <Play className="w-4 h-4 mr-2" />
                )}
                {simulation?.running ? 'Stop Simulation' : 'Start Simulation'}
              </Button>
            </div>
            
            {/* Current Phase */}
            {simulation?.running && (
              <div className="space-y-4">
                <div className="p-4 border rounded-md">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium">Current Phase</h3>
                    <Badge variant="outline">
                      {getCurrentPhase()}
                    </Badge>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span>Progress</span>
                      <span>{getPhaseProgress()}%</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div 
                        className="bg-cyber-500 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${getPhaseProgress()}%` }}
                      />
                    </div>
                  </div>
                </div>
                
                {/* Simulation Metrics */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 border rounded-md">
                    <div className="text-2xl font-bold mb-1">
                      {simulation?.discovered_hosts?.length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Hosts Discovered</div>
                  </div>
                  
                  <div className="p-4 border rounded-md">
                    <div className="text-2xl font-bold mb-1">
                      {simulation?.discovered_vulnerabilities?.length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
                  </div>
                  
                  <div className="p-4 border rounded-md">
                    <div className="text-2xl font-bold mb-1">
                      {simulation?.executed_exploits?.length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Exploits Generated</div>
                  </div>
                  
                  <div className="p-4 border rounded-md">
                    <div className="text-2xl font-bold mb-1">
                      {calculateDuration() || '00:00:00'}
                    </div>
                    <div className="text-sm text-muted-foreground">Elapsed Time</div>
                  </div>
                </div>
              </div>
            )}
            
            {/* Quick Actions */}
            <div className="grid grid-cols-2 gap-4">
              <Button variant="outline" className="w-full" disabled={!simulation?.running}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh Status
              </Button>
              
              <Button variant="outline" className="w-full" disabled={!simulation?.running}>
                <Clock className="w-4 h-4 mr-2" />
                Extend Duration
              </Button>
            </div>
            
            {/* Simulation Safety Notice */}
            <div className="flex items-start gap-3 p-4 border rounded-md bg-muted/20 mt-4">
              <AlertTriangle className="w-5 h-5 text-status-warning flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-sm">Simulation Environment Notice</h4>
                <p className="text-xs text-muted-foreground mt-1">
                  All penetration testing activities are performed in an isolated Docker simulation environment.
                  No actual systems are at risk. All exploits are contained within the simulation network.
                </p>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="config" className="space-y-4 pt-4">
            {/* Simulation Configuration */}
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="duration">Simulation Duration (minutes)</Label>
                <Input
                  id="duration"
                  type="number"
                  min={5}
                  max={120}
                  value={simulationConfig.duration_minutes}
                  onChange={(e) => handleConfigChange('duration_minutes', parseInt(e.target.value))}
                  disabled={simulation?.running}
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="intensity">Scan Intensity</Label>
                <Select
                  value={simulationConfig.scan_intensity}
                  onValueChange={(value) => handleConfigChange('scan_intensity', value)}
                  disabled={simulation?.running}
                >
                  <SelectTrigger id="intensity">
                    <SelectValue placeholder="Select intensity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low - Basic scanning</SelectItem>
                    <SelectItem value="medium">Medium - Standard scanning</SelectItem>
                    <SelectItem value="high">High - Aggressive scanning</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <Label>Target Services</Label>
                <div className="grid grid-cols-2 gap-2">
                  {['web', 'ssh', 'database', 'iot'].map((service) => (
                    <div key={service} className="flex items-center space-x-2">
                      <Switch
                        id={`service-${service}`}
                        checked={simulationConfig.target_services.includes(service)}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            handleConfigChange('target_services', [...simulationConfig.target_services, service]);
                          } else {
                            handleConfigChange(
                              'target_services',
                              simulationConfig.target_services.filter(s => s !== service)
                            );
                          }
                        }}
                        disabled={simulation?.running}
                      />
                      <Label htmlFor={`service-${service}`} className="capitalize">{service}</Label>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch
                  id="exploit-validation"
                  checked={simulationConfig.exploit_validation}
                  onCheckedChange={(checked) => handleConfigChange('exploit_validation', checked)}
                  disabled={simulation?.running}
                />
                <Label htmlFor="exploit-validation">Enable Exploit Validation</Label>
              </div>
              
              <div className="space-y-2">
                <Label>AI Services</Label>
                <div className="grid grid-cols-2 gap-2">
                  {['fetch', 'groq', 'coral', 'blackbox', 'snowflake'].map((service) => (
                    <div key={service} className="flex items-center space-x-2">
                      <Switch
                        id={`ai-${service}`}
                        checked={simulationConfig.ai_services.includes(service)}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            handleConfigChange('ai_services', [...simulationConfig.ai_services, service]);
                          } else {
                            handleConfigChange(
                              'ai_services',
                              simulationConfig.ai_services.filter(s => s !== service)
                            );
                          }
                        }}
                        disabled={simulation?.running}
                      />
                      <Label htmlFor={`ai-${service}`} className="capitalize">{service}</Label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            
            {/* Start Button */}
            <Button
              className="w-full"
              onClick={handleStartSimulation}
              disabled={simulation?.running || loading}
            >
              {loading ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Play className="w-4 h-4 mr-2" />
              )}
              Start Simulation
            </Button>
            
            {/* Advanced Configuration Notice */}
            <div className="text-xs text-muted-foreground mt-2">
              <p>
                Advanced configuration options are available through the API.
                See documentation for details.
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}