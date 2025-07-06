import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Bot, Activity, Zap, Brain, Database, Network } from 'lucide-react';
import { useSimulationState } from '@/hooks/useSimulationState';
import { formatRelativeTime } from '@/lib/utils';

interface AIServiceMonitorProps {
  className?: string;
}

export function AIServiceMonitor({ className }: AIServiceMonitorProps) {
  const { simulation } = useSimulationState();
  const aiServices = simulation?.ai_services || {};

  // Helper function to get status color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'status-scanning';
      case 'initializing': return 'status-warning';
      case 'idle': return 'status-online';
      case 'error': return 'status-offline';
      default: return 'text-muted-foreground';
    }
  };

  // Helper function to get status icon
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <div className="w-2 h-2 bg-status-scanning rounded-full animate-pulse" />;
      case 'initializing': return <div className="w-2 h-2 bg-status-warning rounded-full" />;
      case 'idle': return <div className="w-2 h-2 bg-status-online rounded-full" />;
      case 'error': return <div className="w-2 h-2 bg-status-offline rounded-full" />;
      default: return <div className="w-2 h-2 bg-muted rounded-full" />;
    }
  };

  // Helper function to get service icon
  const getServiceIcon = (service: string) => {
    switch (service) {
      case 'fetch_agents': return <Network className="w-5 h-5 text-blue-500" />;
      case 'groq_analyzers': return <Brain className="w-5 h-5 text-purple-500" />;
      case 'coral_coordinator': return <Bot className="w-5 h-5 text-green-500" />;
      case 'blackbox_generator': return <Zap className="w-5 h-5 text-yellow-500" />;
      case 'snowflake_analyzer': return <Database className="w-5 h-5 text-cyan-500" />;
      default: return <Activity className="w-5 h-5 text-muted-foreground" />;
    }
  };

  // Helper function to get service name
  const getServiceName = (service: string) => {
    switch (service) {
      case 'fetch_agents': return 'Fetch.ai Agents';
      case 'groq_analyzers': return 'Groq Analyzers';
      case 'coral_coordinator': return 'Coral Coordinator';
      case 'blackbox_generator': return 'Blackbox Generator';
      case 'snowflake_analyzer': return 'Snowflake Analyzer';
      default: return service;
    }
  };

  // Helper function to get service description
  const getServiceDescription = (service: string) => {
    switch (service) {
      case 'fetch_agents': return 'Network discovery and scanning';
      case 'groq_analyzers': return 'Vulnerability analysis and assessment';
      case 'coral_coordinator': return 'Multi-agent coordination and task distribution';
      case 'blackbox_generator': return 'Exploit code generation and validation';
      case 'snowflake_analyzer': return 'Security analytics and reporting';
      default: return '';
    }
  };

  // Calculate overall AI pipeline progress
  const calculateProgress = () => {
    if (!simulation?.running) return 0;
    
    const phases = ['initializing', 'network_discovery', 'vulnerability_analysis', 'exploit_generation', 'ai_coordination', 'analytics', 'completed'];
    const currentPhase = simulation?.current_phase || 'idle';
    const phaseIndex = phases.indexOf(currentPhase);
    
    if (phaseIndex === -1) return 0;
    return Math.round((phaseIndex / (phases.length - 1)) * 100);
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-cyber-500" />
          AI Service Pipeline
        </CardTitle>
        <CardDescription>
          Real-time status of coordinated AI services
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Overall Progress */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-medium">Pipeline Progress</div>
            <div className="text-sm text-muted-foreground">{calculateProgress()}%</div>
          </div>
          <Progress value={calculateProgress()} className="h-2" />
          <div className="mt-2 text-xs text-muted-foreground">
            Current Phase: <span className="font-medium text-foreground capitalize">{simulation?.current_phase?.replace('_', ' ') || 'Idle'}</span>
          </div>
        </div>

        {/* AI Services */}
        <div className="space-y-4">
          {Object.entries(aiServices).map(([service, info]: [string, any]) => (
            <div key={service} className="border rounded-lg p-3 hover:bg-muted/50 transition-colors">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  {getServiceIcon(service)}
                  <div>
                    <div className="font-medium text-sm">{getServiceName(service)}</div>
                    <div className="text-xs text-muted-foreground">{getServiceDescription(service)}</div>
                  </div>
                </div>
                <Badge className={`text-xs ${getStatusColor(info.status)}`}>
                  {getStatusIcon(info.status)}
                  <span className="ml-1 uppercase">{info.status}</span>
                </Badge>
              </div>
              
              {info.last_activity && (
                <div className="text-xs text-muted-foreground">
                  Last Activity: {formatRelativeTime(new Date(info.last_activity))}
                </div>
              )}
              
              {/* Service-specific metrics could be added here */}
            </div>
          ))}
        </div>

        {/* AI Coordination Visualization */}
        <div className="mt-6 p-4 border rounded-lg bg-muted/20">
          <h3 className="text-sm font-medium mb-3">AI Service Coordination</h3>
          <div className="flex items-center justify-between">
            <div className="flex flex-col items-center">
              <Network className="w-8 h-8 text-blue-500 mb-2" />
              <div className="text-xs">Fetch.ai</div>
            </div>
            
            <div className="h-0.5 flex-1 bg-gradient-to-r from-blue-500 to-purple-500"></div>
            
            <div className="flex flex-col items-center">
              <Brain className="w-8 h-8 text-purple-500 mb-2" />
              <div className="text-xs">Groq</div>
            </div>
            
            <div className="h-0.5 flex-1 bg-gradient-to-r from-purple-500 to-green-500"></div>
            
            <div className="flex flex-col items-center">
              <Bot className="w-8 h-8 text-green-500 mb-2" />
              <div className="text-xs">Coral</div>
            </div>
            
            <div className="h-0.5 flex-1 bg-gradient-to-r from-green-500 to-yellow-500"></div>
            
            <div className="flex flex-col items-center">
              <Zap className="w-8 h-8 text-yellow-500 mb-2" />
              <div className="text-xs">Blackbox</div>
            </div>
            
            <div className="h-0.5 flex-1 bg-gradient-to-r from-yellow-500 to-cyan-500"></div>
            
            <div className="flex flex-col items-center">
              <Database className="w-8 h-8 text-cyan-500 mb-2" />
              <div className="text-xs">Snowflake</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}