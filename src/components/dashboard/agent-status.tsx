import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Bot, Activity, Clock, Zap } from 'lucide-react'

export function AgentStatus() {
  const agents = [
    {
      id: 'recon-001',
      name: 'Reconnaissance Agent',
      status: 'online' as const,
      uptime: '99.8%',
      tasksCompleted: 1247,
      currentTask: 'Network Discovery',
      capabilities: ['Nmap', 'Masscan', 'DNS Enum']
    },
    {
      id: 'vuln-002', 
      name: 'Vulnerability Scanner',
      status: 'busy' as const,
      uptime: '99.5%',
      tasksCompleted: 892,
      currentTask: 'CVE Assessment',
      capabilities: ['Nessus', 'OpenVAS', 'Nuclei']
    },
    {
      id: 'threat-003',
      name: 'Threat Intelligence',
      status: 'online' as const,
      uptime: '100%',
      tasksCompleted: 2156,
      currentTask: 'IOC Analysis',
      capabilities: ['MISP', 'YARA', 'Sigma']
    },
    {
      id: 'compliance-004',
      name: 'Compliance Checker',
      status: 'online' as const,
      uptime: '98.9%',
      tasksCompleted: 567,
      currentTask: 'SOC2 Validation',
      capabilities: ['CIS', 'NIST', 'ISO27001']
    },
    {
      id: 'incident-005',
      name: 'Incident Responder',
      status: 'standby' as const,
      uptime: '99.9%',
      tasksCompleted: 89,
      currentTask: 'Monitoring',
      capabilities: ['SOAR', 'Playbooks', 'Forensics']
    },
    {
      id: 'report-006',
      name: 'Report Generator',
      status: 'online' as const,
      uptime: '99.7%',
      tasksCompleted: 445,
      currentTask: 'Executive Summary',
      capabilities: ['PDF', 'Dashboard', 'Metrics']
    }
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'status-online'
      case 'busy': return 'status-scanning'
      case 'standby': return 'status-warning'
      case 'offline': return 'status-offline'
      default: return 'status-warning'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <div className="w-2 h-2 bg-status-online rounded-full" />
      case 'busy': return <div className="w-2 h-2 bg-status-scanning rounded-full animate-pulse" />
      case 'standby': return <div className="w-2 h-2 bg-status-warning rounded-full" />
      case 'offline': return <div className="w-2 h-2 bg-status-offline rounded-full" />
      default: return <div className="w-2 h-2 bg-muted rounded-full" />
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-cyber-500" />
          Agent Status
        </CardTitle>
        <CardDescription>
          Multi-agent system monitoring and coordination
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {agents.map((agent) => (
            <div key={agent.id} className="border rounded-lg p-3 hover:bg-muted/50 transition-colors">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  {getStatusIcon(agent.status)}
                  <span className="font-medium text-sm">{agent.name}</span>
                </div>
                <Badge className={`text-xs ${getStatusColor(agent.status)}`}>
                  {agent.status.toUpperCase()}
                </Badge>
              </div>
              
              <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground mb-2">
                <div className="flex items-center gap-1">
                  <Activity className="w-3 h-3" />
                  Uptime: {agent.uptime}
                </div>
                <div className="flex items-center gap-1">
                  <Zap className="w-3 h-3" />
                  Tasks: {agent.tasksCompleted}
                </div>
              </div>

              <div className="text-xs mb-2">
                <span className="text-muted-foreground">Current: </span>
                <span className="text-foreground">{agent.currentTask}</span>
              </div>

              <div className="flex flex-wrap gap-1">
                {agent.capabilities.map((capability, index) => (
                  <Badge key={index} variant="outline" className="text-xs">
                    {capability}
                  </Badge>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 text-center">
          <button className="text-sm text-cyber-500 hover:text-cyber-600 transition-colors">
            Manage Agents →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}