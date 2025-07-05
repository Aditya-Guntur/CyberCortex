import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Search, Clock, User, AlertCircle } from 'lucide-react'

export function RecentScans() {
  const scans = [
    {
      id: 'scan-001',
      type: 'Network Discovery',
      target: '192.168.1.0/24',
      status: 'completed' as const,
      duration: '4m 32s',
      findings: 12,
      agent: 'recon-001',
      timestamp: '10 minutes ago'
    },
    {
      id: 'scan-002',
      type: 'Vulnerability Assessment', 
      target: 'web.company.com',
      status: 'running' as const,
      duration: '12m 15s',
      findings: 8,
      agent: 'vuln-002',
      timestamp: '25 minutes ago'
    },
    {
      id: 'scan-003',
      type: 'Compliance Check',
      target: 'Production Environment',
      status: 'completed' as const,
      duration: '8m 45s',
      findings: 3,
      agent: 'compliance-004',
      timestamp: '1 hour ago'
    },
    {
      id: 'scan-004',
      type: 'Web Application',
      target: 'api.company.com',
      status: 'failed' as const,
      duration: '2m 10s',
      findings: 0,
      agent: 'vuln-002',
      timestamp: '2 hours ago'
    },
    {
      id: 'scan-005',
      type: 'Threat Intelligence',
      target: 'Global IOCs',
      status: 'completed' as const,
      duration: '15m 30s',
      findings: 24,
      agent: 'threat-003',
      timestamp: '3 hours ago'
    }
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'status-online'
      case 'running': return 'status-scanning'
      case 'failed': return 'status-offline'
      case 'queued': return 'status-warning'
      default: return 'status-warning'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <div className="w-2 h-2 bg-status-online rounded-full" />
      case 'running': return <div className="w-2 h-2 bg-status-scanning rounded-full animate-pulse" />
      case 'failed': return <AlertCircle className="w-3 h-3 text-status-offline" />
      case 'queued': return <Clock className="w-3 h-3 text-status-warning" />
      default: return <div className="w-2 h-2 bg-muted rounded-full" />
    }
  }

  const getSeverityColor = (findings: number) => {
    if (findings >= 20) return 'severity-critical'
    if (findings >= 10) return 'severity-high'
    if (findings >= 5) return 'severity-medium'
    if (findings > 0) return 'severity-low'
    return 'severity-info'
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="w-5 h-5 text-cyber-500" />
          Recent Scans
        </CardTitle>
        <CardDescription>
          Latest security assessments and scan results
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {scans.map((scan) => (
            <div key={scan.id} className="border rounded-lg p-3 hover:bg-muted/50 transition-colors">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  {getStatusIcon(scan.status)}
                  <span className="font-medium text-sm">{scan.type}</span>
                </div>
                <Badge className={`text-xs ${getStatusColor(scan.status)}`}>
                  {scan.status.toUpperCase()}
                </Badge>
              </div>
              
              <div className="text-xs text-muted-foreground mb-2">
                <span>Target: </span>
                <span className="font-mono text-foreground">{scan.target}</span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground mb-2">
                <div className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Duration: {scan.duration}
                </div>
                <div className="flex items-center gap-1">
                  <User className="w-3 h-3" />
                  Agent: {scan.agent}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="text-xs text-muted-foreground">
                  {scan.timestamp}
                </div>
                <Badge className={`text-xs ${getSeverityColor(scan.findings)}`}>
                  {scan.findings} findings
                </Badge>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 text-center">
          <button className="text-sm text-cyber-500 hover:text-cyber-600 transition-colors">
            View All Scans →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}