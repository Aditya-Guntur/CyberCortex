import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Bell, AlertTriangle, Info, Shield, Clock } from 'lucide-react'

export function RealTimeAlerts() {
  const alerts = [
    {
      id: 'alert-001',
      title: 'Critical Vulnerability Detected',
      description: 'CVE-2024-0001 found in production web server',
      severity: 'critical' as const,
      category: 'security-incident',
      source: 'Vulnerability Scanner',
      timestamp: '2 minutes ago',
      status: 'new' as const
    },
    {
      id: 'alert-002',
      title: 'Suspicious Network Activity',
      description: 'Unusual outbound connections detected from 192.168.1.100',
      severity: 'high' as const,
      category: 'threat-detected',
      source: 'Network Monitor',
      timestamp: '5 minutes ago',
      status: 'investigating' as const
    },
    {
      id: 'alert-003',
      title: 'Compliance Violation',
      description: 'SOC2 control failure: Encryption not enabled on database',
      severity: 'medium' as const,
      category: 'compliance-violation',
      source: 'Compliance Checker',
      timestamp: '12 minutes ago',
      status: 'acknowledged' as const
    },
    {
      id: 'alert-004',
      title: 'Agent Status Change',
      description: 'Vulnerability Scanner agent went offline unexpectedly',
      severity: 'medium' as const,
      category: 'agent-status',
      source: 'System Monitor',
      timestamp: '18 minutes ago',
      status: 'resolved' as const
    },
    {
      id: 'alert-005',
      title: 'Scan Completed',
      description: 'Network discovery scan completed with 12 new findings',
      severity: 'info' as const,
      category: 'scan-completed',
      source: 'Reconnaissance Agent',
      timestamp: '25 minutes ago',
      status: 'resolved' as const
    }
  ]

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      case 'info': return 'severity-info'
      default: return 'severity-info'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="w-4 h-4" />
      case 'medium':
        return <Shield className="w-4 h-4" />
      case 'low':
      case 'info':
        return <Info className="w-4 h-4" />
      default:
        return <Info className="w-4 h-4" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'new': return 'status-offline'
      case 'acknowledged': return 'status-warning'
      case 'investigating': return 'status-scanning'
      case 'resolved': return 'status-online'
      default: return 'status-warning'
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security-incident':
        return <AlertTriangle className="w-3 h-3" />
      case 'compliance-violation':
        return <Shield className="w-3 h-3" />
      case 'threat-detected':
        return <AlertTriangle className="w-3 h-3" />
      case 'agent-status':
        return <Info className="w-3 h-3" />
      case 'scan-completed':
        return <Info className="w-3 h-3" />
      default:
        return <Info className="w-3 h-3" />
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bell className="w-5 h-5 text-cyber-500" />
          Real-time Alerts
          <Badge className="ml-auto text-xs severity-critical">
            {alerts.filter(a => a.status === 'new').length} New
          </Badge>
        </CardTitle>
        <CardDescription>
          Live security alerts and system notifications
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {alerts.map((alert) => (
            <div key={alert.id} className="border rounded-lg p-3 hover:bg-muted/50 transition-colors">
              <div className="flex items-start gap-3">
                <div className={`p-1 rounded ${getSeverityColor(alert.severity)}`}>
                  {getSeverityIcon(alert.severity)}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="font-medium text-sm truncate">{alert.title}</h4>
                    <Badge className={`text-xs ${getStatusColor(alert.status)}`}>
                      {alert.status.toUpperCase()}
                    </Badge>
                  </div>
                  
                  <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                    {alert.description}
                  </p>
                  
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1">
                        {getCategoryIcon(alert.category)}
                        <span>{alert.source}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      <span>{alert.timestamp}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 flex gap-2">
          <button className="flex-1 text-sm text-cyber-500 hover:text-cyber-600 transition-colors text-center py-2 border border-cyber-500/20 rounded hover:bg-cyber-500/5">
            Mark All Read
          </button>
          <button className="flex-1 text-sm text-cyber-500 hover:text-cyber-600 transition-colors text-center py-2 border border-cyber-500/20 rounded hover:bg-cyber-500/5">
            View All Alerts
          </button>
        </div>
      </CardContent>
    </Card>
  )
}