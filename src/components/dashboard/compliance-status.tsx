import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Shield, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react'

export function ComplianceStatus() {
  const frameworks = [
    {
      id: 'soc2',
      name: 'SOC 2 Type II',
      status: 'compliant' as const,
      score: 94,
      controls: { passed: 47, failed: 3, total: 50 },
      lastAssessment: '2 days ago',
      nextAssessment: 'In 28 days'
    },
    {
      id: 'iso27001',
      name: 'ISO 27001',
      status: 'partial' as const,
      score: 78,
      controls: { passed: 89, failed: 12, total: 114 },
      lastAssessment: '1 week ago',
      nextAssessment: 'In 21 days'
    },
    {
      id: 'nist',
      name: 'NIST CSF',
      status: 'compliant' as const,
      score: 91,
      controls: { passed: 82, failed: 8, total: 98 },
      lastAssessment: '3 days ago',
      nextAssessment: 'In 25 days'
    },
    {
      id: 'gdpr',
      name: 'GDPR',
      status: 'non-compliant' as const,
      score: 65,
      controls: { passed: 23, failed: 12, total: 35 },
      lastAssessment: '5 days ago',
      nextAssessment: 'In 2 days'
    }
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'status-online'
      case 'partial': return 'status-warning'
      case 'non-compliant': return 'status-offline'
      default: return 'status-warning'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant': return <CheckCircle className="w-4 h-4 text-status-online" />
      case 'partial': return <AlertTriangle className="w-4 h-4 text-status-warning" />
      case 'non-compliant': return <XCircle className="w-4 h-4 text-status-offline" />
      default: return <Clock className="w-4 h-4 text-muted-foreground" />
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-status-online'
    if (score >= 75) return 'text-status-warning'
    return 'text-status-offline'
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyber-500" />
          Compliance Status
        </CardTitle>
        <CardDescription>
          Regulatory framework compliance monitoring
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {frameworks.map((framework) => (
            <div key={framework.id} className="border rounded-lg p-3 hover:bg-muted/50 transition-colors">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  {getStatusIcon(framework.status)}
                  <span className="font-medium text-sm">{framework.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-lg font-bold ${getScoreColor(framework.score)}`}>
                    {framework.score}%
                  </span>
                  <Badge className={`text-xs ${getStatusColor(framework.status)}`}>
                    {framework.status.replace('-', ' ').toUpperCase()}
                  </Badge>
                </div>
              </div>
              
              <div className="grid grid-cols-3 gap-2 text-xs mb-2">
                <div className="text-center">
                  <div className="font-medium text-status-online">{framework.controls.passed}</div>
                  <div className="text-muted-foreground">Passed</div>
                </div>
                <div className="text-center">
                  <div className="font-medium text-status-offline">{framework.controls.failed}</div>
                  <div className="text-muted-foreground">Failed</div>
                </div>
                <div className="text-center">
                  <div className="font-medium text-foreground">{framework.controls.total}</div>
                  <div className="text-muted-foreground">Total</div>
                </div>
              </div>

              <div className="w-full bg-muted rounded-full h-2 mb-2">
                <div 
                  className="bg-cyber-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${framework.score}%` }}
                />
              </div>

              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Last: {framework.lastAssessment}</span>
                <span>Next: {framework.nextAssessment}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 p-3 bg-muted/50 rounded-lg">
          <div className="text-sm font-medium mb-1">Overall Compliance Score</div>
          <div className="flex items-center gap-2">
            <div className="text-2xl font-bold text-cyber-500">82%</div>
            <Badge variant="outline" className="text-xs">
              <AlertTriangle className="w-3 h-3 mr-1" />
              Action Required
            </Badge>
          </div>
        </div>

        <div className="mt-4 text-center">
          <button className="text-sm text-cyber-500 hover:text-cyber-600 transition-colors">
            View Compliance Reports →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}