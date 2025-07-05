import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Eye, Globe, AlertTriangle, Clock } from 'lucide-react'

export function ThreatIntelligence() {
  const threats = [
    {
      id: '1',
      title: 'APT29 Campaign Targeting Healthcare',
      severity: 'critical' as const,
      confidence: 95,
      source: 'MITRE ATT&CK',
      timestamp: '2 hours ago',
      iocs: ['185.220.101.42', 'malware.exe', 'apt29-c2.com']
    },
    {
      id: '2', 
      title: 'CVE-2024-0001 Active Exploitation',
      severity: 'high' as const,
      confidence: 87,
      source: 'CISA',
      timestamp: '4 hours ago',
      iocs: ['192.168.1.100', 'exploit.php']
    },
    {
      id: '3',
      title: 'Phishing Campaign - Financial Sector',
      severity: 'medium' as const,
      confidence: 72,
      source: 'PhishTank',
      timestamp: '6 hours ago',
      iocs: ['phishing-site.com', 'fake-bank.net']
    }
  ]

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return 'severity-info'
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Eye className="w-5 h-5 text-cyber-500" />
          Threat Intelligence
        </CardTitle>
        <CardDescription>
          Real-time threat feeds and indicators of compromise
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {threats.map((threat) => (
            <div key={threat.id} className="border rounded-lg p-4 hover:bg-muted/50 transition-colors">
              <div className="flex items-start justify-between mb-2">
                <h4 className="font-medium text-sm">{threat.title}</h4>
                <Badge className={`text-xs ${getSeverityColor(threat.severity)}`}>
                  <AlertTriangle className="w-3 h-3 mr-1" />
                  {threat.severity.toUpperCase()}
                </Badge>
              </div>
              
              <div className="flex items-center gap-4 text-xs text-muted-foreground mb-2">
                <div className="flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  {threat.source}
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {threat.timestamp}
                </div>
                <div>
                  Confidence: {threat.confidence}%
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {threat.iocs.map((ioc, index) => (
                  <Badge key={index} variant="outline" className="text-xs font-mono">
                    {ioc}
                  </Badge>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 text-center">
          <button className="text-sm text-cyber-500 hover:text-cyber-600 transition-colors">
            View All Threats →
          </button>
        </div>
      </CardContent>
    </Card>
  )
}