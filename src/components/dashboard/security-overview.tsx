import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Shield, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react'

export function SecurityOverview() {
  const securityMetrics = {
    overallScore: 87,
    criticalIssues: 3,
    resolvedIssues: 24,
    activeScans: 2,
    trend: '+5%'
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyber-500" />
          Security Overview
        </CardTitle>
        <CardDescription>
          Real-time security posture and threat landscape
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Security Score */}
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-500 mb-1">
              {securityMetrics.overallScore}
            </div>
            <div className="text-sm text-muted-foreground">Security Score</div>
            <Badge variant="outline" className="mt-1 text-xs">
              <TrendingUp className="w-3 h-3 mr-1" />
              {securityMetrics.trend}
            </Badge>
          </div>

          {/* Critical Issues */}
          <div className="text-center">
            <div className="text-3xl font-bold text-security-critical mb-1">
              {securityMetrics.criticalIssues}
            </div>
            <div className="text-sm text-muted-foreground">Critical Issues</div>
            <Badge className="mt-1 text-xs severity-critical">
              <AlertTriangle className="w-3 h-3 mr-1" />
              Needs Attention
            </Badge>
          </div>

          {/* Resolved Issues */}
          <div className="text-center">
            <div className="text-3xl font-bold text-status-online mb-1">
              {securityMetrics.resolvedIssues}
            </div>
            <div className="text-sm text-muted-foreground">Resolved</div>
            <Badge className="mt-1 text-xs status-online">
              <CheckCircle className="w-3 h-3 mr-1" />
              This Week
            </Badge>
          </div>

          {/* Active Scans */}
          <div className="text-center">
            <div className="text-3xl font-bold text-status-scanning mb-1">
              {securityMetrics.activeScans}
            </div>
            <div className="text-sm text-muted-foreground">Active Scans</div>
            <Badge className="mt-1 text-xs status-scanning">
              <div className="w-2 h-2 bg-current rounded-full animate-pulse mr-1" />
              Running
            </Badge>
          </div>
        </div>

        {/* Security Trend Chart Placeholder */}
        <div className="mt-6 p-4 bg-muted/50 rounded-lg">
          <div className="text-sm font-medium mb-2">Security Posture Trend (7 days)</div>
          <div className="h-20 bg-gradient-to-r from-cyber-500/20 to-cyber-600/20 rounded flex items-end justify-between px-2">
            {[65, 72, 78, 81, 85, 83, 87].map((value, index) => (
              <div
                key={index}
                className="bg-cyber-500 rounded-t w-4"
                style={{ height: `${(value / 100) * 100}%` }}
                title={`Day ${index + 1}: ${value}%`}
              />
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}