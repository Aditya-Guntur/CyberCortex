"use client"

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  Shield, 
  TrendingUp, 
  AlertTriangle, 
  CheckCircle, 
  Activity,
  Zap,
  Eye,
  Users,
  Clock,
  BarChart3,
  Mic,
  MicOff
} from 'lucide-react'
import { useDashboard, useSecurityMetrics, useAgents, useAlerts } from '@/hooks/use-dashboard'
import { useWebSocket } from '@/hooks/use-websocket'
import { useVoice } from '@/hooks/use-voice'
import { SecurityDashboardProps } from '@/types/dashboard'
import { cn } from '@/lib/utils'
import { formatRelativeTime } from '@/lib/utils'

export function SecurityDashboard({ className, refreshInterval = 30000 }: SecurityDashboardProps) {
  const [mounted, setMounted] = useState(false)
  
  const {
    fetchSecurityMetrics,
    fetchAgents,
    fetchAlerts,
    loading,
    error,
    lastUpdate,
    connected
  } = useDashboard()

  const securityMetrics = useSecurityMetrics()
  const agents = useAgents()
  const alerts = useAlerts()

  // WebSocket connection for real-time updates
  useWebSocket({
    onConnect: () => {
      console.log('Dashboard connected to real-time updates')
    },
    onMessage: (data) => {
      console.log('Real-time update received:', data.type)
    }
  })

  // Voice interface
  const {
    isSupported: voiceSupported,
    isListening,
    voiceEnabled,
    toggleListening,
    enableVoice,
    disableVoice
  } = useVoice({
    onResult: (transcript, confidence) => {
      console.log('Voice command:', transcript, 'Confidence:', confidence)
    }
  })

  // Initial data fetch and periodic refresh
  useEffect(() => {
    setMounted(true)
    
    const fetchData = async () => {
      await Promise.all([
        fetchSecurityMetrics(),
        fetchAgents(),
        fetchAlerts()
      ])
    }

    fetchData()

    const interval = setInterval(fetchData, refreshInterval)
    return () => clearInterval(interval)
  }, [fetchSecurityMetrics, fetchAgents, fetchAlerts, refreshInterval])

  if (!mounted) {
    return <div className="animate-pulse">Loading dashboard...</div>
  }

  const getSecurityScoreColor = (score: number) => {
    if (score >= 90) return 'text-status-online'
    if (score >= 75) return 'text-status-warning'
    return 'text-status-offline'
  }

  const getSecurityScoreStatus = (score: number) => {
    if (score >= 90) return 'Excellent'
    if (score >= 75) return 'Good'
    if (score >= 60) return 'Fair'
    return 'Poor'
  }

  const activeAgents = agents.filter(agent => agent.status === 'online' || agent.status === 'busy')
  const criticalAlerts = alerts.filter(alert => alert.severity === 'critical' && alert.status === 'new')
  const highAlerts = alerts.filter(alert => alert.severity === 'high' && alert.status === 'new')

  return (
    <div className={cn("space-y-6", className)}>
      {/* Header with Voice Control */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time security posture and threat landscape overview
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Connection Status */}
          <div className="flex items-center gap-2">
            <div className={cn(
              "w-2 h-2 rounded-full",
              connected ? "bg-status-online animate-pulse" : "bg-status-offline"
            )} />
            <span className="text-sm text-muted-foreground">
              {connected ? 'Live' : 'Disconnected'}
            </span>
          </div>

          {/* Voice Control */}
          {voiceSupported && (
            <div className="flex items-center gap-2">
              <Button
                variant={voiceEnabled ? "default" : "outline"}
                size="sm"
                onClick={() => voiceEnabled ? disableVoice() : enableVoice()}
              >
                {voiceEnabled ? <Mic className="w-4 h-4" /> : <MicOff className="w-4 h-4" />}
                Voice
              </Button>
              
              {voiceEnabled && (
                <Button
                  variant={isListening ? "destructive" : "secondary"}
                  size="sm"
                  onClick={toggleListening}
                  className={cn(
                    "transition-all",
                    isListening && "animate-pulse"
                  )}
                >
                  {isListening ? "Stop" : "Listen"}
                </Button>
              )}
            </div>
          )}

          {/* Last Update */}
          {lastUpdate && (
            <div className="text-sm text-muted-foreground">
              Updated {formatRelativeTime(lastUpdate)}
            </div>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <Card className="border-status-offline">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-status-offline">
              <AlertTriangle className="w-5 h-5" />
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Security Score */}
        <Card className="relative overflow-hidden">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
            <Shield className="w-4 h-4 text-cyber-500" />
          </CardHeader>
          <CardContent>
            <div className={cn(
              "text-2xl font-bold",
              getSecurityScoreColor(securityMetrics?.overallScore || 0)
            )}>
              {securityMetrics?.overallScore || 0}/100
            </div>
            <p className="text-xs text-muted-foreground">
              {getSecurityScoreStatus(securityMetrics?.overallScore || 0)}
              {securityMetrics?.trend && (
                <span className="ml-2 inline-flex items-center">
                  <TrendingUp className="w-3 h-3 mr-1" />
                  {securityMetrics.trend}
                </span>
              )}
            </p>
            <div className="mt-2 w-full bg-muted rounded-full h-2">
              <div 
                className="bg-cyber-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${securityMetrics?.overallScore || 0}%` }}
              />
            </div>
          </CardContent>
        </Card>

        {/* Critical Issues */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="w-4 h-4 text-status-offline" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-status-offline">
              {securityMetrics?.criticalIssues || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Requires immediate attention
            </p>
            {criticalAlerts.length > 0 && (
              <Badge variant="destructive" className="mt-2">
                {criticalAlerts.length} new alerts
              </Badge>
            )}
          </CardContent>
        </Card>

        {/* Active Agents */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
            <Users className="w-4 h-4 text-cyber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-cyber-500">
              {activeAgents.length}
            </div>
            <p className="text-xs text-muted-foreground">
              {agents.length} total agents
            </p>
            <div className="mt-2 flex gap-1">
              {agents.slice(0, 6).map((agent, index) => (
                <div
                  key={agent.id}
                  className={cn(
                    "w-2 h-2 rounded-full",
                    agent.status === 'online' ? "bg-status-online" :
                    agent.status === 'busy' ? "bg-status-scanning animate-pulse" :
                    agent.status === 'error' ? "bg-status-offline" :
                    "bg-muted"
                  )}
                  title={`${agent.name}: ${agent.status}`}
                />
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Recent Activity</CardTitle>
            <Activity className="w-4 h-4 text-status-online" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-status-online">
              {securityMetrics?.resolvedIssues || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Issues resolved today
            </p>
            {securityMetrics?.activeScans && securityMetrics.activeScans > 0 && (
              <Badge variant="outline" className="mt-2">
                <Zap className="w-3 h-3 mr-1" />
                {securityMetrics.activeScans} scans running
              </Badge>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Security Trend Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyber-500" />
            Security Posture Trend
          </CardTitle>
          <CardDescription>
            7-day security score trend with key events
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-end justify-between px-4">
            {/* Mock trend data - replace with actual chart component */}
            {[78, 82, 85, 83, 87, 89, securityMetrics?.overallScore || 87].map((value, index) => (
              <div key={index} className="flex flex-col items-center gap-2">
                <div
                  className="bg-cyber-500 rounded-t w-8 transition-all duration-300 hover:bg-cyber-400"
                  style={{ height: `${(value / 100) * 200}px` }}
                  title={`Day ${index + 1}: ${value}%`}
                />
                <span className="text-xs text-muted-foreground">
                  {index === 6 ? 'Today' : `${7 - index}d`}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Common security operations and assessments
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Button variant="outline" className="h-20 flex flex-col gap-2">
              <Eye className="w-6 h-6" />
              <span className="text-sm">Network Scan</span>
            </Button>
            
            <Button variant="outline" className="h-20 flex flex-col gap-2">
              <Shield className="w-6 h-6" />
              <span className="text-sm">Vulnerability Assessment</span>
            </Button>
            
            <Button variant="outline" className="h-20 flex flex-col gap-2">
              <CheckCircle className="w-6 h-6" />
              <span className="text-sm">Compliance Check</span>
            </Button>
            
            <Button variant="outline" className="h-20 flex flex-col gap-2">
              <BarChart3 className="w-6 h-6" />
              <span className="text-sm">Generate Report</span>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* System Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent Status */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="w-5 h-5 text-cyber-500" />
              Agent Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {agents.slice(0, 5).map((agent) => (
                <div key={agent.id} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      "w-2 h-2 rounded-full",
                      agent.status === 'online' ? "bg-status-online" :
                      agent.status === 'busy' ? "bg-status-scanning animate-pulse" :
                      agent.status === 'error' ? "bg-status-offline" :
                      "bg-muted"
                    )} />
                    <div>
                      <div className="font-medium text-sm">{agent.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {agent.currentTask || 'Idle'}
                      </div>
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    {agent.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Recent Alerts */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-status-warning" />
              Recent Alerts
              {alerts.length > 0 && (
                <Badge className="ml-auto">
                  {alerts.filter(a => a.status === 'new').length} new
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {alerts.slice(0, 5).map((alert) => (
                <div key={alert.id} className="flex items-start gap-3">
                  <div className={cn(
                    "w-2 h-2 rounded-full mt-2",
                    alert.severity === 'critical' ? "bg-status-offline" :
                    alert.severity === 'high' ? "bg-status-warning" :
                    "bg-status-online"
                  )} />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm truncate">{alert.title}</div>
                    <div className="text-xs text-muted-foreground">
                      {alert.source} • {formatRelativeTime(alert.timestamp)}
                    </div>
                  </div>
                  <Badge 
                    variant="outline" 
                    className={cn(
                      "text-xs",
                      alert.severity === 'critical' && "border-status-offline text-status-offline",
                      alert.severity === 'high' && "border-status-warning text-status-warning"
                    )}
                  >
                    {alert.severity}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Loading Overlay */}
      {loading && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="flex items-center gap-3">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyber-500" />
            <span>Updating dashboard...</span>
          </div>
        </div>
      )}
    </div>
  )
}