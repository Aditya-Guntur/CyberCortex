"use client"

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  Play, 
  Pause, 
  Square, 
  Clock, 
  Target, 
  Settings,
  Calendar,
  Filter,
  Search,
  MoreHorizontal,
  AlertCircle,
  CheckCircle,
  XCircle
} from 'lucide-react'
import { useDashboard, useAssessments } from '@/hooks/use-dashboard'
import { AssessmentManagerProps, AssessmentData } from '@/types/dashboard'
import { cn } from '@/lib/utils'
import { formatDuration, formatRelativeTime } from '@/lib/utils'

export function AssessmentManager({ 
  className, 
  onAssessmentStart, 
  onAssessmentComplete 
}: AssessmentManagerProps) {
  const [selectedTab, setSelectedTab] = useState('active')
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [filterType, setFilterType] = useState('all')
  const [newAssessment, setNewAssessment] = useState({
    type: 'network-discovery',
    target: '',
    options: {}
  })

  const {
    startAssessment,
    stopAssessment,
    scheduleAssessment,
    fetchAssessments,
    loading
  } = useDashboard()

  const assessments = useAssessments()

  useEffect(() => {
    fetchAssessments()
  }, [fetchAssessments])

  const handleStartAssessment = async () => {
    if (!newAssessment.target.trim()) return

    try {
      const assessmentId = await startAssessment(
        newAssessment.type,
        newAssessment.target,
        newAssessment.options
      )
      
      onAssessmentStart?.({
        id: assessmentId,
        type: newAssessment.type as any,
        target: newAssessment.target,
        status: 'queued',
        startTime: new Date(),
        agentId: 'auto-assigned',
        findings: 0,
        progress: 0,
        metadata: { toolsUsed: [], coverage: {} }
      })

      // Reset form
      setNewAssessment({
        type: 'network-discovery',
        target: '',
        options: {}
      })
    } catch (error) {
      console.error('Failed to start assessment:', error)
    }
  }

  const handleStopAssessment = async (id: string) => {
    try {
      await stopAssessment(id)
    } catch (error) {
      console.error('Failed to stop assessment:', error)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-status-online" />
      case 'running':
        return <Play className="w-4 h-4 text-status-scanning" />
      case 'failed':
        return <XCircle className="w-4 h-4 text-status-offline" />
      case 'cancelled':
        return <Square className="w-4 h-4 text-muted-foreground" />
      default:
        return <Clock className="w-4 h-4 text-status-warning" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'status-online'
      case 'running':
        return 'status-scanning'
      case 'failed':
        return 'status-offline'
      case 'cancelled':
        return 'text-muted-foreground'
      default:
        return 'status-warning'
    }
  }

  const getSeverityColor = (findings: number) => {
    if (findings >= 20) return 'severity-critical'
    if (findings >= 10) return 'severity-high'
    if (findings >= 5) return 'severity-medium'
    if (findings > 0) return 'severity-low'
    return 'severity-info'
  }

  const filteredAssessments = assessments.filter(assessment => {
    const matchesSearch = assessment.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         assessment.type.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = filterStatus === 'all' || assessment.status === filterStatus
    const matchesType = filterType === 'all' || assessment.type === filterType
    
    return matchesSearch && matchesStatus && matchesType
  })

  const activeAssessments = filteredAssessments.filter(a => 
    a.status === 'running' || a.status === 'queued'
  )
  const completedAssessments = filteredAssessments.filter(a => 
    a.status === 'completed' || a.status === 'failed' || a.status === 'cancelled'
  )

  return (
    <div className={cn("space-y-6", className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Assessment Manager</h2>
          <p className="text-muted-foreground">
            Schedule and manage security assessments across your infrastructure
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <Badge variant="outline">
            {activeAssessments.length} active
          </Badge>
          <Badge variant="outline">
            {completedAssessments.length} completed
          </Badge>
        </div>
      </div>

      {/* New Assessment Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="w-5 h-5 text-cyber-500" />
            Start New Assessment
          </CardTitle>
          <CardDescription>
            Configure and launch a new security assessment
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label htmlFor="assessment-type">Assessment Type</Label>
              <Select
                value={newAssessment.type}
                onValueChange={(value) => setNewAssessment(prev => ({ ...prev, type: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="network-discovery">Network Discovery</SelectItem>
                  <SelectItem value="vulnerability-assessment">Vulnerability Assessment</SelectItem>
                  <SelectItem value="web-application">Web Application Scan</SelectItem>
                  <SelectItem value="compliance-check">Compliance Check</SelectItem>
                  <SelectItem value="threat-intelligence">Threat Intelligence</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                placeholder="192.168.1.0/24 or domain.com"
                value={newAssessment.target}
                onChange={(e) => setNewAssessment(prev => ({ ...prev, target: e.target.value }))}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Select defaultValue="medium">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end">
              <Button 
                onClick={handleStartAssessment}
                disabled={!newAssessment.target.trim() || loading}
                className="w-full"
              >
                <Play className="w-4 h-4 mr-2" />
                Start Assessment
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search assessments..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
              </SelectContent>
            </Select>

            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="network-discovery">Network Discovery</SelectItem>
                <SelectItem value="vulnerability-assessment">Vulnerability Assessment</SelectItem>
                <SelectItem value="web-application">Web Application</SelectItem>
                <SelectItem value="compliance-check">Compliance Check</SelectItem>
                <SelectItem value="threat-intelligence">Threat Intelligence</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Assessment Tabs */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="active">
            Active ({activeAssessments.length})
          </TabsTrigger>
          <TabsTrigger value="completed">
            Completed ({completedAssessments.length})
          </TabsTrigger>
          <TabsTrigger value="scheduled">
            Scheduled (0)
          </TabsTrigger>
        </TabsList>

        <TabsContent value="active" className="space-y-4">
          {activeAssessments.length === 0 ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  No active assessments
                </div>
              </CardContent>
            </Card>
          ) : (
            activeAssessments.map((assessment) => (
              <AssessmentCard
                key={assessment.id}
                assessment={assessment}
                onStop={() => handleStopAssessment(assessment.id)}
                showActions
              />
            ))
          )}
        </TabsContent>

        <TabsContent value="completed" className="space-y-4">
          {completedAssessments.length === 0 ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  No completed assessments
                </div>
              </CardContent>
            </Card>
          ) : (
            completedAssessments.map((assessment) => (
              <AssessmentCard
                key={assessment.id}
                assessment={assessment}
                showActions={false}
              />
            ))
          )}
        </TabsContent>

        <TabsContent value="scheduled" className="space-y-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-center text-muted-foreground">
                <Calendar className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No scheduled assessments</p>
                <p className="text-sm">Use the scheduler to automate recurring assessments</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

interface AssessmentCardProps {
  assessment: AssessmentData
  onStop?: () => void
  showActions?: boolean
}

function AssessmentCard({ assessment, onStop, showActions = true }: AssessmentCardProps) {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-status-online" />
      case 'running':
        return <Play className="w-4 h-4 text-status-scanning" />
      case 'failed':
        return <XCircle className="w-4 h-4 text-status-offline" />
      case 'cancelled':
        return <Square className="w-4 h-4 text-muted-foreground" />
      default:
        return <Clock className="w-4 h-4 text-status-warning" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'status-online'
      case 'running':
        return 'status-scanning'
      case 'failed':
        return 'status-offline'
      case 'cancelled':
        return 'text-muted-foreground'
      default:
        return 'status-warning'
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
    <Card className="hover:bg-muted/50 transition-colors">
      <CardContent className="pt-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4 flex-1">
            {getStatusIcon(assessment.status)}
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-medium truncate">
                  {assessment.type.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </h3>
                <Badge variant="outline" className="text-xs">
                  {assessment.agentId}
                </Badge>
              </div>
              
              <div className="text-sm text-muted-foreground mb-2">
                Target: <span className="font-mono">{assessment.target}</span>
              </div>
              
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>Started {formatRelativeTime(assessment.startTime)}</span>
                {assessment.duration && (
                  <span>Duration: {formatDuration(assessment.duration)}</span>
                )}
                {assessment.metadata.coverage.hosts && (
                  <span>Hosts: {assessment.metadata.coverage.hosts}</span>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Progress */}
            {assessment.status === 'running' && (
              <div className="flex items-center gap-2">
                <div className="w-24 bg-muted rounded-full h-2">
                  <div 
                    className="bg-cyber-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${assessment.progress}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground w-8">
                  {assessment.progress}%
                </span>
              </div>
            )}

            {/* Findings */}
            <Badge className={`${getSeverityColor(assessment.findings)}`}>
              {assessment.findings} findings
            </Badge>

            {/* Status */}
            <Badge className={`${getStatusColor(assessment.status)}`}>
              {assessment.status.toUpperCase()}
            </Badge>

            {/* Actions */}
            {showActions && (
              <div className="flex items-center gap-2">
                {assessment.status === 'running' && onStop && (
                  <Button variant="outline" size="sm" onClick={onStop}>
                    <Square className="w-4 h-4" />
                  </Button>
                )}
                
                <Button variant="ghost" size="sm">
                  <MoreHorizontal className="w-4 h-4" />
                </Button>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}