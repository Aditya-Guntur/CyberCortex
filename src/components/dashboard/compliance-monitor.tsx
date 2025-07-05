"use client"

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Clock, 
  FileText,
  Download,
  Calendar,
  BarChart,
  ArrowUpDown,
  ChevronDown,
  ChevronUp,
  ExternalLink
} from 'lucide-react'
import { useDashboard, useCompliance } from '@/hooks/use-dashboard'
import { ComplianceMonitorProps, ComplianceData } from '@/types/dashboard'
import { cn, formatRelativeTime } from '@/lib/utils'

export function ComplianceMonitor({ 
  className, 
  frameworks,
  onComplianceUpdate 
}: ComplianceMonitorProps) {
  const [selectedTab, setSelectedTab] = useState('overview')
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [expandedControls, setExpandedControls] = useState<Record<string, boolean>>({})

  const {
    fetchCompliance,
    loading
  } = useDashboard()

  const complianceData = useCompliance()

  useEffect(() => {
    fetchCompliance()
  }, [fetchCompliance])

  useEffect(() => {
    if (complianceData.length > 0 && !selectedFramework) {
      setSelectedFramework(complianceData[0].framework)
    }
  }, [complianceData, selectedFramework])

  const toggleControlExpanded = (controlId: string) => {
    setExpandedControls(prev => ({
      ...prev,
      [controlId]: !prev[controlId]
    }))
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="w-4 h-4 text-status-online" />
      case 'partial':
        return <AlertTriangle className="w-4 h-4 text-status-warning" />
      case 'non-compliant':
        return <XCircle className="w-4 h-4 text-status-offline" />
      default:
        return <Clock className="w-4 h-4 text-muted-foreground" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'status-online'
      case 'partial': return 'status-warning'
      case 'non-compliant': return 'status-offline'
      default: return 'text-muted-foreground'
    }
  }

  const getControlStatusIcon = (status: string) => {
    switch (status) {
      case 'met':
        return <CheckCircle className="w-4 h-4 text-status-online" />
      case 'partial':
        return <AlertTriangle className="w-4 h-4 text-status-warning" />
      case 'not-met':
        return <XCircle className="w-4 h-4 text-status-offline" />
      default:
        return <Clock className="w-4 h-4 text-muted-foreground" />
    }
  }

  const getControlStatusColor = (status: string) => {
    switch (status) {
      case 'met': return 'status-online'
      case 'partial': return 'status-warning'
      case 'not-met': return 'status-offline'
      default: return 'text-muted-foreground'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return 'severity-info'
    }
  }

  const selectedFrameworkData = complianceData.find(f => f.framework === selectedFramework)

  return (
    <div className={cn("space-y-6", className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Compliance Monitor</h2>
          <p className="text-muted-foreground">
            Track compliance status across regulatory frameworks
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <FileText className="w-4 h-4 mr-2" />
            Reports
          </Button>
          <Button variant="outline" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Framework Selector */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row gap-4 items-center">
            <div className="text-sm font-medium">Framework:</div>
            <Select 
              value={selectedFramework || ''} 
              onValueChange={setSelectedFramework}
            >
              <SelectTrigger className="w-60">
                <SelectValue placeholder="Select framework" />
              </SelectTrigger>
              <SelectContent>
                {complianceData.map(framework => (
                  <SelectItem key={framework.framework} value={framework.framework}>
                    {framework.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {selectedFrameworkData && (
              <div className="flex items-center gap-4 ml-auto">
                <div className="flex items-center gap-2">
                  <div className="text-xs text-muted-foreground">Status:</div>
                  <Badge className={getStatusColor(selectedFrameworkData.status)}>
                    {selectedFrameworkData.status.toUpperCase()}
                  </Badge>
                </div>
                
                <div className="flex items-center gap-2">
                  <div className="text-xs text-muted-foreground">Score:</div>
                  <div className="text-lg font-bold">{selectedFrameworkData.score}%</div>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Compliance Tabs */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overview">
            Overview
          </TabsTrigger>
          <TabsTrigger value="controls">
            Controls
          </TabsTrigger>
          <TabsTrigger value="history">
            History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {!selectedFrameworkData ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No framework selected</p>
                  <p className="text-sm">Select a compliance framework to view details</p>
                </div>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Framework Summary */}
              <Card>
                <CardHeader>
                  <CardTitle>{selectedFrameworkData.name}</CardTitle>
                  <CardDescription>
                    Framework overview and compliance status
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Score */}
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Compliance Score</h3>
                      <div className="flex items-center gap-4">
                        <div className="w-16 h-16 rounded-full flex items-center justify-center text-lg font-bold border-4 border-current text-foreground">
                          {selectedFrameworkData.score}%
                        </div>
                        <div>
                          <Badge className={getStatusColor(selectedFrameworkData.status)}>
                            {selectedFrameworkData.status.toUpperCase()}
                          </Badge>
                          <div className="text-xs text-muted-foreground mt-1">
                            Last assessed {formatRelativeTime(selectedFrameworkData.lastAssessment)}
                          </div>
                        </div>
                      </div>
                      <div className="w-full bg-muted rounded-full h-2">
                        <div 
                          className="bg-cyber-500 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${selectedFrameworkData.score}%` }}
                        />
                      </div>
                    </div>

                    {/* Control Stats */}
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Control Status</h3>
                      <div className="grid grid-cols-3 gap-2 text-center">
                        <div className="bg-muted/50 p-2 rounded">
                          <div className="text-lg font-bold text-status-online">
                            {selectedFrameworkData.controls.passed}
                          </div>
                          <div className="text-xs text-muted-foreground">Passed</div>
                        </div>
                        <div className="bg-muted/50 p-2 rounded">
                          <div className="text-lg font-bold text-status-offline">
                            {selectedFrameworkData.controls.failed}
                          </div>
                          <div className="text-xs text-muted-foreground">Failed</div>
                        </div>
                        <div className="bg-muted/50 p-2 rounded">
                          <div className="text-lg font-bold">
                            {selectedFrameworkData.controls.total}
                          </div>
                          <div className="text-xs text-muted-foreground">Total</div>
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Next assessment scheduled for {formatRelativeTime(selectedFrameworkData.nextAssessment)}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Actions</h3>
                      <div className="space-y-2">
                        <Button variant="outline" size="sm" className="w-full justify-start">
                          <Shield className="w-4 h-4 mr-2" />
                          Run Assessment
                        </Button>
                        <Button variant="outline" size="sm" className="w-full justify-start">
                          <FileText className="w-4 h-4 mr-2" />
                          Generate Report
                        </Button>
                        <Button variant="outline" size="sm" className="w-full justify-start">
                          <BarChart className="w-4 h-4 mr-2" />
                          View Trends
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Compliance Chart */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart className="w-5 h-5 text-cyber-500" />
                    Compliance Trend
                  </CardTitle>
                  <CardDescription>
                    90-day compliance score history
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 flex items-end justify-between px-4">
                    {/* Mock trend data - replace with actual chart component */}
                    {[65, 68, 72, 75, 78, 82, 85, 87, 84, 88, 90, selectedFrameworkData.score].map((value, index) => (
                      <div key={index} className="flex flex-col items-center gap-2">
                        <div
                          className="bg-cyber-500 rounded-t w-6 transition-all duration-300 hover:bg-cyber-400"
                          style={{ height: `${(value / 100) * 200}px` }}
                          title={`Month ${index + 1}: ${value}%`}
                        />
                        {index % 3 === 0 && (
                          <span className="text-xs text-muted-foreground">
                            {index === 0 ? '90d' : index === 3 ? '60d' : index === 6 ? '30d' : index === 9 ? '15d' : 'Now'}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        <TabsContent value="controls" className="space-y-4">
          {!selectedFrameworkData ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No framework selected</p>
                  <p className="text-sm">Select a compliance framework to view controls</p>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {/* Control Filters */}
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-col md:flex-row gap-4">
                    <Select defaultValue="all">
                      <SelectTrigger className="w-40">
                        <SelectValue placeholder="Status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Status</SelectItem>
                        <SelectItem value="met">Met</SelectItem>
                        <SelectItem value="not-met">Not Met</SelectItem>
                        <SelectItem value="partial">Partial</SelectItem>
                        <SelectItem value="not-applicable">Not Applicable</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select defaultValue="all">
                      <SelectTrigger className="w-40">
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Severities</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>

                    <div className="ml-auto">
                      <Button variant="outline" size="sm">
                        <Download className="w-4 h-4 mr-2" />
                        Export Controls
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Controls List */}
              <div className="space-y-2">
                {selectedFrameworkData.findings.map((control) => (
                  <Card 
                    key={control.controlId}
                    className={cn(
                      "hover:bg-muted/50 transition-colors overflow-hidden",
                      expandedControls[control.controlId] && "ring-1 ring-cyber-500/20"
                    )}
                  >
                    <div 
                      className="p-4 cursor-pointer"
                      onClick={() => toggleControlExpanded(control.controlId)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          {getControlStatusIcon(control.status)}
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="font-medium text-sm">
                                {control.controlId}: {control.title}
                              </h3>
                              <Badge className={getSeverityColor(control.severity)}>
                                {control.severity}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground line-clamp-1">
                              {control.description}
                            </p>
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-4">
                          <Badge className={getControlStatusColor(control.status)}>
                            {control.status.replace('-', ' ').toUpperCase()}
                          </Badge>
                          
                          {expandedControls[control.controlId] ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Expanded Control Details */}
                    {expandedControls[control.controlId] && (
                      <div className="px-4 pb-4 pt-0 border-t">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
                          <div className="space-y-4">
                            <div>
                              <h4 className="text-sm font-medium mb-2">Description</h4>
                              <p className="text-sm text-muted-foreground">
                                {control.description}
                              </p>
                            </div>
                            
                            <div>
                              <h4 className="text-sm font-medium mb-2">Status Details</h4>
                              <div className="text-sm text-muted-foreground">
                                {control.status === 'met' ? (
                                  <p>This control has been fully implemented and verified.</p>
                                ) : control.status === 'partial' ? (
                                  <p>This control has been partially implemented but requires additional work.</p>
                                ) : control.status === 'not-met' ? (
                                  <p>This control has not been implemented or has failed verification.</p>
                                ) : (
                                  <p>This control is not applicable to the current environment.</p>
                                )}
                              </div>
                            </div>
                          </div>
                          
                          <div className="space-y-4">
                            <div>
                              <h4 className="text-sm font-medium mb-2">Actions</h4>
                              <div className="space-y-2">
                                <Button variant="outline" size="sm" className="w-full justify-start">
                                  <Shield className="w-4 h-4 mr-2" />
                                  Reassess Control
                                </Button>
                                
                                <Button variant="outline" size="sm" className="w-full justify-start">
                                  <FileText className="w-4 h-4 mr-2" />
                                  View Evidence
                                </Button>
                                
                                <Button variant="outline" size="sm" className="w-full justify-start">
                                  <ExternalLink className="w-4 h-4 mr-2" />
                                  View Framework Documentation
                                </Button>
                              </div>
                            </div>
                            
                            <div>
                              <h4 className="text-sm font-medium mb-2">Metadata</h4>
                              <div className="text-xs text-muted-foreground space-y-1">
                                <div className="flex items-center gap-1">
                                  <Calendar className="w-3 h-3" />
                                  <span>Last assessed: {formatRelativeTime(selectedFrameworkData.lastAssessment)}</span>
                                </div>
                                <div className="flex items-center gap-1">
                                  <Shield className="w-3 h-3" />
                                  <span>Framework: {selectedFrameworkData.name}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </Card>
                ))}
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-center text-muted-foreground">
                <Clock className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>Compliance assessment history</p>
                <p className="text-sm">Historical compliance data will be displayed here</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}