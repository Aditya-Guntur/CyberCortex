// Core types for CyberCortex platform

export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'analyst' | 'viewer'
  avatar?: string
  lastLogin?: Date
  isActive: boolean
  permissions: Permission[]
}

export interface Permission {
  id: string
  name: string
  description: string
  resource: string
  action: string
}

export interface Organization {
  id: string
  name: string
  domain: string
  industry: string
  size: 'startup' | 'small' | 'medium' | 'large' | 'enterprise'
  complianceFrameworks: ComplianceFramework[]
  settings: OrganizationSettings
}

export interface OrganizationSettings {
  scanFrequency: 'hourly' | 'daily' | 'weekly' | 'monthly'
  alertThreshold: 'low' | 'medium' | 'high' | 'critical'
  autoRemediation: boolean
  dataRetention: number // days
  allowedIpRanges: string[]
}

export interface ComplianceFramework {
  id: string
  name: string
  version: string
  requirements: ComplianceRequirement[]
  status: 'compliant' | 'non-compliant' | 'partial' | 'unknown'
  lastAssessment?: Date
}

export interface ComplianceRequirement {
  id: string
  title: string
  description: string
  category: string
  severity: Severity
  status: 'met' | 'not-met' | 'partial' | 'not-applicable'
  evidence?: string[]
  remediation?: string
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SecurityScan {
  id: string
  type: ScanType
  target: string
  status: ScanStatus
  startTime: Date
  endTime?: Date
  duration?: number
  agentId: string
  findings: SecurityFinding[]
  metadata: ScanMetadata
}

export type ScanType = 
  | 'network-discovery'
  | 'vulnerability-assessment'
  | 'web-application'
  | 'compliance-check'
  | 'threat-intelligence'
  | 'penetration-test'

export type ScanStatus = 
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'paused'

export interface ScanMetadata {
  toolsUsed: string[]
  parameters: Record<string, any>
  resourcesConsumed: {
    cpu: number
    memory: number
    network: number
  }
  coverage: {
    hosts: number
    ports: number
    services: number
  }
}

export interface SecurityFinding {
  id: string
  title: string
  description: string
  severity: Severity
  category: FindingCategory
  cve?: string
  cvss?: number
  affected: {
    host: string
    port?: number
    service?: string
    url?: string
  }
  evidence: Evidence[]
  remediation: Remediation
  status: FindingStatus
  discoveredAt: Date
  lastSeen: Date
  falsePositive: boolean
  tags: string[]
}

export type FindingCategory = 
  | 'vulnerability'
  | 'misconfiguration'
  | 'weak-credential'
  | 'information-disclosure'
  | 'injection'
  | 'authentication'
  | 'authorization'
  | 'cryptography'
  | 'network'
  | 'compliance'

export type FindingStatus = 
  | 'open'
  | 'in-progress'
  | 'resolved'
  | 'accepted-risk'
  | 'false-positive'

export interface Evidence {
  type: 'screenshot' | 'log' | 'packet-capture' | 'code' | 'configuration'
  content: string
  metadata?: Record<string, any>
}

export interface Remediation {
  priority: 'immediate' | 'high' | 'medium' | 'low'
  effort: 'minimal' | 'moderate' | 'significant' | 'extensive'
  steps: string[]
  resources: string[]
  estimatedTime: number // hours
  automatable: boolean
}

export interface Agent {
  id: string
  name: string
  type: AgentType
  status: AgentStatus
  version: string
  capabilities: AgentCapability[]
  configuration: AgentConfiguration
  metrics: AgentMetrics
  lastHeartbeat: Date
  assignedTasks: Task[]
}

export type AgentType = 
  | 'reconnaissance'
  | 'vulnerability-scanner'
  | 'threat-intelligence'
  | 'compliance-checker'
  | 'incident-responder'
  | 'report-generator'
  | 'coordinator'

export type AgentStatus = 
  | 'online'
  | 'offline'
  | 'busy'
  | 'error'
  | 'maintenance'
  | 'initializing'

export interface AgentCapability {
  name: string
  version: string
  description: string
  parameters: Record<string, any>
}

export interface AgentConfiguration {
  maxConcurrentTasks: number
  timeout: number
  retryAttempts: number
  resources: {
    cpu: number
    memory: number
    storage: number
  }
  tools: string[]
  apiKeys: Record<string, string>
}

export interface AgentMetrics {
  tasksCompleted: number
  tasksSuccessful: number
  tasksFailed: number
  averageExecutionTime: number
  uptime: number
  resourceUtilization: {
    cpu: number
    memory: number
    storage: number
  }
}

export interface Task {
  id: string
  type: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  parameters: Record<string, any>
  createdAt: Date
  startedAt?: Date
  completedAt?: Date
  result?: any
  error?: string
  agentId?: string
}

export interface ThreatIntelligence {
  id: string
  type: ThreatType
  source: string
  confidence: number // 0-100
  severity: Severity
  title: string
  description: string
  indicators: IOC[]
  ttps: TTP[]
  attribution?: Attribution
  publishedAt: Date
  expiresAt?: Date
  tags: string[]
}

export type ThreatType = 
  | 'malware'
  | 'phishing'
  | 'apt'
  | 'vulnerability'
  | 'campaign'
  | 'tool'
  | 'technique'

export interface IOC {
  type: IOCType
  value: string
  description?: string
  firstSeen: Date
  lastSeen: Date
  confidence: number
}

export type IOCType = 
  | 'ip'
  | 'domain'
  | 'url'
  | 'hash'
  | 'email'
  | 'file'
  | 'registry'
  | 'mutex'

export interface TTP {
  id: string
  name: string
  description: string
  tactic: string
  technique: string
  subtechnique?: string
  mitreId?: string
}

export interface Attribution {
  actor: string
  group?: string
  country?: string
  motivation: string[]
  confidence: number
}

export interface Alert {
  id: string
  title: string
  description: string
  severity: Severity
  category: AlertCategory
  source: string
  timestamp: Date
  status: AlertStatus
  assignee?: string
  relatedFindings: string[]
  actions: AlertAction[]
  metadata: Record<string, any>
}

export type AlertCategory = 
  | 'security-incident'
  | 'compliance-violation'
  | 'system-anomaly'
  | 'threat-detected'
  | 'scan-completed'
  | 'agent-status'

export type AlertStatus = 
  | 'new'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'false-positive'

export interface AlertAction {
  type: 'email' | 'slack' | 'webhook' | 'ticket' | 'auto-remediate'
  target: string
  parameters: Record<string, any>
  executed: boolean
  executedAt?: Date
  result?: string
}

export interface Dashboard {
  id: string
  name: string
  description: string
  widgets: Widget[]
  layout: LayoutConfig
  filters: FilterConfig
  refreshInterval: number
  isPublic: boolean
  owner: string
  sharedWith: string[]
}

export interface Widget {
  id: string
  type: WidgetType
  title: string
  configuration: WidgetConfiguration
  position: {
    x: number
    y: number
    width: number
    height: number
  }
  dataSource: DataSource
}

export type WidgetType = 
  | 'metric'
  | 'chart'
  | 'table'
  | 'map'
  | 'gauge'
  | 'timeline'
  | 'heatmap'
  | 'treemap'

export interface WidgetConfiguration {
  chartType?: 'line' | 'bar' | 'pie' | 'area' | 'scatter'
  timeRange?: string
  aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count'
  groupBy?: string[]
  filters?: Record<string, any>
  colors?: string[]
  showLegend?: boolean
  showGrid?: boolean
}

export interface DataSource {
  type: 'api' | 'database' | 'file' | 'stream'
  endpoint: string
  query?: string
  parameters?: Record<string, any>
  refreshInterval?: number
}

export interface LayoutConfig {
  columns: number
  rowHeight: number
  margin: [number, number]
  containerPadding: [number, number]
}

export interface FilterConfig {
  timeRange: {
    start: Date
    end: Date
  }
  severity: Severity[]
  categories: string[]
  agents: string[]
  custom: Record<string, any>
}

export interface APIResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
  pagination?: {
    page: number
    limit: number
    total: number
    totalPages: number
  }
}

export interface WebSocketMessage {
  type: string
  payload: any
  timestamp: Date
  id: string
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy'
  components: ComponentHealth[]
  uptime: number
  version: string
  lastCheck: Date
}

export interface ComponentHealth {
  name: string
  status: 'healthy' | 'degraded' | 'unhealthy'
  responseTime?: number
  errorRate?: number
  lastCheck: Date
  details?: Record<string, any>
}