// Dashboard-specific types for CyberCortex platform

export interface SecurityMetrics {
  overallScore: number
  criticalIssues: number
  resolvedIssues: number
  activeScans: number
  trend: string
  lastUpdated: Date
}

export interface ThreatData {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  source: string
  timestamp: Date
  iocs: string[]
  description?: string
  mitreId?: string
  killChainPhase?: string
}

export interface VulnerabilityData {
  id: string
  cveId?: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvssScore?: number
  affectedSystems: string[]
  discoveryDate: Date
  status: 'open' | 'in-progress' | 'resolved' | 'accepted-risk' | 'false-positive'
  remediation?: {
    priority: 'immediate' | 'high' | 'medium' | 'low'
    effort: 'minimal' | 'moderate' | 'significant' | 'extensive'
    steps: string[]
    estimatedTime: number
  }
  exploitAvailable: boolean
  patchAvailable: boolean
}

export interface AssessmentData {
  id: string
  type: 'network-discovery' | 'vulnerability-assessment' | 'web-application' | 'compliance-check' | 'threat-intelligence'
  target: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  startTime: Date
  endTime?: Date
  duration?: number
  agentId: string
  findings: number
  progress: number
  metadata: {
    toolsUsed: string[]
    coverage: {
      hosts?: number
      ports?: number
      services?: number
    }
  }
}

export interface ComplianceData {
  framework: string
  name: string
  status: 'compliant' | 'non-compliant' | 'partial' | 'unknown'
  score: number
  controls: {
    total: number
    passed: number
    failed: number
  }
  lastAssessment: Date
  nextAssessment: Date
  findings: Array<{
    controlId: string
    title: string
    status: 'met' | 'not-met' | 'partial' | 'not-applicable'
    severity: 'critical' | 'high' | 'medium' | 'low'
    description: string
  }>
}

export interface AgentData {
  id: string
  name: string
  type: 'reconnaissance' | 'vulnerability-scanner' | 'threat-intelligence' | 'compliance-checker' | 'incident-responder' | 'report-generator'
  status: 'online' | 'offline' | 'busy' | 'error' | 'maintenance'
  uptime: string
  tasksCompleted: number
  currentTask?: string
  capabilities: string[]
  performance: {
    successRate: number
    averageExecutionTime: number
    resourceUtilization: {
      cpu: number
      memory: number
    }
  }
  lastHeartbeat: Date
}

export interface AlertData {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: 'security-incident' | 'compliance-violation' | 'system-anomaly' | 'threat-detected' | 'scan-completed' | 'agent-status'
  source: string
  timestamp: Date
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false-positive'
  assignee?: string
  relatedFindings: string[]
  actions: Array<{
    type: 'email' | 'slack' | 'webhook' | 'ticket' | 'auto-remediate'
    executed: boolean
    executedAt?: Date
  }>
}

export interface DashboardFilters {
  timeRange: {
    start: Date
    end: Date
    preset?: '1h' | '24h' | '7d' | '30d' | '90d' | 'custom'
  }
  severity: Array<'critical' | 'high' | 'medium' | 'low' | 'info'>
  categories: string[]
  agents: string[]
  status: string[]
}

export interface WebSocketMessage {
  type: 'security_event' | 'assessment_update' | 'agent_status' | 'alert' | 'metrics_update'
  payload: any
  timestamp: Date
  id: string
}

export interface VoiceCommand {
  command: string
  confidence: number
  intent: 'scan' | 'status' | 'report' | 'alert' | 'navigate'
  parameters: Record<string, any>
  timestamp: Date
}

export interface ChartData {
  labels: string[]
  datasets: Array<{
    label: string
    data: number[]
    backgroundColor?: string | string[]
    borderColor?: string
    borderWidth?: number
    fill?: boolean
  }>
}

export interface MetricCard {
  title: string
  value: string | number
  change?: {
    value: number
    direction: 'up' | 'down' | 'stable'
    period: string
  }
  status?: 'good' | 'warning' | 'critical'
  icon?: string
}

export interface TableColumn<T = any> {
  key: keyof T
  title: string
  sortable?: boolean
  filterable?: boolean
  render?: (value: any, record: T) => React.ReactNode
  width?: string | number
}

export interface TableProps<T = any> {
  data: T[]
  columns: TableColumn<T>[]
  loading?: boolean
  pagination?: {
    current: number
    pageSize: number
    total: number
    onChange: (page: number, pageSize: number) => void
  }
  selection?: {
    selectedRowKeys: string[]
    onChange: (selectedRowKeys: string[], selectedRows: T[]) => void
  }
  filters?: Record<string, any>
  onFiltersChange?: (filters: Record<string, any>) => void
}

export interface DashboardState {
  // Data
  securityMetrics: SecurityMetrics | null
  threats: ThreatData[]
  vulnerabilities: VulnerabilityData[]
  assessments: AssessmentData[]
  compliance: ComplianceData[]
  agents: AgentData[]
  alerts: AlertData[]
  
  // UI State
  loading: boolean
  error: string | null
  filters: DashboardFilters
  selectedTimeRange: string
  darkMode: boolean
  sidebarCollapsed: boolean
  
  // Real-time
  connected: boolean
  lastUpdate: Date | null
  
  // Voice
  voiceEnabled: boolean
  listening: boolean
  lastCommand: VoiceCommand | null
}

export interface DashboardActions {
  // Data actions
  fetchSecurityMetrics: () => Promise<void>
  fetchThreats: (filters?: Partial<DashboardFilters>) => Promise<void>
  fetchVulnerabilities: (filters?: Partial<DashboardFilters>) => Promise<void>
  fetchAssessments: (filters?: Partial<DashboardFilters>) => Promise<void>
  fetchCompliance: () => Promise<void>
  fetchAgents: () => Promise<void>
  fetchAlerts: (filters?: Partial<DashboardFilters>) => Promise<void>
  
  // Assessment actions
  startAssessment: (type: string, target: string, options?: any) => Promise<string>
  stopAssessment: (id: string) => Promise<void>
  scheduleAssessment: (schedule: any) => Promise<void>
  
  // Vulnerability actions
  updateVulnerabilityStatus: (id: string, status: string) => Promise<void>
  assignVulnerability: (id: string, assignee: string) => Promise<void>
  
  // Alert actions
  acknowledgeAlert: (id: string) => Promise<void>
  resolveAlert: (id: string) => Promise<void>
  
  // UI actions
  setFilters: (filters: Partial<DashboardFilters>) => void
  setTimeRange: (range: string) => void
  toggleDarkMode: () => void
  toggleSidebar: () => void
  
  // Voice actions
  enableVoice: () => void
  disableVoice: () => void
  processVoiceCommand: (command: string) => Promise<void>
  
  // WebSocket actions
  connect: () => void
  disconnect: () => void
  handleMessage: (message: WebSocketMessage) => void
}

export interface DashboardContextType extends DashboardState, DashboardActions {}

// Component Props Types
export interface SecurityDashboardProps {
  className?: string
  refreshInterval?: number
}

export interface AssessmentManagerProps {
  className?: string
  onAssessmentStart?: (assessment: AssessmentData) => void
  onAssessmentComplete?: (assessment: AssessmentData) => void
}

export interface VulnerabilityTrackerProps {
  className?: string
  showResolved?: boolean
  onVulnerabilityUpdate?: (vulnerability: VulnerabilityData) => void
}

export interface ComplianceMonitorProps {
  className?: string
  frameworks?: string[]
  onComplianceUpdate?: (compliance: ComplianceData) => void
}

export interface MetricCardProps extends MetricCard {
  className?: string
  loading?: boolean
  onClick?: () => void
}

export interface ChartProps {
  data: ChartData
  type: 'line' | 'bar' | 'pie' | 'doughnut' | 'area'
  height?: number
  options?: any
  className?: string
}

export interface DataTableProps<T = any> extends TableProps<T> {
  className?: string
  title?: string
  actions?: React.ReactNode
  exportable?: boolean
  searchable?: boolean
}

// API Response Types
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
  timestamp: Date
}

export interface WebSocketConfig {
  url: string
  reconnectInterval: number
  maxReconnectAttempts: number
  heartbeatInterval: number
}

export interface VoiceConfig {
  language: string
  continuous: boolean
  interimResults: boolean
  maxAlternatives: number
  serviceType: 'browser' | 'groq'
}

export interface ThemeConfig {
  primary: string
  secondary: string
  accent: string
  background: string
  surface: string
  text: string
  border: string
}

export interface NotificationConfig {
  position: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left'
  duration: number
  maxNotifications: number
  showProgress: boolean
}