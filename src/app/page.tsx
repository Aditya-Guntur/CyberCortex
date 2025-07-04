import { Suspense } from 'react'
import { DashboardHeader } from '@/components/dashboard/dashboard-header'
import { SecurityOverview } from '@/components/dashboard/security-overview'
import { ThreatIntelligence } from '@/components/dashboard/threat-intelligence'
import { AgentStatus } from '@/components/dashboard/agent-status'
import { RecentScans } from '@/components/dashboard/recent-scans'
import { ComplianceStatus } from '@/components/dashboard/compliance-status'
import { RealTimeAlerts } from '@/components/dashboard/real-time-alerts'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      
      <main className="container mx-auto px-4 py-8 space-y-8">
        {/* Hero Section */}
        <div className="text-center space-y-4 mb-12">
          <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-cyber-400 to-cyber-600 bg-clip-text text-transparent">
            CyberCortex
          </h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Autonomous Security Validation Platform powered by Multi-Agent AI
          </p>
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <div className="w-2 h-2 bg-status-online rounded-full animate-pulse"></div>
            <span>System Operational • 6 Agents Active • Real-time Monitoring</span>
          </div>
        </div>

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Primary Metrics */}
          <div className="lg:col-span-2 space-y-8">
            <Suspense fallback={<LoadingSpinner />}>
              <SecurityOverview />
            </Suspense>
            
            <Suspense fallback={<LoadingSpinner />}>
              <ThreatIntelligence />
            </Suspense>
            
            <Suspense fallback={<LoadingSpinner />}>
              <RecentScans />
            </Suspense>
          </div>

          {/* Right Column - Status & Alerts */}
          <div className="space-y-8">
            <Suspense fallback={<LoadingSpinner />}>
              <RealTimeAlerts />
            </Suspense>
            
            <Suspense fallback={<LoadingSpinner />}>
              <AgentStatus />
            </Suspense>
            
            <Suspense fallback={<LoadingSpinner />}>
              <ComplianceStatus />
            </Suspense>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center text-sm text-muted-foreground pt-8 border-t">
          <p>
            Built for Raise Your Hack 2025 • Blackbox.ai Track • 
            <span className="text-cyber-500 font-medium"> Securing the digital world, one agent at a time</span>
          </p>
        </div>
      </main>
    </div>
  )
}