"use client"

import { Suspense } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DashboardHeader } from '@/components/dashboard/dashboard-header'
import { SecurityDashboard } from '@/components/dashboard/security-dashboard'
import { AssessmentManager } from '@/components/dashboard/assessment-manager'
import { VulnerabilityTracker } from '@/components/dashboard/vulnerability-tracker'
import { ComplianceMonitor } from '@/components/dashboard/compliance-monitor'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import React, { useState } from 'react'

export default function DashboardPage() {
  const [tab, setTab] = useState('overview')
  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader setTab={setTab} />
      
      <main className="container mx-auto px-4 py-8">
        <Tabs value={tab} onValueChange={setTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="assessments">Assessments</TabsTrigger>
            <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-6">
            <Suspense fallback={<LoadingSpinner />}>
              <SecurityDashboard />
            </Suspense>
          </TabsContent>
          
          <TabsContent value="assessments">
            <Suspense fallback={<LoadingSpinner />}>
              <AssessmentManager />
            </Suspense>
          </TabsContent>
          
          <TabsContent value="vulnerabilities">
            <Suspense fallback={<LoadingSpinner />}>
              <VulnerabilityTracker />
            </Suspense>
          </TabsContent>
          
          <TabsContent value="compliance">
            <Suspense fallback={<LoadingSpinner />}>
              <ComplianceMonitor />
            </Suspense>
          </TabsContent>
        </Tabs>
      </main>
      
      <footer className="border-t py-6">
        <div className="container mx-auto px-4">
          <div className="text-center text-sm text-muted-foreground">
            <p>
              CyberCortex Platform • Autonomous Security Validation • 
              <span className="text-cyber-500 font-medium"> Securing the digital world, one agent at a time</span>
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}