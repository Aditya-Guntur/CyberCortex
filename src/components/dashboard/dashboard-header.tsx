"use client"

import { Bell, Settings, User, Shield, Activity, Zap } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useRouter } from 'next/navigation'

export function DashboardHeader({ setTab }: { setTab?: (tab: string) => void }) {
  const router = useRouter();
  return (
    <header className="border-b bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          {/* Logo and Navigation */}
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyber-500" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-status-online rounded-full animate-pulse" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground">CyberCortex</h1>
                <p className="text-xs text-muted-foreground">Security Command Center</p>
              </div>
            </div>
            
            <nav className="hidden md:flex items-center space-x-6">
              <Button variant="ghost" size="sm" className="text-cyber-500" onClick={() => setTab && setTab('overview')}>
                <Activity className="w-4 h-4 mr-2" />
                Dashboard
              </Button>
              <Button variant="ghost" size="sm" onClick={() => router.push('/simulation')}>
                Simulation
              </Button>
            </nav>
          </div>

          {/* Status and Actions */}
          <div className="flex items-center space-x-4">
            {/* System Status */}
            <div className="hidden lg:flex items-center space-x-2 text-sm">
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-status-online rounded-full" />
                <span className="text-muted-foreground">All Systems</span>
              </div>
              <Badge variant="outline" className="text-xs">
                <Zap className="w-3 h-3 mr-1" />
                6 Agents Active
              </Badge>
            </div>

            {/* Notifications */}
            {/* <Button variant="ghost" size="sm" className="relative">
              <Bell className="w-4 h-4" />
              <Badge className="absolute -top-1 -right-1 w-5 h-5 text-xs bg-security-high">
                3
              </Badge>
            </Button> */}

            {/* Settings */}
            {/* <Button variant="ghost" size="sm">
              <Settings className="w-4 h-4" />
            </Button> */}

            {/* User Menu */}
            {/* <Button variant="ghost" size="sm" className="flex items-center space-x-2" onClick={() => router.push('/simulation')}>
              <User className="w-4 h-4" />
              <span className="hidden md:inline text-sm">Admin</span>
            </Button> */}
          </div>
        </div>
      </div>
    </header>
  )
}