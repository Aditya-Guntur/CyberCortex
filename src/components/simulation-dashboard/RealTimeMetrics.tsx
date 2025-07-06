import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  BarChart, 
  PieChart, 
  Pie, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  Cell
} from 'recharts';
import { BarChart3, PieChart as PieChartIcon, AlertTriangle, Shield } from 'lucide-react';
import { useSimulationState } from '@/hooks/useSimulationState';

interface RealTimeMetricsProps {
  className?: string;
}

export function RealTimeMetrics({ className }: RealTimeMetricsProps) {
  const { simulation, vulnerabilities } = useSimulationState();

  // Prepare vulnerability severity data for pie chart
  const vulnerabilitySeverityData = [
    { name: 'Critical', value: vulnerabilities.filter(v => v.severity === 'critical').length, color: '#dc2626' },
    { name: 'High', value: vulnerabilities.filter(v => v.severity === 'high').length, color: '#ea580c' },
    { name: 'Medium', value: vulnerabilities.filter(v => v.severity === 'medium').length, color: '#d97706' },
    { name: 'Low', value: vulnerabilities.filter(v => v.severity === 'low').length, color: '#65a30d' }
  ].filter(item => item.value > 0);

  // Prepare vulnerability type data for bar chart
  const getVulnerabilityTypes = () => {
    const typeCounts: Record<string, number> = {};
    
    vulnerabilities.forEach(vuln => {
      const type = vuln.type.replace(/_/g, ' ');
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    return Object.entries(typeCounts).map(([name, value]) => ({ name, value }));
  };

  const vulnerabilityTypeData = getVulnerabilityTypes();

  // Prepare host vulnerability data
  const getHostVulnerabilityData = () => {
    const hostCounts: Record<string, number> = {};
    
    vulnerabilities.forEach(vuln => {
      const host = vuln.host;
      hostCounts[host] = (hostCounts[host] || 0) + 1;
    });
    
    return Object.entries(hostCounts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5); // Top 5 hosts
  };

  const hostVulnerabilityData = getHostVulnerabilityData();

  // Calculate security metrics
  const calculateSecurityScore = () => {
    if (vulnerabilities.length === 0) return 100;
    
    // Weight vulnerabilities by severity
    const weights = {
      critical: 10,
      high: 5,
      medium: 2,
      low: 1
    };
    
    const totalWeight = vulnerabilities.reduce((sum, vuln) => {
      return sum + (weights[vuln.severity as keyof typeof weights] || 1);
    }, 0);
    
    // Base score of 100, subtract weighted vulnerabilities
    const baseScore = 100;
    const maxPenalty = 80; // Don't go below 20
    
    // Calculate penalty based on number and severity of vulnerabilities
    const penalty = Math.min(maxPenalty, totalWeight);
    
    return Math.max(baseScore - penalty, 20);
  };

  const securityScore = calculateSecurityScore();

  // Get security score color
  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-status-online';
    if (score >= 70) return 'text-status-warning';
    if (score >= 50) return 'text-status-scanning';
    return 'text-status-offline';
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-cyber-500" />
          Security Metrics
        </CardTitle>
        <CardDescription>
          Real-time security assessment metrics and analytics
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Security Score */}
          <div className="flex flex-col items-center justify-center p-6 border rounded-md">
            <div className={`text-4xl font-bold ${getScoreColor(securityScore)}`}>
              {securityScore}
            </div>
            <div className="text-sm font-medium mt-2">Security Score</div>
            <div className="text-xs text-muted-foreground mt-1">
              Based on {vulnerabilities.length} vulnerabilities
            </div>
            
            {/* Score gauge */}
            <div className="w-full mt-4">
              <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                <div 
                  className="h-full rounded-full transition-all duration-500"
                  style={{ 
                    width: `${securityScore}%`,
                    background: securityScore >= 90 
                      ? '#10b981' 
                      : securityScore >= 70 
                        ? '#f59e0b' 
                        : securityScore >= 50 
                          ? '#8b5cf6' 
                          : '#ef4444'
                  }}
                />
              </div>
              <div className="flex justify-between text-xs text-muted-foreground mt-1">
                <span>Critical</span>
                <span>Secure</span>
              </div>
            </div>
          </div>

          {/* Vulnerability Severity Distribution */}
          <div className="border rounded-md p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium">Severity Distribution</h3>
              <PieChartIcon className="w-4 h-4 text-muted-foreground" />
            </div>
            
            {vulnerabilitySeverityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={vulnerabilitySeverityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {vulnerabilitySeverityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value) => [`${value} vulnerabilities`, 'Count']}
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      borderColor: 'hsl(var(--border))',
                      borderRadius: '0.5rem'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[200px]">
                <div className="text-center text-muted-foreground">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No vulnerabilities detected</p>
                </div>
              </div>
            )}
          </div>

          {/* Vulnerability Types */}
          <div className="border rounded-md p-4 md:col-span-2">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium">Vulnerability Types</h3>
              <BarChart3 className="w-4 h-4 text-muted-foreground" />
            </div>
            
            {vulnerabilityTypeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={vulnerabilityTypeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis 
                    dataKey="name" 
                    tick={{ fontSize: 12 }}
                    stroke="hsl(var(--muted-foreground))"
                  />
                  <YAxis 
                    allowDecimals={false}
                    stroke="hsl(var(--muted-foreground))"
                  />
                  <Tooltip 
                    formatter={(value) => [`${value} vulnerabilities`, 'Count']}
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      borderColor: 'hsl(var(--border))',
                      borderRadius: '0.5rem'
                    }}
                  />
                  <Bar 
                    dataKey="value" 
                    fill="hsl(var(--primary))" 
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[200px]">
                <div className="text-center text-muted-foreground">
                  <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No vulnerability data available</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
          <div className="p-4 border rounded-md">
            <div className="text-2xl font-bold">
              {simulation?.discovered_hosts?.length || 0}
            </div>
            <div className="text-sm text-muted-foreground">Hosts Scanned</div>
          </div>
          
          <div className="p-4 border rounded-md">
            <div className="text-2xl font-bold">
              {vulnerabilities.length}
            </div>
            <div className="text-sm text-muted-foreground">Vulnerabilities</div>
          </div>
          
          <div className="p-4 border rounded-md">
            <div className="text-2xl font-bold">
              {simulation?.executed_exploits?.length || 0}
            </div>
            <div className="text-sm text-muted-foreground">Exploits</div>
          </div>
          
          <div className="p-4 border rounded-md">
            <div className="text-2xl font-bold">
              {vulnerabilities.filter(v => v.severity === 'critical').length}
            </div>
            <div className="text-sm text-muted-foreground">Critical Issues</div>
          </div>
        </div>

        {/* Most Vulnerable Hosts */}
        {hostVulnerabilityData.length > 0 && (
          <div className="mt-6 p-4 border rounded-md">
            <h3 className="text-sm font-medium mb-3">Most Vulnerable Hosts</h3>
            <div className="space-y-2">
              {hostVulnerabilityData.map((host, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="text-sm">{host.name}</div>
                  <div className="flex items-center">
                    <div className="w-32 h-2 bg-muted rounded-full overflow-hidden mr-2">
                      <div 
                        className="h-full bg-status-offline rounded-full"
                        style={{ width: `${(host.value / Math.max(...hostVulnerabilityData.map(h => h.value))) * 100}%` }}
                      />
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {host.value}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}