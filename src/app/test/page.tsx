export default function TestPage() {
  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-4 text-foreground">Test Page</h1>
        <p className="text-muted-foreground mb-6">If you can see this with proper styling, Tailwind CSS is working.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-card p-6 rounded-lg border">
            <h2 className="text-xl font-semibold mb-2 text-card-foreground">Card Test</h2>
            <p className="text-muted-foreground">This should have a card background and border.</p>
          </div>
          
          <div className="bg-primary p-6 rounded-lg">
            <h2 className="text-xl font-semibold mb-2 text-primary-foreground">Primary Test</h2>
            <p className="text-primary-foreground/80">This should have a primary background.</p>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-cyber-500/10 rounded-lg border border-cyber-500/20">
          <h3 className="text-lg font-medium text-cyber-500 mb-2">CyberCortex Colors</h3>
          <p className="text-muted-foreground">This should have CyberCortex brand colors.</p>
        </div>
      </div>
    </div>
  )
} 