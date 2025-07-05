#!/bin/bash

echo "🔄 Restarting CyberCortex Development Server..."

# Stop any running processes
echo "📋 Stopping existing processes..."
pkill -f "next dev" || true
pkill -f "npm run dev" || true

# Clear Next.js cache
echo "🧹 Clearing Next.js cache..."
rm -rf .next

# Clear node_modules (optional - uncomment if needed)
# echo "🗑️  Clearing node_modules..."
# rm -rf node_modules
# npm install

# Start development server
echo "🚀 Starting development server..."
npm run dev 