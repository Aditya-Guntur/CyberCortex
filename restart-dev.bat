@echo off
echo 🔄 Restarting CyberCortex Development Server...

REM Stop any running processes
echo 📋 Stopping existing processes...
taskkill /f /im node.exe 2>nul || echo No Node processes found

REM Clear Next.js cache
echo 🧹 Clearing Next.js cache...
if exist .next rmdir /s /q .next

REM Start development server
echo 🚀 Starting development server...
npm run dev 