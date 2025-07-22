# AutoVC Bootstrap Script - PowerShell
Write-Host "`n🧠 AutoVC Bootstrap Initializing..." -ForegroundColor Cyan

# Step 1: Load environment variables from .env
if (Test-Path ".env") {
    Write-Host "✅ Loading .env variables..." -ForegroundColor Green
    Get-Content .env | ForEach-Object {
        if ($_ -match "^(\w+)=['\"]?(.*)['\"]?") {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
} else {
    Write-Host "⚠️  .env file not found. Please make sure it exists in the current directory." -ForegroundColor Yellow
    exit 1
}

# Step 2: Optionally activate virtual environment (if exists)
if (Test-Path ".\venv\Scripts\Activate.ps1") {
    Write-Host "✅ Activating virtual environment..." -ForegroundColor Green
    . .\venv\Scripts\Activate.ps1
} else {
    Write-Host "⚠️  Virtual environment not found. Skipping activation." -ForegroundColor Yellow
}

# Step 3: Run the app
Write-Host "`n🚀 Starting AutoVC..." -ForegroundColor Cyan
python autovc.py