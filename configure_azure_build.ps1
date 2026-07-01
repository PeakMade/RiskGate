# Configure Azure App Service to build during deployment
# This enables Oryx to install Python dependencies automatically

$appName = "RiskGate"
$resourceGroup = "your-resource-group-name"  # UPDATE THIS

Write-Host "Configuring Azure App Service build settings..." -ForegroundColor Cyan

# Enable Oryx build during deployment
az webapp config appsettings set `
    --name $appName `
    --resource-group $resourceGroup `
    --settings SCM_DO_BUILD_DURING_DEPLOYMENT=true

# Remove the problematic startup command (let Oryx auto-detect)
Write-Host "`nRemoving custom startup command..." -ForegroundColor Cyan
az webapp config set `
    --name $appName `
    --resource-group $resourceGroup `
    --startup-file ""

# Verify the settings
Write-Host "`nVerifying configuration..." -ForegroundColor Cyan
az webapp config appsettings list `
    --name $appName `
    --resource-group $resourceGroup `
    --query "[?name=='SCM_DO_BUILD_DURING_DEPLOYMENT']" `
    --output table

Write-Host "`nConfiguration complete! Next deployment will build properly." -ForegroundColor Green
Write-Host "Run this to deploy: git add . && git commit -m 'Fix deployment' && git push origin main" -ForegroundColor Yellow
