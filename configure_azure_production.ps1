# Configure Azure App Service for production (disable test mode)
# Run this script to configure your production Azure deployment

$appName = "RiskGate"
$resourceGroup = "your-resource-group-name"  # UPDATE THIS

Write-Host "Configuring Azure App Service for production..." -ForegroundColor Cyan

# Disable test mode in production
Write-Host "`nDisabling test authentication mode..." -ForegroundColor Cyan
az webapp config appsettings set `
    --name $appName `
    --resource-group $resourceGroup `
    --settings TESTING_MODE=false

# Verify the settings
Write-Host "`nVerifying configuration..." -ForegroundColor Cyan
az webapp config appsettings list `
    --name $appName `
    --resource-group $resourceGroup `
    --query "[?name=='TESTING_MODE']" `
    --output table

Write-Host "`nProduction configuration complete!" -ForegroundColor Green
Write-Host "Test authentication is now disabled in production." -ForegroundColor Yellow
