# Specify the filter name to be removed
$FilterName = "ServiceFilter"

# Remove the event filter
$FilterPath = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" | Where-Object { $_.Name -eq $FilterName }

if ($null -ne $FilterPath) {
    $FilterPath.Delete()
    Write-Host "Event filter '$FilterName' removed successfully."
} else {
    Write-Host "Event filter '$FilterName' not found."
}
