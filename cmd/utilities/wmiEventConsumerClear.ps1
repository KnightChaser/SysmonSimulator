# Get the existing LogFileEventConsumer with the specified Name
$ExistingLogConsumer = Get-CimInstance -Namespace root\subscription -ClassName LogFileEventConsumer -Filter "Name='ServiceConsumer'"

# Check if LogFileEventConsumer exists and delete it
if ($null -ne $ExistingLogConsumer) {
    $ExistingLogConsumer | Remove-CimInstance
    Write-Output "LogFileEventConsumer '$($ExistingLogConsumer.Name)' removed successfully."
} else {
    Write-Output "LogFileEventConsumer with Name 'ServiceConsumer' not found."
}
