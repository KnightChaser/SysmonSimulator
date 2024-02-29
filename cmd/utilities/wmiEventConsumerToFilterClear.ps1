# Get the existing LogConsumerBinder
$ExistingLogConsumerBinder = Get-WmiObject -Namespace root\subscription -ClassName __FilterToConsumerBinding

if ($null -ne $ExistingLogConsumerBinder) {
    $ExistingLogConsumerBinder | Remove-WmiObject
    Write-Output "LogFileEventConsumerBinder removed successfully."
} else {
    Write-Output "LogFileEventConsumerBinder not found."
}