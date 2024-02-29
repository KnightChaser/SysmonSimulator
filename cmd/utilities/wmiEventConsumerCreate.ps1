#Creating a new event consumer
$LogConsumer = ([wmiclass]"\\.\root\subscription:LogFileEventConsumer").CreateInstance()

# Set properties of consumer
$LogConsumer.Name = 'ServiceConsumer'
$LogConsumer.Filename = "C:\Log.log"
$LogConsumer.Text = 'A change has occurred on the service: %TargetInstance.DisplayName%'

# Sets the intance in the namespace
$LogResult = $LogConsumer.Put()
$LogConsumerObj = $LogResult.Path
Write-Output $LogConsumerObj