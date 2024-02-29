#Creating a new event filter
$ServiceFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()

# Set the properties of the instance
$ServiceFilter.QueryLanguage = 'WQL'
$ServiceFilter.Query = "select * from __instanceModificationEvent within 5 where targetInstance isa 'win32_Service'"
$ServiceFilter.Name = "ServiceFilter"
$ServiceFilter.EventNamespace = 'root\cimv2'

# Sets the intance in the namespace
$FilterResult = $ServiceFilter.Put()
$ServiceFilterObj = $FilterResult.Path
Write-Output $ServiceFilterObj