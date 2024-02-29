# Creating new binder
$instanceBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()

$instanceBinding.Filter = $ServiceFilterObj
$instanceBinding.Consumer = $LogConsumerObj
$result = $instanceBinding.Put()
$newBinding = $result.Path
Write-Output $newBinding