$TestValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
If($TestValue.DisableWindowsConsumerFeatures -eq 1)
{
    Write-Output "Compliant"
}