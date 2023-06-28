<#
The below is a very basic example of how to create a WIM file. It has no error checking or remediation of any kind.
This is just to show how simple it can be to get started.
#>

# Data you want to be put into a WIM
$Source = "$PSScriptroot\IMAGE"
# Where you want the WIM file to be created, and its name
$WIMLocation = "$PSScriptroot\Image.wim"
# This is actually the name of the Index 1 on the WIM
$WIMName =  "Image"
# Discription of the Index
$Discription = "Autodesk Inventor Pro 2023"

# This creates a WIM based on the above variables
New-WindowsImage -CapturePath $Source -ImagePath $WIMLocation -CompressionType Max -Name $WIMName -Description $Discription

# This is an example of creating a wim withouth the varaibles
#New-WindowsImage -CapturePath "D:\SolidWorksSetup_2021_SP4.1 - Source" -ImagePath "D:\SW_PDM.wim" -CompressionType Fast -Name "SW_PDM" -Description "SolidWorks PDM Install Source"