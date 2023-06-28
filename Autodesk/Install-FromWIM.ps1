# there is an assumption that only 1 wim file is in this folder
$wimFile = "image.wim"
#$mountPath = "C:\windows\temp\temp_" + $wimFile.BaseName
$mountpath	= "C:\windows\temp\temp_image"

## Create / Test the folder to mount the WIM to

TRY {
	##Checks for mount folder and deletes if present
	If((Test-Path $mountPath)){
		## cleanup mount point
		Remove-Item -Path $mountPath -force -recurse
	}
    ## checks for mount folder and creates if missing
    If(!(Test-Path $mountPath)){
        New-Item -Path $mountPath -ItemType Directory
        } Else {
        ## Folder already exists.  We need to ensure its clean, so check if it's mounted, then remove it, then re-create it 

        $Mounted = Get-WindowsImage -Mounted | Where-Object { $_.MountPath -eq $mountPath } 

        If ([bool]$Mounted) { 
            ## attempt to dismount the mounted image
            try { 

            $Mounted | Dismount-WindowsImage -Discard 

            Clear-WindowsCorruptMountPoint 

            Write-Log -Message "Dismount complete" 
            } Catch {
                ## clean up failed, exit
                Exit 1
            }
        }
    } 
    } Catch {
        ## Couldn't create a mounting point, exiting.
        Exit 1
    }

try {
    ## mount the WIM here
	#New-Item -Path $mountPath -ItemType Directory
	Mount-WindowsImage -ImagePath $wimFile -Index 1 -Path $mountPath
}
catch {
    ## failed to mount the WIM, can't proceed
    exit 1
}

try {
    ## perform your install here
	# call the install.cmd that is contained within the WIM file
	#powershell.exe -ExecutionPolicy Bypass .\Install.ps1
	cmd /c $mountPath\Install.cmd 	
    ## set exit return code to success value
    $returnCode = 0
}
catch {
    ## handle/log the errors, etc.
 IF (Test-Path $source) {
    ## creates a destination folder if missing
    If(!(Test-Path -Path $Dest)){
    New-Item -Path $dest -ItemType Directory
    }
    ## copies log files to common log folder
    Copy-Item -Path $source -Destination $dest -Recurse -Force   
    ## set exit return code to error value
    $returnCode = 1
	}
}	
finally {
    ## dismount the WIM whether we succeeded or failed
    try {
        Dismount-WindowsImage -Path $mountPath -Discard
		## cleanup mount point
		Remove-Item -Path $mountPath -force -recurse
    }
    catch {
        ## failed to cleanly dismount, so set a task to cleanup after reboot
        $STAction = New-ScheduledTaskAction `
            -Execute 'Powershell.exe' `
            -Argument '-NoProfile -WindowStyle Hidden -command "& {Get-WindowsImage -Mounted | Where-Object {$_.MountStatus -eq ''Invalid''} | ForEach-Object {$_ | Dismount-WindowsImage -Discard -ErrorVariable wimerr; if ([bool]$wimerr) {$errflag = $true}}; If (-not $errflag) {Clear-WindowsCorruptMountPoint; Unregister-ScheduledTask -TaskName ''CleanupWIM'' -Confirm:$false}}"'
            
        $STTrigger = New-ScheduledTaskTrigger -AtStartup
        
        Register-ScheduledTask `
            -Action $STAction `
            -Trigger $STTrigger `
            -TaskName "CleanupWIM" `
            -Description "Clean up WIM Mount points that failed to dismount properly" `
            -User "NT AUTHORITY\SYSTEM" `
            -RunLevel Highest `
            -Force
    }
    
    ## return exit code
    exit $returnCode
}


