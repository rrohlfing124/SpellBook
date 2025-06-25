---
layout: default
title: Home
---

# Cybersecurity Analyst Command Reference

Welcome to your beginner-friendly command reference guide. This document provides categorized examples of commonly used commands across various platforms.

---

## Table of Contents
- [Windows CMDline](#windows-cmdline)
- [PowerShell](#powershell)
- [PowerShell Scripts](#powershell-scripts)


## Windows CMDline

## Cmdline  

| Command| Notes|
|----|----|
|(netstat -ano & tasklist & sc query) > moredata.txt |  *Note: () and & allows commands to be combined in a single line*|
  
<br>  

## Startup locations:

> - C:\ProgramData\microsoft\windows\start menu\programs\startup
> - C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
> - wmic startup list brief
> - wmic startup list brief

<br>  

## Hotfixes:
> - `systeminfo /s <IP>`

<br>  

## Remote:  

| Command| Notes|
|----|----|
| mstsc  |  *Note: start remote desktop session in GUI*|
| winrs -r:<IP> -u:USERNAME -p:PASSWORD COMMAND | |
| \\\IP -u:USERNAME -p:PASSWORD COMMAND | *Note: located in sysinternals* |
| psexec \\<IP> -u:USERNAME -p: PASSWORD -S COMMAND  |  *Note: System Priveleges*|
| psexec \\<IP> COMMAND  ||
| wmic /node:<IP> process where "name like '%svc%'" get name, processid, commandline  |  *Note: For remote machines, get name, process IDs for process svc*|
|sc \\\10.0.0.50 \<CMD> \<service> |*Note: remote with sc*|  
<br>  

## Search  

| Command| Notes|
|----|----|
|find (case sensitive) | *Note: <br> /I Case Insensitive <br> /S Include subdirectories <br> /C Count of line containing string*|
|findstr | *Note: /d:[dir] <"string"> [files to search]*|
|findstr \<"string"> \*.txt| *Note: Shows filename and content*|
|find /I z:\\stuff\\* \<"string">| *Note: If access is denied for folder, use asterisk for access to subfolders*|
|tasklist \| find "svchost"| *Note: Search for svchost service in tasklist*|

## Share  

| Command| Notes|
|----|----|
|net use z: \\\ \<IP to share>\\S \<password> /user:domain\\user| *Note: Mount fileshare*|
|net use \\\ \<server> W12SVR||
|Z:|*Note: Change drive*|
|net share| *Note: Manage, view status of shares, connect/disconnect to/from shares*|
|net share \<name of share> = \<letter of drive>:\\\<path> \<options> | *Note: Netshare*|

## PowerShell  


| Command| Notes|
|----|----|
|Get-Alias \<command>||
|Get-Alias -definition where-object||
|ICM|*Invoke command*||
|CN|*Computer Name*||
|CR|*Credentials*||
|gci|*Get-Childiten*||
|select|*Select-Object*||
|gps|*Get-Process*||
|gm|*Get-Member*||  
<br>  

## Audit  

| Command| Notes|
|----|----|
|Get-Eventlog Security \| Group-Object instanceid||
|Get-Eventlog Security -instanceid \<####> \| where {timewritten -gt "2022-08-22 00:00:00"} \| Group-Object Eventid | *Return how many events with ID were generated on said date*|
|icm {Get-Eventlog Security -instanceid \<####> \| where {timewritten -gt "2022-08-22 00:00:00"} \| Group-Object Eventid} -cn \<IP> -cr \<domain\\user>|
|icm -cn \<IP> -cr \<domain\\user> {Get-Eventlog Security \| where message -match "Logon Type:\\s+2" \| Group-Object Eventid} |*Match logon types in eventViewer*|
|icm -cn \<IP> -cr \<domain\\user> {Get-Eventlog Security \| where message -match "Logon Type:\\s+2" \| where timegenerated -gt "2022-08-22 00:00:00" \| Select index, instanceid, message} |*To get message of certain types on screen*|
<br>

## Dependencies  

| Command| Notes|
|----|----|
|Get-Service \<service> \| Select requiredservices, dependentservices|
<br>

## History  

| Command| Notes|
|----|----|
|Get-History|
<br>

## Out-File  

| Command| Notes|
|----|-------|
|ipconfig /all \| Out-file -filepath \<filepath> |*Redirect information to txt file*|
|netstat \| Out-file -append -filepath \<filepath> |*Append data to file in filepath*|
|netstat \| Out-file \<filename.txt>; tasklist \| Out-file -append \<filename.txt>; C:\\user\\public\\desktop\\sysinternals\\autoruns.exe \| Out-file -appemd \<filename.txt> | *; - Combine cmds <br> \| -  Out-file <br> -append -  append to filename*|
<br>


## Network  

| Command| Notes|
|----|-------|
|Get-NetTCPConnection|
<br>

## Processes  

| Command| Notes|
|----|-------|
|gps \| gm| *To see options*|
|gps \<process> \| select -property \<id, modules, path> | *Get selected properties of process*|
|gps \<process> \| select -expand modules | *Path of the modules*|
|Stop-Process -name \<process name>|
<br>

## Services  

| Command| Notes|
|----|-------|
|Get-Service|
|Get-Service \| gm|
|Get-Service \<service> \| select -property \<properties>|
|Get-Service \| Where StartType -eq "Auto"|*Search services set to Auto Start*|
|Get-Service \| Where name -eq "Wlansvc"|
|Get-Service \<service> \| Select requiredservices, dependentservices|
<br>

## Firewall  

| Command| Notes|
|----|-------|
|Get-netfirewallrule|
|netsh advfirewall set allprofiles state off|*Disable firewall*|
|netsh advfirewall set allprofiles state on|*Enable firewall*|
<br>

## Remoting  

| Command| Notes|
|----|-------|
|icm -cn \<IP> -cr \<domain\\user> {command}|
|icm -cn \<IP> {command} -cr \<domain\user> | *Sending commands to remote host*|
|Copy-item -path C:\moredata.txt -Destination \\\10.0.0.50\\c$\\users\\public\\desktop |*Move file from \<source> to -destination \<\\\ \<IP>\\\<path> <br> C$ instead of C:*|
|icm -cn \<IP> -cr \<domain/user> {certutil -hashfile C:\networkdata.txt} | *Remote hashfile*|
<br>

## Search  

| Command| Notes|
|----|-------|
|Get-Process -name notepad|
|Get-Command \*search*|
|Get-Command -name \*IP*|
|Get-Command -verb add|
|Select-String -pattern \<string>|*Searches for text in input strings and files*|
|Get-Childitem \| Get-Member \| Select-String -pattern \<string> | *Get-Childitem = gci*|
|Get-Itemproperty|*Get lastaccesstime and registry entries*|
|gci -recurse -path C:\windows -filter \<"string"> | *Search file system for \<"string.exe"*> name
|icm -cn \<computername or IP> -cr \<domain/user> {gci -recurse -path C:\\windows -filter \<"string">} | *Remotely search file system for \<"string.exe"> name*|
<br>

## ADS  

| Command| Notes|
|----|-------|
|PS C:\\ Get-Childitem -recurse \| %{Get-item $_.fullname -stream *} \| where stream -ne ':$Data'|
<br>

## Select-String  

| Command| Notes|
|----|-------|
|netstat -ano \| select-string "ESTABLISHED"|
|Select-string -pattern \<string>|
<br>

## Filter/refine Example  

| Command| Notes|
|----|-------|
|Get-Childitem -recurse -file -filter \<string> \| Where-Object lastwritetime -gt (-lt -eq -match) \<string> or date \<07/05/2016> \| select name, lastwritetime \| measure-object | *Select is alias for Select-Object <br> Search every file containing "log" in the name and has been modified after "07/04/2016"*|
|Get-Childitem \| Where-object name -eq Desktop | *Looks in files for files named Desktop*|
|Get-Process \| Sort Object -Descending|
|Get-Process \| Select-Object ProcessName, ID | *Specify objects to return*|
|Get-Process \| Select name, path @{name="Hash"; expression={(Get-Filehash $_.path).hash}} | *Name/Label = "Name of Parameter"*|
<br>

## Where-Object  

| Command| Notes|
|----|-------|
|Get-Service \| Where-Object -property name -like "*cd*"|
|Get-Service \| Where-Object {$_.status -eq "Stopped"}|
|Get-Service \| Where-Object {$_.LastLogon -gt (Get-Date}.AddDays(-1)}|
|Get-Service \| Where-Object {$_.name -like "cd" -and $_.status -eq "running"}|  
<br>

## Format-Object  

| Command| Notes|
|----|-------|
|Get-Process \| Sort-Object -property BasePriority | Format-Table -GroupBy Basepriority -wrap|
|Format-Table -Autosize|
<br>

## Compare Files  

| Command| Notes|
|----|-------|
|Compare-Object -referenceobject (Get-content service1.txt) -differenceobject (get-content service2.txt) \| out-file servicecompare.txt | *Compare two files and output into a new file*|
|Get-command \| where-object property -comparison_operator value| *Compare an object's property to a given value*|
<br>

## Attributes  

| Command| Notes|
|----|-------|
|(Get-Item .\Squirrel.docx).attributes='Archive, Hidden' | *Sets Archive and hidden attrbutes to .\Squirrel.docx*|
|gci -force | *Shows hidden files*|
|(gci -force .\Squirrel.docx).attributes='Archive' | *Removes attribute*|
<br>

## Format  

| Command| Notes|
|----|-------|
|Format-table -property \<specific property> -autosize | *-Shrinks columns <br> -groupby -One table per group <br> -wrap -Doesn't truncate*|
<br>

## Hash  

| Command| Notes|
|----|-------|
|Get-filehash moredata.txt -algorithm SHA1 | *Get filehash for \<file<*|
<br>


## Count  

| Command| Notes|
|----|-------|
|(CMD).count|
|Measure-object|
<br>

## Get-WMIObject/Ciminstance  

| Command| Notes|
|----|-------|
|Get-CimClass -ClassName "*process*" | *List available classes*|
|Get-CimInstance -ClassName Win32_Process | *Executes specific class*|
<br>

## Show-Command  

| Command| Notes|
|----|-------|
|Show-Command Get-Process| *Creates  cmnd in GUI cmd window*|
<br>

#POWERSHELL SCRIPTS
## User Accounts

<br>

## PowerShell Scripts
---


### [Csv](http://855-cyber-protection-team.pages.joust.lab/tools/_Windows/Export/) creation of all computers in Active Directory  

    Get-ADComputer -Filter * -Property * | Select-Object Name, OperatingSystem, OperatingSystemVersion, ipv4Address | Export-Csv ADcomputerslist.csv -NoTypeInformation -Encoding UTF8


### <u> VARIABLE CREATION</u>  

    $targets = Import-Csv ..\Path\to\CSV.csv | Where-Object {$_.field -eq "string"} | Select-Object -ExpandProperty IP   
    $creds = Get-Credential <domain\User> #Password


### <u> REMOTE SCRIPTS</u>
    Invoke-Command -computername $targets -Credentials $creds -FilePath..\Path\to\Powershell_script.ps1 | Export-Csv .\Path\to\new_CSV.csv    

    ICM -CN $targets -CR $creds -FilePath..\Path\to\Powershell_script.ps1 | Export-Csv .\Path\to\new_CSV.csv  

**Connect to IP remotely and execute a command**  

	Invoke-Command -computername <IP> {Command}

**Move a file from local machine to remote machine using PSSession**

	$session = New-PSSession -ComputerName 192.168.0.1 -Credential $creds 	

	Copy-Item -Path .\file.name.txt -ToSession $session -Destination C:\Users\student\Documents\file.name.txt

	Remove-PSSession *

**Move a file from remote machine to local machine using PSSession**

	$session = New-PSSession -ComputerName 192.168.0.1 -Credential $creds 	

	Copy-Item -Path C:\Users\student\Documents\file.name.txt -FromSession $session -Destination .	

	Remove-PSSession *
	

### <u>**EVENT LOGS**</u>  		

	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$logfilter = @{
	        	LogName   = "Security"
	        	ID        = 4720
	        	StartTime = [datetime]"08/05/2022 00:00:00z"
	        	EndTime   = [datetime]"08/05/2022 00:00:00z"
	        	#Data      = "<SID>" #This is if you want to look for events related to a specific user
	    }
	
		Get-WinEvent -FilterHashtable $logfilter 	

		} | Select-Object -Property RecordID, Message |
	    		Format-Table -Wrap  
			  
### <u>**FILE LOCATION**</u>

	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$Paths = "C:Windows\System32\Hidden", "C:\Program Files\Downloads"
		Get-ChildItem -Path $Paths -Recurse -File -Force


### <u>**REGULAR EXPRESSIONS**</u>
**Find important information within files using regular expressions.** 
	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$ssn     = "\d{3}-\d{2}-\d{4}"
		$email   = "[\w\.-]+@[\w\.-]+\.[\w]{2,3}"
		$keyword = "(?=.*Str1)(?=.*Str2|.*Str3)"
		$paths   = "C:Windows\System32\Hidden", "C:\Program Files\Downloads"
	

		Get-ChildItem $paths -Recurse -File -Force |
	        	Select-String -Pattern $ssn,$email,$keyword -AllMatches |
	            	Select-Object -Property Path, Line
	}


### <u>**REFERENCE SCRIPTS**</u>   
SAVE BELOW COMMANDS AS .ps1 TO BE REFERENCED FOR REMOTE EXECUTION OR AUTOMATION  

####  <u> Accounts </u>
| CMD| Flags | Description |
|---|---|---|
| Get-CimInstance |**-ClassName Win32_UserAccount \| Select-Object -Property Name, Disabled, PasswordRequired, SID** | List of User Accounts w/specific properties|
| Net localgroup administrators | |List of local admin accounts |
| Net localgroup administrators | **/Domain**  | List of domain admins in "administrators" group|  

    Invoke-Command -computername $targets -Credentials $creds -FilePath..\Path\to\Accounts.ps1 | Export-Csv .\Path\to\Accounts.csv  

####  <u> Autoruns</u>
    param([string][] $AutoRunKey)

        foreach($key in Get-Item -Path $AutoRunKey -Error Actrion SilentlyContinue){
            $data = $key.GetValueNames() | 
                Select-Object -Property @{n="Key_Location"; e={$key}},
                                        @{n="Key_ValueName"; e={$_}},
                                        @{n="Key_Value"; e={$key.GetValue($_)}}

            if($null -ne $data){
            [pscustomobject]$data
            }

        }


####  <u> Firewall</u>
    $rules = Get-NetFirewallRule | Where-Object {$_.enabled}
	        $portfilter    = Get-NetFirewallPortFilter
	        $addressfilter = Get-NetFirewallAddressFilter
	

	        ForEach($rule in $rules){
	            $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
	            $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
	            $data        = @{
	                    InstanceID = $rule.InstanceID.ToString()
	                    Direction  = $rule.Direction.ToString()
	                    Action     = $rule.Action.ToString()
	                    LocalAddress = $ruleaddress.LocalAddress -join ","
	                    RemoteAddress = $ruleaddress.RemoteAddress -join ","
	                    Protocol = $ruleport.Protocol.ToString()
	                    LocalPort = $ruleport.LocalPort -join ","
	                    RemotePort = $ruleport.RemotePort -join ","
	                   }
	

	            New-Object -TypeName psobject -Property $data
	    }

####  <u> Processes </u>  
    Get-CimInstance -ClassName Win32_Process |
	             Select-Object -Property ProcessName,
	                            ProcessID,
	                            Path,
	                            CommandLine,
	                            @{n="Hash"; e={(Get-FileHash -Path $_.path).hash}}  


####  <u> Scheduled tasks</u>  
	schtasks /query /V /FO CSV | ConvertFrom-Csv |
	    	Where-Object {$_."Scheduled Task State" -eq "Enabled"} |
	        	Select-Object -Property TaskName,
	                                Status,
	                                "Run As User",
	                                "Schedule Time",
	                                "Next Run Time",
	                                "Last Run Time",
	                                "Start Time",
	                                "End Time",
	                                "End Date",
	                                "Task to Run",
	                                @{n="Hash";e={(Get-FileHash -Path (($_."Task to Run") -replace '\"','' -replace "\.exe.*","exe") -ErrorAction SilentlyContinue).	hash}}

####  <u> Services </u>  
	Get-CimInstance -ClassName Win32_Service |
	    		Select-Object -Property @{n="ServiceName";e={$_.name}},
	                            		@{n="Status";e={$_.state}},
	                            		@{n="StartType";e={$_.stertmode}},
	                            		PathName


### <u>**BASELINE SCRIPTS**</u>   

####  <u> Accounts</u>  
 	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\accounts.ps1 | Export-Csv .\<OperatingSystrem>_AccountsBaseline.csv  

####  <u> Autoruns </u>  
 	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\autoruns.ps1 | -ArgumentList (,(Get-Content .\Autoruns.txt)) | Export-Csv .\<OperatingSystrem>_AutoRunsBaseline.csv

####  <u> Firewall </u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\firewall.ps1 | Export-Csv .\<OperatingSystrem>_FirewallsBaseline.csv

####  <u> Processes </u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\processes.ps1 | Export-Csv .\<OperatingSystrem>_ProcessesBaseline.csv	

####  <u> Scheduled Tasks</u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\scheduled_tasks.ps1 | Export-Csv .\<OperatingSystrem>_ScheduledTasksBaseline.csv	

####  <u> Services</u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\services.ps1 | Export-Csv .\<OperatingSystrem>_ServicesBaseline.csv  

	
### <u>**COMPARE BASELINE SCRIPTS**</u>  

####  <u> Accounts </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP
	    
		$ht = @{
	 			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AccountsBaseline.csv
				Property        = "name"
	 			PassThru        = $true
		}

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\accounts.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	                Sort-Object -Property name -Unique
	        Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}

####  <u> Autoruns </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP
	    
		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AutoRunsBaseline.csv
	  			Property        = "Key_ValueName"
	  			PassThru        = $true
		}	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\autoruns.ps1 -ArgumentList (,(Get-Content ..		\Autorunkeys.txt))
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	               Sort-Object -Property Key_Valuename -Unique
	        Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}


####  <u> Firewall </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AccountsBaseline.csv
	  			Property        = "direction", "action", "localaddress", "remoteaddress", "localport", "remoteport"
	  			PassThru        = $true
		}	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\firewall.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	    		Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property direction, action, localaddress, remoteaddress, localport, remoteport -Unique
	    	Compare-Object @ht |
	        	Select-Object -Property *, @{n = "IP"; e = {"$IP"}}
		}

####  <u> Processes </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP  

		$ht = @{
				ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ProcessesBaseline.csv
				Property        = "hash", "path"
				PassThru        = $true
		}

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\processes.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property hash, path -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>" -and $_.path -ne $null}
		}		

####  <u> Scheduled Tasks</u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ScheduledTasksBaseline.csv
	  			Property        = "taskname"
	 			PassThru        = $true
		}
	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\ScheduledTask.ps1 
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property taskname -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}

####  <u> Services </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
				ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ServicesBaseline.csv
				Property        = "ServiceName"
				PassThru        = $true
		}
	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\services.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property ServiceName -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}  
### <u>**LFA SCRIPTS**</u>  

####  <u> AutoRuns </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\autoruns.ps1 -ArgumentList (Get-Content ..\AutoRunKeys.txt)
	
			$current | Sort-Object -Property pscomputername, Key_ValueName -Unique |
	        	Group-Object Key_ValueName |
	                Where-Object {$_.count -le 2} |
	                    Select-Object -ExpandProperty Group


####  <u> Processes </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\processes.ps1	

			$current | Sort-Object -Property pscomputername, hash -Unique |
	        	Group-Object hash |
	                Where-Object {$_.count -le 2} |
	                	Select-Object -ExpandProperty Group  

####  <u> Scheduled Tasks </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\scheduledtask.ps1	

			$current | Sort-Object -Property pscomputername, taskname -Unique |
	        	Group-Object taskname |
	                Where-Object {$_.count -le 2} |
	                    Select-Object -ExpandProperty Group  

####  <u> Services </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\services.ps1	

			$current | Sort-Object -Property pscomputername, ServiceName -Unique |
	        	Group-Object ServiceName |
	                Where-Object {$_.count -le 2} |
	                        Select-Object -ExpandProperty Group


## 🧰 Linux CMDs

### System
- `uname -a`  
  *Note: Shows system information.*
- `top`  
  *Note: Displays running processes and resource usage.*

### Networking
- `ifconfig` or `ip a`  
  *Note: Shows network interfaces.*
- `netstat -tuln`  
  *Note: Lists listening ports.*

---

## 🔍 Security Monitoring

- `whoami`  
  *Note: Shows current user.*
- `net user`  
  *Note: Displays user account information.*
- `auditpol /get /category:*`  
  *Note: Shows audit policy settings on Windows.*

---

## 🔗 Helpful Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [CyberChef](https://gchq.github.io/CyberChef)

---

*Save this file with a `.md` extension and open it in a Markdown editor like VS Code, Typora, or Obsidian.*
