# Uses POSH-SSH tested with 2.0.2

$DHCPserver = '' # Name/ip of DHCP server
$Firstscope = '' # first number in the first scope on DHCP
$Secondscope = '' # first number in the second scope on DHCP
$adcreds = Get-Credential -Message "This is the AD creds for the DHCP server."
$global:creds = Get-Credential -Message "Creds for Switches" # comment this out if you have multiple passwords for all your switches and good luck.

$global:maclookup = Get-Content "$PSScriptRoot\macaddress.io-db.json" | convertfrom-json
$global:switches = Get-Content "$PSScriptRoot\switches.csv" | ConvertFrom-Csv
$DHCPtableSecond = invoke-command -Credential $adcreds -computername $DHCPserver -ArgumentList $Secondscope -scriptblock {
    param($Secondscope)
    Get-DhcpServerv4Lease -scopeid $Secondscope
}
$DHCPtableFirst = invoke-command -Credential $adcreds -computername $DHCPserver -ArgumentList $Firstscope -scriptblock {
    param($Firstscope)
    Get-DhcpServerv4Lease -scopeid $Firstscope
}
$global:DHCPtable = combine-arrays -array1 $DHCPtableFirst -array2 $DHCPtableSecond



Function Invoke-CiscoCommand{
    param($command,$ip)
    get-sshtrustedhost | Remove-SSHTrustedHost
    $session = New-SSHSession -ComputerName $ip -Credential $global:creds -AcceptKey
    $SSHStream = New-SSHShellStream -Index $session.SessionId
    $Completecommand = @(
    'terminal length 0',
    $command,
    'terminal length 24'
    )
    foreach ($c in $Completecommand){
    sleep 1
        $SSHStream.WriteLine($c)
    }
    sleep 1   
    $results = $sshstream.read() 
    Remove-SSHSession -SSHSession $session 
    return $results
}

function New-Table{
    param($ip,$hostname)
    $mactable = get-mactable -ip $ip -creds $global:creds -hostname $hostname
   
    
    $table = @()
    foreach ($line in $mactable){
        
        $convertedmac = ($line.mac.replace('.','') -split '(..)').Where({$_}) -join '-'
        $dhcpindex = $global:DHCPtable.clientid.indexof($convertedmac)
        $ipfrommac = $null
        $dhcphostname = $null
        if($dhcpindex -ne '-1'){
            $dhcphostname = $global:DHCPtable.hostname[$dhcpindex]
            $ipfrommac = $global:DHCPtable.ipAddress.ipaddresstostring[$dhcpindex]
        }
        $table += [pscustomobject]@{Vlan = $line.Vlan; Mac = $line.mac; IP = $ipfrommac; DHCPHostname = $dhcphostname ; Type = $line.type; Ports = $line.ports; Company = $line.company; Switch = $hostname; SwitchIP = $ip}
    }
    return $table
}
function get-mactable{
    param($ip,$hostname)
    $rawmactable = Invoke-CiscoCommand -command "sh mac add" -ip $ip -creds $global:creds
    $mactable = @()
    $words = $(-split $rawmactable)
    for ($i = 0;$i -le $words.count;$i++){
        if($words[$i] -match '^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$'){
            $company = get-maclookup -mac $words[$i]
            $mactable += [pscustomobject]@{Vlan = $words[$i-1]; Mac = $words[$i]; Type = $words[$i+1]; Ports = $words[$i+2]; Company = $company}
        }
    }
    return $mactable
}
function get-arptable{
    param($ip,$hostname)
    $rawarptable = Invoke-CiscoCommand -command "sh arp" -ip $ip -creds $global:creds
    $arptable = @()
    $words = $(-split $rawarptable)
    for ($i = 0;$i -le $words.count;$i++){
        if($words[$i] -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'){
            $arptable += [pscustomobject]@{Protocol = $words[$i-1]; IP = $words[$i]; AgeMinutes = $words[$i+1]; Mac = $words[$i+2]; Type = $words[$i+3]; Interface = $words[$i+4]}
        }
    }
    return $arptable
}

function get-maclookup{
    param($mac)
    $index = $null
    if($mac -match '^([0-9A-Fa-f]{4}[.-]){2}([0-9A-Fa-f]{4})$'){
        $convertedmac = $mac.replace('.','').replace('-','').ToUpper()
        $convertedmac = ($convertedmac -split '(..)').Where({$_}) -join ':'
    }
    
    $company = $null
    $index = $global:maclookup.oui.indexof($convertedmac.substring(0,8))
    if($index -eq '-1'){$index = $global:maclookup.oui.indexof($convertedmac.substring(0,10))}
    if($index -eq '-1'){$index = $global:maclookup.oui.indexof($convertedmac.substring(0,11))}
    if($index -eq '-1'){$index = $global:maclookup.oui.indexof($convertedmac.substring(0,13))}
    if($index -eq '-1'){$index = $global:maclookup.oui.indexof($convertedmac.substring(0,14))}
    if($index -ne '-1'){$company = $global:maclookup[$index].companyname}else{$company = $null}
    

    return $company
}
function combine-arrays{
    param($array1,$array2)
    $properties = $array1 | Get-Member -MemberType property,ScriptProperty
    $newarray = @()
    
    foreach ($line1 in $array1){
        $object = [PSCustomObject]@{}
        foreach($property in $properties.name){
            
            $object | add-member -NotePropertyName $property -NotePropertyValue $line1.$property
            
        }   
        $newarray += $object 
        
    }
    
    foreach ($line2 in $array2){
        $object = [PSCustomObject]@{}
        foreach($property in $properties.name){
            $object | add-member -NotePropertyName $property -NotePropertyValue $line2.$property
        }  
        $newarray += $object   
    }
    
    return $newarray
    
}


function new-seperateswitchreport{
    $date = get-date -Format yyyyMMddhhmmss
    $folder = "$PSScriptRoot\logs\$date"
    if(!(test-path $folder -PathType Container)){New-Item -Path $folder -ItemType Directory}
    foreach($switch in $global:switches){
        write-host "Parsing $($switch.hostname)..." -NoNewline
        $table = new-table -ip $Switch.ip -creds $global:creds -hostname $switch.Hostname
        $table | convertto-csv -NoTypeInformation | set-content "$folder\$($switch.Hostname).csv"
        write-host "Complete."
    }
}
function new-combinedswitchreport{
    $date = get-date -Format yyyyMMddhhmmss
    $folder = "$PSScriptRoot\logs\$date"
    if(!(test-path $folder -PathType Container)){New-Item -Path $folder -ItemType Directory}
    $table = $false
    foreach($switch in $global:switches){
        write-host "Parsing $($switch.hostname)..." -NoNewline
        if(!($table)){
            $table = new-table -ip $Switch.ip -creds $global:creds -hostname $switch.Hostname
        }else{
            $table += new-table -ip $Switch.ip -creds $global:creds -hostname $switch.Hostname        
        }
        write-host "Complete."
    }
    $table | convertto-csv -NoTypeInformation | set-content "$folder\Combined.csv"
}


new-combinedswitchreport


