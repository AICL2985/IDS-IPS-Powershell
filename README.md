# IDS-IPS-Powershell

This PowerShell script is an important tool for managing and mitigating vulnerabilities in a cybersecurity project. The script monitors a list of commonly targeted ports, such as ports 21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, and 5900, for any incoming connections. If an intrusion attempt is detected on any of these ports, the script alerts the user and blocks the port using a firewall rule.
These ports are often targeted by attackers as they are commonly used for various services, such as FTP, SSH, Telnet, SMTP, HTTP, HTTPS, and RDP. Attackers can exploit vulnerabilities in these services to gain unauthorized access to a system or network. For example, an attacker can use an FTP server to upload malicious files or steal sensitive data, or use an RDP server to gain remote access to a system.
By monitoring these ports and blocking any unauthorized access attempts, this script helps to mitigate the risk of successful attacks. It provides a simple and effective solution for intrusion detection and prevention, which can be easily integrated into a larger cybersecurity project.


```powershell
# Function to monitor and detect intrusion attempts on a specific port
function Monitor-Port {
    param (
        [int]$Port
    )
    # Filter connection events on the specified port
    $filter = @{
        LogName = 'Security' 
        Id = 5157 
        StartTime = (Get-Date).AddMinutes(-1) 
        ProviderName = 'Microsoft-Windows-Security-Auditing'
        FilterXPath = "*[System[(EventID=5157) and (EventData/Data[@Name='TcpPort']='$Port')]]"
    }

    # Gets the connection events on the specified port
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    
    # If connection events are detected, alert the user and block the port
    if ($events) {
        Write-Host "Port intrusion detected $Port" -ForegroundColor Red -BackgroundColor Black
        Add-FirewallRule -RuleName "Block_Port_$Port" -Port $Port
    }
}

$existingRule = $null

function Check-FirewallRule {
    param (
        [string]$RuleName
    )
    # Check if the rule already exists
    $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
}

function New-FirewallRule {
    param (
        [string]$RuleName,
        [int]$Port
    )
    # If the rule does not exist, it creates a new rule
    if (!$existingRule) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -LocalPort $Port -Protocol TCP -Action Block
        Write-Host "Added firewall rule: $RuleName (Puerto: $Port)" -ForegroundColor Green
    } else {
        Write-Host "The firewall rule already exists: $RuleName (Puerto: $Port)" -ForegroundColor Cyan
    }
}

# Prompting the user for their desired action
# Display the available options
Write-Host ""
Write-Host "     FIREWALL MONITOR      "
Write-Host ""

# List of ports to monitor
$portsToMonitor = @(21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900)
$portsToMonitor

# Monitor ports and detect intrusion attempts
foreach ($port in $portsToMonitor) {
    Monitor-Port -Port $port
}

Write-Host "What would you like to do?"
Write-Host ""
Write-Host "    A) Check if the firewall rule already exists"
Write-Host "    B) Create a new firewall rule"
Write-Host ""

# Read and return the user's response
$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host ""
Write-Host "User entered $($response)" -ForegroundColor Green
Write-Host ""

if ($response -eq "A".ToUpper()){
    $ruleName = Read-Host -Prompt "Please enter the name of the firewall rule to check"
    Check-FirewallRule -RuleName $ruleName
}
elseif($response -eq "B".ToUpper()){
    $ruleName = Read-Host -Prompt "Please enter the name of the new firewall rule"
    $port = Read-Host -Prompt "Please enter the port to block"
    New-FirewallRule -RuleName $ruleName -Port $port
}
```


This script is an important tool for managing and mitigating vulnerabilities in a cybersecurity project. It helps to protect against common attack vectors by monitoring and blocking incoming connections on commonly targeted ports. By using this script, organizations can improve their overall security posture and reduce the risk of successful attacks.
