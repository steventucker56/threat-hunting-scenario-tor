ST Threat-Hunting Project

<img width="800" height="534" alt="image" src="https://github.com/user-attachments/assets/2200f8da-c6b4-4e8f-a870-c156a849a92e" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/steventucker56/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks like the user “Stwlab1“ downloaded a tor installer, that person did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-08-25T16:34:09.2862278Z. These events began at: 2025-08-25T16:05:43.0571833Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "st-mde-vm"
| where InitiatingProcessAccountName == "stwlab1"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-25T16:05:43.0571833Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1180" height="620" alt="image" src="https://github.com/user-attachments/assets/1d4120f7-1c75-4bd4-842f-a28d42f174e4" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string
“Tor-browser-windows-x86_64-portable-14.5.6.exe”. Based on the logs returned, At 2025-08-25T16:11:32.4851876Z, an employee named stwlab1 on the device st-mde-vm ran a program from their Downloads folder — the Tor Browser portable installer — using a command that silently installed it in the background without showing any setup prompts.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "st-mde-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="2353" height="817" alt="image" src="https://github.com/user-attachments/assets/3f5a8627-c6ed-493e-bd16-34cd61a801b0" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “stwlab1” actually opened the tor browser. There was evidence that they did open it at 2025-08-25T16:12:28.4690063Z.
There were several other instances of firefox.exe (tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "st-mde-vm"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe", "start-tor-browser.exe", "tor-browser-windows-x86_64-portable-*.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="2416" height="1220" alt="image" src="https://github.com/user-attachments/assets/a809440f-ea31-4a27-859b-2d36ef87b5de" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known ports. At 2025-08-25T16:12:38.0152789Z, the user account stwlab1 on device st-mde-vm successfully established a network connection from the program tor.exe (located in the Tor Browser folder on their desktop) to the remote IP address 37.120.178.238 over port 9001, which is a known Tor network port.There were a couple  other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "st-mde-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="2386" height="1116" alt="image" src="https://github.com/user-attachments/assets/19b1076d-2454-434f-a221-b3531b26b49b" />

---

## Chronological Event Timeline 

2025-08-25 11:05:43 (UTC)

-On device st-mde-vm, user stwlab1 had a file event involving
 tor-browser-windows-x86_64-portable-14.5.6.exe in the Downloads folder.


-Action: File renamed, marking the beginning of Tor-related activity.



2025-08-25 11:09:51 (UTC)

-Two file events recorded for tor-browser-windows-x86_64-portable-14.5.6.exe.


-Action: File deleted twice from the Downloads folder.


-Indicates cleanup after download, possibly due to the installer moving itself or being removed post-execution.



2025-08-25 11:11:32 (UTC)

-A process creation event shows that user stwlab1 executed the Tor Browser installer:
 tor-browser-windows-x86_64-portable-14.5.6.exe /S


-This was launched from the Downloads directory with the silent install flag (/S), meaning installation occurred in the background without user prompts.



2025-08-25 11:11:55 (UTC)

-A new file named tor.txt was created in the Tor Browser\Browser\Tor folder under the user’s Desktop.


-Confirms that installation produced Tor-related files on the Desktop.



2025-08-25 11:12:28 (UTC)

-Evidence shows that stwlab1 launched the Tor Browser (firefox.exe/tor.exe).


-This is the first indication of Tor being opened and executed on the system.



2025-08-25 11:12:38 (UTC)

-A network connection was established from tor.exe (in the Desktop Tor Browser directory).


-Remote IP: 37.120.178.238


-Port: 9001 (a known Tor network port).


-Action: ConnectionSuccess


-This confirms the Tor client successfully connected to the Tor network.


-Additional connections over port 443 were also observed, consistent with Tor relays or encrypted traffic.



2025-08-25 11:34:09 (UTC)

-A file named tor-shopping-list.txt was created on the Desktop.


-Suggests the user saved some personal note or data related to Tor usage.

---

## Summary

On August 25, 2025, user stwlab1 on device st-mde-vm downloaded and executed the Tor Browser installer (tor-browser-windows-x86_64-portable-14.5.6.exe). The installer was executed in silent mode, resulting in Tor being installed on the user’s Desktop. Within minutes, the user launched Tor Browser (firefox.exe/tor.exe), which successfully established a network connection to the Tor network over port 9001 to IP address 37.120.178.238. Later, the user created a text file named tor-shopping-list.txt, indicating some personal activity tied to Tor usage. This timeline shows a full progression from download → installation → execution → network use → user file creation, confirming that Tor Browser was intentionally installed and actively used on the system.

---

## Response Taken

TOR usage was confirmed on endpoint St-MDE-VM by the user stwlab1. The device was isolated and the user's direct manager was notified.

---
