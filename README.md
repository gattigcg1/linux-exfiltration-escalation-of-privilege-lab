# Linux Exfiltration Escalation Of Privilege Lab
Incident Response lab fully created by myself - covers creating a Linux vm, creating storage container in Azure, basic linux commands, script writing, creating rules in MDE, report writing, and more. 

**Google docs covering the full lab**: https://docs.google.com/document/d/1pcssRize7ksabLfACIgAkX-AGibAjiMY9YSy28MlmuU/edit?tab=t.0

**Youtube Video of whole lab**: https://www.youtube.com/watch?v=YWhpAxc_Aco&ab_channel=GregEaster

**Scenario**: 

Company A has been noticing some PII information about employees might be getting leaked because of recent phishing attempts that have been perpetrated. Such information includes address, email address, and phone number. All of this information is stored on a linux server as a hidden file where only the root/sudo users have read and write access. There was a report by another employee the other day of a fellow employee messing with the computer while the root administrator was in the bathroom. The company has decided to investigate this. 

## Platforms and Languages Leveraged
- Ubuntu Server 22.04 LTS
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Azure Blob Storage

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

One of the things we can look for is a file creation that the attacker might have performed in the time span that the company suspects (this is naturally when you placed the “attack script” in the VM). The day in question is X. 

I used a query that searches for “FileCreated” Action type using the query below:

```kql
DeviceFileEvents
| where DeviceName contains "VM_HOST_NAME"
| where ActionType == "FileCreated"
```

Looking at the data above, a suspicious looking file called “super_secret_script.sh” was created on 2025-06-16T12:20:50.902852Z. There are two rows that have this filename, after investigating the contents we find the differences as follows:

Touch is a linux command that creates the super_secret_script.sh while nano command opens said file in the nano text editor in Linux. 

This is the first most interesting thing, but let's also look in this table and see if there’s anything else interesting. 

DeviceFileEvents
| where DeviceName contains "VM_HOST_NAME"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc

InitialProcessCommandLine gives us more insight into what effects could be had on the VM. After the command “nano super_secret_script.sh”, we see one more interesting row. “usermod -aG sudo john_smith” which is very suspicious as it gives the user John Smith sudo privileges, which is a backdoor into the system. The door is closing in! 

---

### 2. Searched the DeviceProcessEvents For Script Execution

```kql
DeviceProcessEvents
| where Timestamp >= datetime(TIME_STAMP)
| where DeviceName contains "VM_NAME"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

The date above is used to narrow down the timespan after the super_secret_script.sh was created and ordered by ascending to see events immediately after the file creation. 

As we can see from the logs, one of the first rows at 2025-06-16T12:23:17.729273Z has value “/bin/bash ./super_secret_script.sh” for the InitiatingProcessCommandLine column. /bin/bash indicates the interpreter that is used, which is bash, and the next part is “./super_secret_script.sh” which shows that the script was executed by the attacker. Shortly after, we see a bunch of commands that indicate some suspicious behavior involving using the Azure CLI. At 2025-06-16T12:23:17.734244Z, we see a command involving uploading to an Azure storage blob account (storage blob upload), using an account key and a storage account. We also checked for anything resembling the script self-deleting since an audit of the VM was done, and the exact file and its contents were not found, but could not find a record referring to this outcome in this table or the DeviceFileEvents table. 

Quick look at the DeviceNetworkEvents

Using command:

```kql
DeviceNetworkEvents
| where DeviceName contains "VM_NAME"
| where Timestamp >= datetime(TIMESTAMP)
| project Timestamp, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

We can see that we have a ConnectionRequest ActionType row involving Azure CLI blob storage, followed by a ConnectionSuccess row for the same request. 

Note: The script does not appear in the Linux VM, unfortunately I can’t find the exact row in the database that represents the script self-deleting itself (maybe it’s there! Check it out). I looked for some reference to something close to “rm -- "$0" in the DeviceProcessEvents and DeviceFileEvents table but ultimately could not find it. 

---

## 3. Chronological Event Timeline 

### 1. File creation - super_secret_script.sh

- **Timestamp:** `2025-06-16T12:20:50.902852Z`
- **Event:** The user creates a file called super_secret_script.sh through the touch command in Linux.
- **Action:** Bash script file created.
- **File Path:** `/home/gattigcg1/super_secret_script.sh`

- ### 2. Opening script and writing it. 

- **Timestamp:** `2025-06-16T12:22:51.98438Z`
- **Event:** The user creates a file called super_secret_script.sh through the touch command in Linux.
- **Action:** Bash script opened in nano editor and obviously stuff was written into it.
- **File Path:** `/home/gattigcg1/super_secret_script.sh`

### 3. Process Execution - super_secret_script.sh execution

- **Timestamp:** `2025-06-16T12:23:17.631238Z`
- **Event:** The user executes the super_secret_script.sh.
- **Action:** Process creation detected.
- **File Path:** `/home/gattigcg1/super_secret_script.sh`

### 4. Escalation of privilege - making john_smith a sudo user

- **Timestamp:** `2025-06-16T12:23:17.649853Z`
- **Event:** The script grants sudo access to john_smith user.
- **Action:** Escalation of privilege.
- **File Path:** `/home/gattigcg1/super_secret_script.sh`

### 5. Network Request to upload file to Azure Storage Account

- **Timestamp:** `2025-06-16T12:23:19.007669Z`
- **Event:** The script uploads file .my_secret_file.txt to Azure Storage account named gcgstorage12 through the Azure CLI. 
- **Action:** Exfiltration of PII data.
- **File Path:** `/home/gattigcg1/.secret_data/.my_secret_file.txt`

---

## 4. Summary

It looks like an employee gained access to the root account and installed a script. This script had 2 main functions. One function uploaded a file that contained PII information that was only previously accessible to accounts given sudo accounts to an Azure storage. The second function of the script was to give a backdoor to the actor by escalating the privilege of his account by giving his user account sudo access which would allow him to poke through the data more in the future. The script was then deleted. 

---

## 5. Response Taken

The user account that performed the exfiltration of data has been suspended temporarily awaiting further direction by management. The sudo privileges of this account were also removed just in case. This report was provided to the employee’s manager and upper management for further direction. 

