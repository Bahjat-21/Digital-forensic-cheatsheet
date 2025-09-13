# Digital-forensic-cheatsheet
This cheatsheet contains essential commands for DFIR (Digital Forensics and Incident Response) analysis, covering memory forensics, disk analysis, timelines, and artifact extraction.

#  Table of Contents

- [DF Cheatsheet – Grep & Strings](#df-cheatsheet--grep--strings)
- [DF Cheatsheet – Volatility 2 & 3](#df-cheatsheet--volatility-2--3)
  - [Volatility 2](#volatility-2)
  - [Volatility 3](#volatility-3)
- [DF Cheatsheet – Autopsy](#df-cheatsheet--autopsy)
- [DF Cheatsheet – Sleuth Kit (TSK)](#df-cheatsheet--sleuth-kit-tsk)
- [DF Cheatsheet – Plaso / Log2Timeline](#df-cheatsheet--plaso--log2timeline)
- [DF Cheatsheet – Bulk Extractor](#df-cheatsheet--bulk-extractor)
- [DF Cheatsheet – Disk Imaging & Duplication](#df-cheatsheet--disk-imaging--duplication)
- [DF Cheatsheet – File & Filesystem Analysis](#df-cheatsheet--file--filesystem-analysis)
- [DF Cheatsheet – Linux Forensics](#df-cheatsheet--linux-forensics)
  - [Live Response](#live-response)
  - [Processes & Memory](#processes--memory)
  - [Networking](#networking)
  - [Users & Logins](#users--logins)
  - [Logs & Persistence](#logs--persistence)
  - [Rootkit Detection](#rootkit-detection)
- [DF Cheatsheet – Windows Live Response](#df-cheatsheet--windows-live-response)
  - [System Info](#system-info)
  - [Processes & Services](#processes--services)
  - [Networking](#networking-1)
  - [Users & Logins](#users--logins-1)
  - [Persistence & Startup](#persistence--startup)
  - [Sysinternals Suite](#sysinternals-suite-must-be-downloaded)
  - [IR Frameworks](#ir-frameworks)
- [DF Cheatsheet – Windows Post-Mortem Forensics](#df-cheatsheet--windows-post-mortem-forensics)
  - [File System & Metadata](#file-system--metadata)
  - [Registry Hives](#registry-hives)
  - [Event Logs](#event-logs)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Prefetch](#prefetch)
  - [Jump Lists](#jump-lists)
  - [Shadow Copies](#shadow-copies)
  - [Other Useful Locations](#other-useful-locations)
- [DF Cheatsheet – Memory Acquisition](#df-cheatsheet--memory-acquisition)
- [DF Cheatsheet – Memory Analysis](#df-cheatsheet--memory-analysis)
- [DF Cheatsheet – Application Forensics](#df-cheatsheet--application-forensics)
  - [Web Browsers](#web-browsers)
  - [Email](#email)
  - [Office Files](#office-files)
  - [Chat & Messaging](#chat--messaging)
  - [VPN & Logs](#vpn--logs)
  - [Anti-Forensics](#anti-forensics)


---
#  DF Cheatsheet – Grep & Strings

- `grep "keyword" file.txt`  
  Search for keyword in a file.

- `grep -i "keyword" file.txt`  
  Case-insensitive search.

- `grep -r "keyword" /path/`  
  Recursive search in directory.

- `grep -n "keyword" file.txt`  
  Show line numbers.

- `grep -A 5 -B 5 "keyword" file.txt`  
  Show 5 lines after and before the match.

- `grep -E "regex1|regex2" file.txt`  
  Use extended regex.

- `grep -v "pattern" file.txt`  
  Invert match (exclude pattern).

- `grep -c "keyword" file.txt`  
  Count number of matches.

- `zgrep "keyword" file.gz`  
  Search inside compressed files.

---

- `strings disk.img`  
  Extract printable strings from a binary file or image.

- `strings -n 8 file.bin`  
  Only show strings with a minimum length (8 chars).

- `strings -t d file.bin`  
  Print offset in decimal.

- `strings -t x file.bin`  
  Print offset in hexadecimal.

- `strings -e l file.bin`  
  Interpret as 16-bit little-endian.

- `strings -a memory.dump`  
  Scan the entire file, not just loaded sections.  

 Useful for:  
- Extracting suspicious URLs, IP addresses  
- Finding registry keys in Windows hives  
- Detecting embedded shellcode

#  DF Cheatsheet – Volatility 2 & 3

## Volatility 2
- `volatility -f memory.img imageinfo`  
  Identify profile (OS version) of the memory image.

- `volatility -f memory.img --profile=Win7SP1x64 pslist`  
  List processes.

- `volatility -f memory.img --profile=Win7SP1x64 pstree`  
  Show process tree.

- `volatility -f memory.img --profile=Win7SP1x64 netscan`  
  List network connections.

- `volatility -f memory.img --profile=Win7SP1x64 connscan`  
  Scan for network connections.

- `volatility -f memory.img --profile=Win7SP1x64 sockets`  
  List open sockets.

- `volatility -f memory.img --profile=Win7SP1x64 handles`  
  List open handles.

- `volatility -f memory.img --profile=Win7SP1x64 dlllist -p <PID>`  
  List DLLs loaded by a process.

- `volatility -f memory.img --profile=Win7SP1x64 malfind`  
  Detect injected code in memory.

- `volatility -f memory.img --profile=Win7SP1x64 dumpfiles -Q <offset> -D output/`  
  Dump file from memory.

- `volatility -f memory.img --profile=Win7SP1x64 hivelist`  
  Locate registry hives in memory.

- `volatility -f memory.img --profile=Win7SP1x64 hashdump`  
  Extract password hashes.

- `volatility -f memory.img --profile=Win7SP1x64 timeliner`  
  Generate a forensic timeline.

---

## Volatility 3
- `vol.py -f memory.img windows.info`  
  Get basic OS and memory info.

- `vol.py -f memory.img windows.pslist`  
  List processes.

- `vol.py -f memory.img windows.pstree`  
  Process tree.

- `vol.py -f memory.img windows.netscan`  
  Network connections.

- `vol.py -f memory.img windows.dlllist --pid <PID>`  
  DLLs for a given process.

- `vol.py -f memory.img windows.vadyarascan --yara-rule "rule dummy { strings: $a = { 6A 40 68 00 30 00 00 } condition: $a }"`  
  YARA scan on memory image.

- `vol.py -f memory.img windows.hashdump`  
  Dump NTLM hashes from registry.

- `vol.py -f memory.img timeliner`  
  Create a timeline of events.

#  DF Cheatsheet – Autopsy

- `autopsy`  
  Start Autopsy (runs a local web server on port 9999).  

 Access in your browser:  
http://localhost:9999/autopsy  

Autopsy provides:  
- File system analysis  
- Timeline analysis  
- Keyword search  
- Hash set comparison  
- Email and web artifact analysis

#  DF Cheatsheet – Sleuth Kit (TSK)

## File System Layer
- `fsstat`  
  Display all details associated with a file system.

## File Name Layer
- `ffind`  
  Find unallocated and allocated file names that point to specific metadata.
- `fls`  
  List directory names (including deleted files).

## Metadata Layer
- `icat`  
  Extract data units from a file using metadata address instead of filename.
- `ifind`  
  Find metadata structure for a given file name or related pointer.
- `ils`  
  List metadata structures and their content.
- `istat`  
  Display statistics (MAC times, size, etc.) of metadata structures.

## Data Unit Layer
- `blkcat`  
  Extract and display contents of a data unit.
- `blkls`  
  List details of data units, including allocation status.
- `blkstats`  
  Display statistics for data units.
- `blkcalc`  
  Calculate where unallocated space data resides on the image.

## File System Journal Layer
- `jcat`  
  Display information of a journal block.
- `jls`  
  List entries for a file system journal.

## Volume System Layer
- `mmls`  
  Display disk layout and partition organization.
- `mmstat`  
  Show information on the volume system.
- `mmcat`  
  Extract contents from a partition.

---

## Image File Layer
- `img_stat`  
  Display details of an image file (size, byte range, split format).
- `img_cat`  
  Output raw contents of image files.

## Disk Tools Layer
- `disk_sreset`  
  Remove Host Protected Areas (HPA) if they exist.
- `disk_stat`  
  Display whether HPAs exist on an image.

## Automated Tools
- `tsk_comparedir`  
  Compare local directories with images/raw devices (detect rootkits hiding files).
- `tsk_gettimes`  
  Extract metadata for `mactime` to create forensic timelines.
- `tsk_loaddb`  
  Save volume, image, and metadata to an SQLite database for further analysis.
- `tsk_recover`  
  Extract unallocated and allocated files from an image into a local directory.

## Miscellaneous
- `hfind`  
  Compare hashes with a hash database (MD5/SHA1).
- `mactime`  
  Create a timeline for file activity.
- `sorter`  
  Sort files by type, check extensions, and perform hash lookups.
- `sigfind`  
  Find binary signatures in a dataset.
---
- `fls -r -f ntfs image.dd`  
  List all files recursively from an NTFS image.

- `fls -m / image.dd > bodyfile.txt`  
  Create bodyfile for timeline analysis.

- `mactime -b bodyfile.txt > timeline.txt`  
  Generate timeline from bodyfile.

- `icat image.dd <inode>`  
  Extract file by inode number.

- `istat image.dd <inode>`  
  Show metadata about a file (MAC times, size, etc.).

- `fsstat image.dd`  
  Display file system details.

- `ffind image.dd filename.txt`  
  Find inode of a file by name.

- `tsk_recover -e image.dd recovered/`  
  Extract files from a disk image into a directory.

- `tsk_recover -e image.dd output/`  
  Recover all files from image.

#  DF Cheatsheet – Plaso / Log2Timeline

- `log2timeline.py timeline.dump image.dd`  
  Create a Plaso storage file (timeline.dump) from an image.

- `psort.py -o L2tcsv timeline.dump > timeline.csv`  
  Convert Plaso storage file into CSV format.

- `pinfo.py timeline.dump`  
  Show info about the Plaso storage file.

- `log2timeline.py --parsers win7 -f mount_point/ timeline.dump`  
  Use specific parser for Windows 7 artifacts.  

 Common artifacts parsed:  
- Browser history  
- Event logs  
- Registry keys  
- Prefetch files  
- File system timestamps

#  DF Cheatsheet – Bulk Extractor

- `bulk_extractor -o output_dir image.dd`  
  Run bulk_extractor on disk image, results go into output_dir.

- `bulk_extractor -o output_dir -R /path/to/subdir image.dd`  
  Focus scan on a specific subdirectory of the image.

- `bulk_extractor -o output_dir -E email image.dd`  
  Extract only emails.

- `bulk_extractor -o output_dir -E url image.dd`  
  Extract only URLs.

- `bulk_extractor -o output_dir -E ccns image.dd`  
  Extract only credit card numbers.  

 Results are saved as text files (`email.txt`, `url.txt`, etc.) in output_dir.

 #  DF Cheatsheet – Disk Imaging & Duplication
- `mmls -i list windowsxp.dd`  
  Show partition layout of a disk image.

- `mount -t ntfs-3g -o ro,loop,noexec,show_sys_files,streams_interface=windows,offset=$((51*512)) windowsxp.dd /mnt/windows_mount/`  
  Mount an NTFS partition from a disk image in **read-only mode**, with support for Alternate Data Streams (ADS).

- `umount /mnt/windows_mount/`  
  Safely unmount the forensic mount point.

- `dd if=/dev/sda of=disk.img bs=4M conv=noerror,sync`  
  Create a raw disk image.

- `dc3dd if=/dev/sda of=disk.img hash=md5 log=logfile.txt`  
  Forensic imaging with integrated hashing.

- `ewfacquire -t case1.E01 /dev/sda`  
  Acquire forensic image in EnCase EWF format.

- `xmount --in ewf evidence.E01 --out raw /mnt/evidence`  
  Convert and mount forensic images.

- `md5sum disk.img` / `sha256sum disk.img`  
  Generate hash values for verification.

- `gpg --gen-key`  
  Generate GPG keypair (for signing).

- `gpg --detach-sign disk.img`  
  Create detached signature of image.

- `gpg --verify disk.img.sig disk.img`  
  Verify integrity of signed image.

- `dcfldd if=windowsxp.dd bs=512 skip=51 count=256224 of=filesystem.dd`  
  Extract a specific partition from a disk image using `dcfldd`.  
  - `if=windowsxp.dd` → input image  
  - `bs=512` → block size (sector size)  
  - `skip=51` → skip first 51 sectors (partition offset)  
  - `count=256224` → number of sectors to copy  
  - `of=filesystem.dd` → output partition image  

#  DF Cheatsheet – File & Filesystem Analysis

- `fdisk -l`  
  List partitions on a disk.

- `mount -o ro,loop image.dd /mnt/forensic`  
  Mount a disk image read-only for analysis.

- `file suspicious.bin`  
  Identify file type using magic numbers.

- `strings suspicious.bin | less`  
  Extract printable strings from a binary.

- `xxd file.bin | less`  
  Hex dump of a file.

- `stat file.txt`  
  Show detailed file metadata (MAC times, size, inode).

- `touch -t 202201010101 file.txt`  
  Manipulate file timestamps.

- `timestomp C:\\ -r`  
  (Meterpreter) Reset MAC times for antiforensics.

---

### Useful Filesystem Commands
- `ls -l`  
  List files with metadata.

- `ls -i`  
  Show inode numbers.

- `df -h`  
  Show mounted filesystems.

- `du -sh *`  
  Show disk usage per directory.

- `find / -type f -name "*.docx"`  
  Search files by type or name.

#  DF Cheatsheet – Linux Forensics

##  Live Response
- `date -u`  
  Show current system time in UTC.

- `uptime`  
  Display system uptime and load averages.

- `dmesg | less`  
  Show kernel ring buffer (boot/system messages).

- `cat /proc/cpuinfo`  
  Show CPU details.

- `cat /proc/meminfo`  
  Show memory information.

---

##  Processes & Memory
- `ps aux`  
  List running processes.

- `top`  
  Show real-time process usage.

- `lsof -nP`  
  List open files and network connections.

- `cat /proc/<PID>/maps`  
  Show memory mappings of a process.

- `cat /proc/<PID>/cmdline`  
  Show process command-line arguments.

---

##  Networking
- `ifconfig -a`  
  Show network interfaces and IP addresses.

- `ip addr show`  
  Show IP addresses (newer command).

- `arp -vn`  
  Display ARP cache.

- `netstat -tulpen`  
  Show active connections and listening ports.

- `ss -tulpen`  
  Replacement for netstat (faster).

- `iptables -L -n -v`  
  Show firewall rules.

---

##  Users & Logins
- `who`  
  Show logged-in users.

- `w`  
  Show logged-in users with activity.

- `last`  
  Show login history.

- `id <username>`  
  Show UID, GID, and groups of a user.

- `cat /etc/passwd`  
  List user accounts.

- `cat /etc/shadow`  
  Show password hashes (root only).

---

##  Logs & Persistence
- `ls -l /var/log/`  
  List system log files.

- `less /var/log/auth.log`  
  Check authentication logs.

- `less /var/log/syslog`  
  General system log.

- `systemctl list-unit-files --type=service`  
  Show installed services.

- `chkconfig --list`  
  Show startup services (older systems).

---

##  Rootkit Detection
- `lsmod`  
  List loaded kernel modules.

- `chkrootkit`  
  Run chkrootkit rootkit detection tool.

- `rkhunter --check`  
  Run Rootkit Hunter.

#  DF Cheatsheet – Windows Live Response

##  System Info
- `systeminfo`  
  Display OS version and patch level.

- `wmic qfe list`  
  Show installed hotfixes.

- `hostname`  
  Display system hostname.

---

##  Processes & Services
- `tasklist`  
  List running processes.

- `tasklist /svc`  
  Show processes with associated services.

- `sc query`  
  Query running services.

- `wmic process list full`  
  Detailed process list.

---

##  Networking
- `ipconfig /all`  
  Show IP configuration.

- `netstat -ano`  
  List active connections with PIDs.

- `arp -a`  
  Show ARP cache.

- `route print`  
  Display routing table.

---

##  Users & Logins
- `query user`  
  Show logged-in users.

- `net user`  
  List local user accounts.

- `net localgroup administrators`  
  Show local administrators.

- `whoami /all`  
  Show current user privileges.

---

##  Persistence & Startup
- `wmic startup get caption,command`  
  List auto-start programs.

- `schtasks /query /fo LIST /v`  
  List scheduled tasks.

---

##  Sysinternals Suite (must be downloaded)
- `PsExec.exe \\target cmd`  
  Run remote command.

- `PsList.exe`  
  List processes.

- `PsLoggedOn.exe`  
  Show logged-on users.

- `PsService.exe`  
  Query and control services.

---

##  IR Frameworks
- **KAPE** (Kroll Artifact Parser and Extractor)  
  Collect artifacts quickly from live systems.

- **Velociraptor**  
  Endpoint visibility and collection tool.

#  DF Cheatsheet – Windows Post-Mortem Forensics

##  File System & Metadata
- `fsutil usn readjournal c:`  
  Read the NTFS change journal.

- `dir /r`  
  Show alternate data streams (ADS).

---

##  Registry Hives
- `reg save HKLM\\SAM sam.save`  
  Export SAM hive.

- `reg save HKLM\\SYSTEM system.save`  
  Export SYSTEM hive.

- `reg save HKLM\\SECURITY security.save`  
  Export SECURITY hive.

- `reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`  
  Check auto-start entries.

---

##  Event Logs
- `wevtutil el`  
  List all event logs.

- `wevtutil qe Security /c:10 /f:text /q:*`  
  Export 10 recent security events.

---

##  Scheduled Tasks
- `schtasks /query /fo LIST /v`  
  List scheduled tasks.

---

##  Prefetch
- `dir C:\\Windows\\Prefetch`  
  Show prefetch files.

---

##  Jump Lists
- `%AppData%\\Microsoft\\Windows\\Recent\\AutomaticDestinations`  
  Location of automatic Jump Lists.

- `%AppData%\\Microsoft\\Windows\\Recent\\CustomDestinations`  
  Location of custom Jump Lists.

---

##  Shadow Copies
- `vssadmin list shadows`  
  List shadow copies.

- `vssadmin list providers`  
  Show VSS providers.

---

##  Other Useful Locations
- `%SystemRoot%\\System32\\winevt\\Logs\\`  
  Event log storage.

- `%SystemRoot%\\Prefetch\\`  
  Prefetch directory.

- `%UserProfile%\\NTUSER.DAT`  
  User registry hive.

#  DF Cheatsheet – Memory Acquisition

- `dd if=/dev/fmem of=/mnt/mem.dd bs=4096 conv=noerror,sync`  
  Acquire a memory dump on Linux using the fmem kernel module.

- `insmod ./lime.ko "path=/mnt/memdump.lime format=lime"`  
  Load LiME kernel module to dump memory in LiME format.

- `winpmem.exe --output memdump.raw`  
  Acquire physical memory on Windows with WinPmem.

- `DumpIt.exe`  
  Create a complete memory dump on Windows (simple double-click tool).

- `avml memory.lime`  
  Acquire volatile memory on Linux using AVML (Azure tool).

- `Belkasoft RAM Capturer`  
  Windows GUI tool for memory acquisition.

- `osforensics.exe /acquirememory memdump.bin`  
  Acquire memory with OSForensics tool.

- `powercfg /h on`  
  Enable hibernation file (hiberfil.sys) for later forensic extraction.

- `copy C:\\hiberfil.sys D:\\case\\hiberfil.sys`  
  Copy Windows hibernation file for analysis.

- `strings pagefile.sys | less`  
  Extract readable text from Windows pagefile.sys (swap file).

- `dd if=/dev/sda2 of=swapfile.dd bs=4M`  
  Copy Linux swap partition for analysis.

#  DF Cheatsheet – Memory Analysis

- `strings memdump.raw | grep "password"`  
  Search memory dump for passwords.

- `bulk_extractor -o output_dir memdump.raw`  
  Extract features (URLs, emails, credit cards) from memory.

- `yara -r rules.yar memdump.raw`  
  Scan memory with YARA rules.

- `volatility -f memdump.raw imageinfo`  
  Identify profile of memory dump.

- `volatility -f memdump.raw --profile=Win7SP1x64 pslist`  
  List processes.

- `volatility -f memdump.raw netscan`  
  Show active network connections.

- `rekall -f memdump.raw pslist`  
  Analyze memory dump with Rekall.

- `redline.exe`  
  Use Redline (FireEye) for advanced memory and IOC analysis.

- `memprocfs.exe -device memdump.raw -forensic 1`  
  Mount memory dump as a virtual filesystem (MemProcFS).

#  DF Cheatsheet – Application Forensics

##  Web Browsers
- `sqlite3 places.sqlite "SELECT url, datetime(visit_date/1000000,'unixepoch') FROM moz_places;"`  
  Extract Firefox history.

- `sqlite3 History "SELECT url, title, last_visit_time FROM urls;"`  
  Extract Chrome history.

- `sqlite3 Cookies "SELECT host_key, name, value FROM cookies;"`  
  Extract stored browser cookies.

---

##  Email
- `cat Inbox.mbox | grep "From:"`  
  Extract sender information from mbox files.

- `strings outlook.pst | grep "@domain.com"`  
  Extract emails from Outlook PST file.

---

##  Office Files
- `exiftool report.docx`  
  Extract metadata from Office documents.

- `strings document.docx | grep "Confidential"`  
  Search inside Office files for keywords.

---

##  Chat & Messaging
- `sqlite3 main.db "SELECT author, text, datetime(timestamp/1000,'unixepoch') FROM messages;"`  
  Extract Skype chat history.

- `strings msgstore.db | grep "text"`  
  Extract WhatsApp messages from backup.

---

##  VPN & Logs
- `cat /var/log/openvpn.log`  
  Check OpenVPN logs.

- `Get-WinEvent -LogName "Application" | ? Message -match "VPN"`  
  Search Windows event logs for VPN entries.

---

##  Anti-Forensics
- Look for anomalies like:  
  - Deleted browser history  
  - Cleared logs  
  - Timestamp manipulation (timestomping)  
  - Encrypted containers (VeraCrypt, BitLocker)
