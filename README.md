# Digital-forensic-cheatsheet
###  Digital Forensics Commands

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

---

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
