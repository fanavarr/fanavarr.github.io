---
layout: post
title:  Detecting Windows Procesess Injection 
date:   2022-05-12 13:30:00
tags:
- Windows
- DFIR
---


One of the big topics on almost any Threat Hunting course material is Process Injection detection, hence I have decided to write this post as a quick and
dirty "how to". I will not go over the definition of what process injection is or the types that could be executed on a system, because  really awesome posts
already exist. [elastic](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process).


### Memhunter

[Memhunter](https:/github.com/marcosd4h/memhunter), It detects known malicious memory injection techniques and the detection process is performed through live analysis without needing memory dumps. Simply download the tool and execute it by running ```memhunter.exe -r```. This will try to detect all techniques, but if you want to test for a specific one, use ```memhunter.exe -r -m X```,  where X is the technique listed under ```memhunter.exe -h```
<br/>


### Hollow's Hunter

It basically allows you to scan multiple processes at once and search for evil, it can be downloaded [here](https://github.com/hasherezade/hollows_hunter),
and like Memhunter, it is quite easy to use ```hollows_hunter.exe /hooks```, Howllows Hunter has some nice features which can be enabled with simple "flags"
at execution, more of this on the tool [Wiki](https://github.com/hasherezade/hollows_hunter/wiki)
<br/>

### The Captain

The [Captain](https://github.com/y3n11/Captain) is a powershell script created to monitor new processes in search for malicious events through API hooking,
just open powershell as admin and run the following:
``` .\Monitor.ps1 ```
Once the process is started, it will catch up any malicious activity coming in. Also, it will create a log directory under ```C:\ProgramData\Captain
\Reporting```.

