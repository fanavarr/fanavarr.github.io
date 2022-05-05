---
layout: post
title:  Normal Core Windows Procesess 
date:   2022-04-20 15:30:00
tags:
- Windows
- DFIR
---



One of the most important things for detection is getting to know the windows processes, Windows does have a lot of processes which are present every time we boot a machine, when reviewing a possible compromised host process, we should ask the following questions:


 - Are the processes signed?
 - Are they names spelled correctly?
 - Are they running out of the expected path?
 - Are they running under the proper SID?
 - Does it have the expected parent process?
 - How many instances should exist?
    
Hence it becomes a must to have information available about the normal behavior of this processes like for example number of instances that should be running, parent process path, etc.
Any anomaly on this parameter should immediately call our attention.

Let’s review some of the windows core processes:

## Local Security Authority Subsystem (lsass.exe)
It is responsible for the windows authentication and manages the creation of security tokens for AD, NetLogon and SAM, also writes the security event log.

    Parent Process: wininit.exe
    User / Owner: NT AUTHORITY\SYSTEM (S-1-5-18)
    Path: %Systemroot%\system32\lsass.exe
    Number of instances: 1
    Child Processes: None
    Base Priority: 9
    

## Generic Service Host Process (svchost.exe)
Responsible for hosting multiple services DLLs into generic shared service process, it should never exist without the “-k <name>” argument.

    Parent Process: services.exe
    User / Owner: NT AUTHORITY\SYSTEM (S-1-5-18), NT AUTHORITY\LOCAL SERVICE(S-1-5-19), NT AUTHORITY\NETWORK SERVICE(S-1-5-20)
    Path: %Systemroot%\system32\ svchost.exe
    Number of instances: Multiple
    Child Processes: Multiple
    Base Priority: 8

  
## Session Manager (smss.exe)
It creates new sessions, also it creates the list of environments variables. 
Session 0 starts csrss.exe and wininit.exe which are OS services; Session 1 starts csrss.exe and winlogon.exe which are under User Session.
  
    Parent Process: System
    User / Owner: NT AUTHORITY\SYSTEM (S-1-5-18)
    Path: %Systemroot%\system32\ smss.exe
    Number of instances: Multiple, but only one without arguments after booting up
    Child Processes: SMSS.EXE (Session 0), SMSS.EXE (Session 1), AUTOCHK.EXE and a new SMSS.EXE instance for each new session
    Base Priority: 11

  
## Client Server Run Subsystem Process (csrss.exe)
Responsible for managing process and threads, as well as making windows API available for processes.
It also creates temp files, map drive letters and handles the shutdown process, it will be available for each newly user session and runs on Session 0 and 1.

    Parent Process: Orphan process (Parent was the SMSS.EXE child process of the master SMSS.EXE)
    User / Owner: NT AUTHORITY\SYSTEM (S-1-5-18)
    Path: %Systemroot%\system32\ csrss.exe
    Number of instances: typically, 2 instances.
    Child Processes: None
    Base Priority: 13


## Windows Logon Process (Winlogon.exe)
Responsible for user logons and logoffs. 
It launches LogonUI.exe for users to input credentials and then passes it to lsass.exe for AD / SAM verification. 
  
    Parent Process: Orphan process (Parent was the SMSS.EXE child process with session > 0)
    User / Owner: NT AUTHORITY\SYSTEM (S-1-5-18)
    Path: %Systemroot%\system32\ winlogon.exe
    Number of instances: 1 per user session
    Child Processes: “LogonUI.exe”, “userinit.exe”, “dwm.exe”, “fontdrvhost.exe” and anything else listed in the “Userinit” value
    Base Priority: 13

  
  
