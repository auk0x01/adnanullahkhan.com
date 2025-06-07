---
title: Malbuster - TryHackme Writeup
date: 2023-02-09 10:03
categories: [ctf, reversing]
tags: [tryhackme, reversing, ctf, malbuster]    # TAG names should be lowercase
---

# Intro

Hi folks, today we will solve Malbuster room from [Tryhackme](https://tryhackme.com). Malbuster is 
basic room for malware analysis. Static analysis is a prerequisite to complete this room. Let's start

# Scenario

We are working as a Malware reverse engineer for a company.
Our SOC team has detected some malicious samples and want us
to identify and analyse these samples.

You have two options for machine deployment in this room. 
Either you can deploy FLARE VM (Windows) or you can go with
RemNux VM (Linux). I am gonna solve by deploying RemNux VM here, it's up to you what you chose.

You can also RDP to machines using following creds:
Username    administrator
Password	letmein123!
IP Address	MACHINE_IP

ALL MALWARE SAMPLES ARE PRESENT ON THE DESKTOP ON BOTH OF THE INSTANCES.

# Challenge Questions: 

## **Question#1** ##

1) *Based on the ARCHITECTURE of the binary, is malbuster_1 a 32-bit or a 64-bit application? (32-bit/64-bit)*

We can check details of any binary from *file* utlity present on linux systems.

**Command:**

```
file malbuster_1
```

**Output:**

```
malbuster_1: PE32 executable (GUI) Intel 80386, for MS Windows
```

Upon checking *malbuster_1* we come to know that it is 32-bit Portable Executable (PE) file.

*Note: PE is a file format used for most of the Windows executables.*

## **Question#2** ##

2) *What is the MD5 hash of malbuster_1?*

We can generate md5 hash of any file with the help of *md5sum* by using following command:

```
md5sum <FILE>
```
Upon generating md5 hash of *malbuster_1* binary, we have our answer.

## **Question#3** ##

3) *Using the hash, what is the number of detections of malbuster_1 in VirusTotal?*

Virustotal [https://virustotal.com](https://virustotal.com) is an online platform which lets you upload files/hashes/urls and scans your files/hashes/urls through multiple antivirus programs to see if any antivirus program has already identified this malware.

Let's upload the hash which we generated in previous question on virustotal.

![img](https://i.imgur.com/TNtK96k.png)

We can see that there are 51 number of detections on virustotal for this executable.

## **Question#4** ##

4) *Based on VirusTotal detection, what is the malware signature of malbuster_2 according to Avira?*

Okay now, let's upload the hash of *malbuster_2* on virustotal.

Scrolled down a bit and got the malware signature according to Avira.

![img](https://i.imgur.com/OPfBwJc.png)

## **Question#5** ##

5) *malbuster_2 imports the function _CorExeMain. From which DLL file does it import this function?*

We can see list of DLLs and its imported functions on Virustotal too.

VirusTotal shows all imported DLLs and functions on *DETAILS* tab.

![img](https://i.imgur.com/iZhlA56.png)

We can see from which DLL *malbuster_2* is importing *_CorExeMain* function.

## **Question#6** ##

6) *Based on the VS_VERSION_INFO header, what is the original name of malbuster_2?*

We can also see alternative names for this executable on virustotal. Below are the names which Virustotal detected for this executable. 

Tryhackme answer requires 5-digit name for the executable so the answer is obvious.

![img](https://i.imgur.com/vTzqDMH.png)

## **Question#7** ##

7) *Using the hash of malbuster_3, what is its malware signature based on abuse.ch?*

abuse.ch is also a online platform containing malware database where you can search for malware samples using hashes or malware family.

Generated md5 hash of *malbuster_3* and uploaded it here:
[https://bazaar.abuse.ch/browse/](https://bazaar.abuse.ch/browse/)

Upon searching on abuse.ch, I found malware signature for *malbuster_3*.

![img](https://i.imgur.com/8Av161p.png)

## **Question#8** ##

8) *Using the hash of malbuster_4, what is its malware signature based on abuse.ch?*

Using the same techniques as *malbuster_3*, found malware signature for malbuster_4 on abuse.ch.

## **Question#9** ##

9) *What is the message found in the DOS_STUB of malbuster_4?*

DOS_STUB is a small piece of code present in PE files located in the header of PE files. The DOS_STUB program runs when file is executed on older systems. This program can also be edited by malware developers to hide some info.

We can check the contents of DOS_STUB program through *strings* utlity.

**Command:**

```
strings malbuster_4
```

Upon checking strings content of malbuster_4, we have message present on first lines.

## **Question#10** ##

10) *malbuster_4 imports the function ShellExecuteA. From which DLL file does it import this function?*

At this point, we know that we can see list of DLLs and its imported functions on [https://virustotal.com](https://virustotal.com).

VirusTotal shows all imported DLLs and functions on *DETAILS* tab.

We can see from which DLL *malbuster_4* is importing *ShellExecuteA* function.

## **Question#11** ##

11) *Using capa, how many anti-VM instructions were identified in malbuster_1?*

***capa*** is an online tool to identify capabilities in executable files.

*Note: capa is already installed on the VM we are working on.*

**Syntax to use capa:**
```
capa <SAMPLE TO ANALYZE>
```

Upon analyzing malbuster_1 with capa, we can clearly see the number of anti-VM strings present on the executable.

![img](https://i.imgur.com/9kAQHlG.png)

## **Question#12** ##

12) *Using capa, which binary can log keystrokes?*

Running *capa* on every executable and grepping "log" keyword gave the answer.

## **Question#13** ##

13) *Using capa, what is the MITRE ID of the DISCOVERY technique used by malbuster_4?*

Again running *capa* on malbuster_4 gave the MITRE id of the Discovery technique used by the executable.

## **Question#14** ##

14) *Which binary contains the string GodMode?*

With the help of *strings* utility, we can see all strings present on the executable. Grepping the output for "GodMode" gave the answer.

## **Question#15** ##

15) *Which binary contains the string Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)?*

Again repeating the previous process of finding string "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" got us the answer.





Thankyou for Reading
