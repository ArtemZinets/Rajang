# Overview
**Rajang** (named after an elephant; elephants are known for their superior olfactory receptors) is a program that logs internet activity and hard disk activity on a specific machine.
Made by Artem Zinets and Ella Sooley (@ErnestServal)

# Features
Two main features are:
- Displaying log entries that relate to a process reading/writing to a file on a hard drive (to track worm viruses, reading of session keys, reading of password manager files etc)
- Displaying log entries that relate to an internet packet (TCP/UDP/Etc) exchange (sending/receiving) (to track stealer viruses, botnet client viruses etc)

All this functionality is shipped as a Python program with a Qt-powered UI

# Dependencies
To use internet packet sniffing functionality, you must install [Npcap](https://npcap.com/#download) **if you are running Windows** or [libpcap](https://github.com/the-tcpdump-group/libpcap) **if you are running Linux** (do `sudo apt-get install libpcap-dev`)

To use disk monitoring, you must install [???](???) **if you are using Windows** or [auditd](???) **if you are running Linux** (do `sudo apt-get install auditd`)

# Credit
- Artem Zinets (@ArtemZinets): hard drive logger functions
- Ella Sooley (@ErnestServal): internet packet logger functions
