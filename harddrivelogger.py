#   =   =   =   =   =   =   =   =   =
# Hard Drive Activity Logging Library (Linux Side)
# by Artem Zinets
#
# September 13, 2025
#   =   =   =   =   =   =   =   =   =

import subprocess
import multiprocessing
import os


def start_monitoring():
    print("start_monitoring call")
    result : subprocess.CompletedProcess = subprocess.run("sudo auditctl -a always,exit -F dir=/home -F perm=rwx".split(" "),capture_output=True,text=True)
    if result.returncode == 0:
        print("Starting auditing /home...")
    else:
        print("Error occured when tried to audit /home: ",result.stderr)


def stop_monitoring():
    print("stop_monitoring call")
    result : subprocess.CompletedProcess = subprocess.run("sudo auditctl -d always,exit -F dir=/home -F perm=rwx".split(" "),capture_output=True,text=True)
    if result.returncode == 0:
        print("Starting auditing /home...")
    else:
        print("Error occured when tried to audit /home: ",result.stderr)


def audit_function():
    audit_process : subprocess.Popen = subprocess.Popen(["tail","-f","/var/log/audit/audit.log"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

    current_event = ""
    for line in audit_process.stdout: #type: ignore (idk why is this line shows an error because it actually works perfectly fine)
        event_id : str = line.split(" ")[1].split(":")[1][0:-1]
        if current_event != event_id:
            print()
            print(" ".join(["sudo","ausearch","--intepret","--event",current_event]))
            current_event = event_id
            audit_intepreter : subprocess.CompletedProcess = subprocess.run(["sudo","ausearch","--interpret","--event",current_event],capture_output=True,text=True)
            if audit_intepreter.returncode == 0:
                print(audit_intepreter.stdout)
                
                
                transaction : dict = {}
                for subline in audit_intepreter.stdout.split("\n"):
                    if len(subline) <= 0 or subline[0] == "-":
                        continue
                    header : str = subline[:subline.find(" : ")]
                    body : str = subline[subline.find(" : ")+3:]
                    
                    transaction_type : str = header[header.find("type=")+5:header.find(" msg=")]
                    transaction["type"] = transaction_type

                    timestamp : str = header[header.find("msg=audit(")+len("msg=audit("):header.rfind(":")]
                    transaction["timestamp"] = timestamp

                    transaction["event_id"] = event_id

                    if transaction_type == "PROCTITLE":
                        transaction["proctitle"] = body[body.find("=")+1:]
                    if transaction_type == "PATH":
                        pass 
            else:
                print("Error! ",audit_intepreter.stderr)




start_monitoring()
auditter = multiprocessing.Process(target=audit_function)
auditter.start()
auditter.join(5) # DO NOT CTRL+C THE PROGRAM
auditter.terminate()
stop_monitoring()


"""
['sudo', 'ausearch', '--intepret', '--event', '12964']
----
type=PROCTITLE msg=audit(2025-09-13 19:39:23.239:12964) : proctitle=sudo ausearch --interpret --event 12911 
type=PATH msg=audit(2025-09-13 19:39:23.239:12964) : item=1 name=/home/st2005/.sudo_as_admin_successful inode=1082102 dev=103:05 mode=file,644 ouid=st2005 ogid=st2005 rdev=00:00 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
type=PATH msg=audit(2025-09-13 19:39:23.239:12964) : item=0 name=/home/st2005/ inode=1048579 dev=103:05 mode=dir,750 ouid=st2005 ogid=st2005 rdev=00:00 nametype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
type=CWD msg=audit(2025-09-13 19:39:23.239:12964) : cwd=/home/st2005/Documents/Rajang/Rajang 
type=SYSCALL msg=audit(2025-09-13 19:39:23.239:12964) : arch=x86_64 syscall=openat success=no exit=EEXIST(File exists) a0=AT_FDCWD a1=0x5a4be23d6440 a2=O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK a3=0x1a4 items=2 ppid=31838 pid=31861 auid=st2005 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts6 ses=4 comm=sudo exe=/usr/bin/sudo subj=vscode key=(null) 
"""

"""
sudo ausearch --intepret --event 28603
----
type=PROCTITLE msg=audit(2025-09-14 09:46:01.103:28604) : proctitle=/usr/bin/nemo 
type=PATH msg=audit(2025-09-14 09:46:01.103:28604) : item=0 name=/home/st2005/.local/share/icons/hicolor/64x64/apps inode=2103116 dev=103:05 mode=dir,775 ouid=st2005 ogid=st2005 rdev=00:00 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
type=CWD msg=audit(2025-09-14 09:46:01.103:28604) : cwd=/home/st2005 
type=SYSCALL msg=audit(2025-09-14 09:46:01.103:28604) : arch=x86_64 syscall=openat success=yes exit=14 a0=AT_FDCWD a1=0x5b9a95ffa950 a2=O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC a3=0x0 items=1 ppid=1445 pid=50337 auid=st2005 uid=st2005 gid=st2005 euid=st2005 suid=st2005 fsuid=st2005 egid=st2005 sgid=st2005 fsgid=st2005 tty=(none) ses=4 comm=nemo exe=/usr/bin/nemo subj=unconfined key=(null) 
"""