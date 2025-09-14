#   =   =   =   =   =   =   =   =   =
# Hard Drive Activity Logging Library (Linux Side)
# by Artem Zinets
#
# September 13, 2025
#   =   =   =   =   =   =   =   =   =

import subprocess
import multiprocessing
import os
from playground import add_to_log as log


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
        print("Stopping auditing /home...")
    else:
        print("Error occured when tried to stop auditting /home: ",result.stderr)


def audit_function():
    audit_process : subprocess.Popen = subprocess.Popen(["tail","-f","/var/log/audit/audit.log"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

    current_event = ""
    for line in audit_process.stdout: #type: ignore (idk why is this line shows an error because it actually works perfectly fine)
        event_id : str = line.split(" ")[1].split(":")[1][0:-1]
        if current_event != event_id:
            current_event = event_id
            audit_intepreter : subprocess.CompletedProcess = subprocess.run(["sudo","ausearch","--interpret","--event",current_event],capture_output=True,text=True)
            if audit_intepreter.returncode == 0:
                transaction : dict = {}
                cancelled : bool = True
                for subline in audit_intepreter.stdout.split("\n"):
                    if len(subline) <= 0 or subline[0] == "-":
                        continue
                    header : str = subline[:subline.find(" : ")]
                    body : str = subline[subline.find(" : ")+3:]
                    
                    transaction_type : str = header[header.find("type=")+5:header.find(" msg=")]

                    timestamp : str = header[header.find("msg=audit(")+len("msg=audit("):header.rfind(":")]
                    transaction["timestamp"] = timestamp

                    transaction["event_id"] = int(event_id)
                    item_number : int = 0
                    if transaction_type == "PROCTITLE":
                        transaction["executable"] = body[body.find("=")+1:-1]
                        cancelled = False
                    elif transaction_type == "PATH":
                        cancelled = False
                        if int(body[body.find("item=")+5:body.find("name=")]) < item_number:
                            continue
                        item_number = int(body[body.find("item=")+5:body.find("name=")])
                        transaction["process_accessed_path"] = body[body.find("name=")+5:body.find("inode=")-1]
                    elif transaction_type == "SYSCALL":
                        cancelled = False
                        transaction["syscall"] = body[body.find("syscall=")+8:body.find("success=")-1]
                        transaction["success"] = body[body.find("success=")+8:body.find("exit=")-1]
                        transaction["kernel_return"] = body[body.find("exit=")+5:body.find("a0=")-1]
                        transaction["arguments"] = body[body.find("a0="):body.find("items=")-1]
                        transaction["user_id"] = body[body.find(" uid=")+5:body.find("gid=")-1]
                        transaction["authed_user_id"] = body[body.find("auid=")+5:body.find(" uid=")]
                        transaction["process_id"] = int(body[body.find(" pid=")+5:body.find("auid=")-1])
                
                if not cancelled:
                    if not (transaction["executable"][:transaction["executable"].find("--event")] == "sudo ausearch --interpret "):
                        log(transaction)
                        print(transaction)
                        print()
            else:
                print("Error! ",audit_intepreter.stderr)




start_monitoring()
auditter = multiprocessing.Process(target=audit_function)
auditter.start()
auditter.join(15) # DO NOT CTRL+C THE PROGRAM
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