#   =   =   =   =   =   =   =   =   =
# Hard Drive Activity Logging Library (Linux Side)
# by Artem Zinets
#
# September 13, 2025
#   =   =   =   =   =   =   =   =   =

import subprocess
import multiprocessing
import time

def start_monitoring():
    print("start_monitoring call")
    result : subprocess.CompletedProcess = subprocess.run(["sudo","auditctl","-w","/home","-p","rwx"],capture_output=True,text=True)
    if result.returncode == 0:
        print("Starting auditing /home...")
    else:
        print("Error occured when tried to audit /home: ",result.stderr)

def stop_monitoring():
    print("stop_monitoring call")
    result : subprocess.CompletedProcess = subprocess.run(["sudo","auditctl","-W","/home","-p","rwx"],capture_output=True,text=True)
    if result.returncode == 0:
        print("Stopping auditing /home...")
    else:
        print("Error occured when tried to stop auditing /home: ",result.stderr)

def parse_file_operation_log_line(line : str):
    pass

def audit_function():
    audit_process : subprocess.Popen = subprocess.Popen(["tail","-f","/var/log/audit/audit.log"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    for line in audit_process.stdout: #type: ignore (idk why is this line shows an error because it actually works perfectly fine)
        parse_file_operation_log_line("""type=SYSCALL msg=audit(1757779819.283:1110): arch=c000003e syscall=83 success=no exit=-17 a0=7649cec46888 a1=1ed a2=1ed a3=b41e7f items=1 ppid=2126 pid=2130 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=4 comm=4267494F5468727E6F6C2023313434 exe="/app/lib/firefox/firefox-bin" subj=flatpak key=(null)ARCH=x86_64 SYSCALL=mkdir AUID="st2005" UID="st2005" GID="st2005" EUID="st2005" SUID="st2005" FSUID="st2005" EGID="st2005" SGID="st2005" FSGID="st2005""""")


start_monitoring()
auditter = multiprocessing.Process(target=audit_function)
auditter.start()
auditter.join(15) # DO NOT CTRL+C THE PROGRAM
auditter.terminate()
stop_monitoring()