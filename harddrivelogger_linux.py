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
        print("Stopping auditing /home...")
    else:
        print("Error occured when tried to stop auditting /home: ",result.stderr)


def audit_function(stop_flag, queue : multiprocessing.Queue):
    log = []

    audit_process : subprocess.Popen = subprocess.Popen(["tail","-f","/var/log/audit/audit.log"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

    current_event = ""
    for line in audit_process.stdout: #type: ignore (idk why is this line shows an error because it actually works perfectly fine)
        if stop_flag.is_set():
            return
        
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
                        queue.put(transaction)
            else:
                print("Error! ",audit_intepreter.stderr)