from etw import ProviderInfo, GUID, ETW
import time
import threading
import queue
import datetime

def windows_highres_timestamp_to_datetime(wintime):
    return datetime.datetime.fromtimestamp((wintime - 116444736000000000)/10000000)



def on_file_event(event):
    try:
        logs.put({
            "timestamp": windows_highres_timestamp_to_datetime(int(event[1]["EventHeader"]["TimeStamp"])).isoformat(),
            "pid": event[1]["EventHeader"]["ProcessId"],
            "operation": event[1]["Task Name"],
            "filename": event[1]["FileName"]
        })
    except Exception:
        pass

logs = queue.Queue()
etw_session = ETW(
    providers=[ProviderInfo("Microsoft-Windows-Kernel-File", GUID("{EDD08927-9CC4-4E65-B970-C2560FB5C289}"))],
    event_callback=on_file_event
)

def run_thread():
    etw_session.start()   # this blocks forever until stop() is called
    print("Start complete")

def stop_thread():
    etw_session.stop()
    print("Stop complete")

"""
print("Starting")
starter = threading.Thread(target=run_thread, daemon=True)
starter.start()

# Let it run
try:
    while True:
        pass
except KeyboardInterrupt:
    pass

print("Stopping")
stopper = threading.Thread(target=stop_thread, daemon=True)
stopper.start()

print("Fetching logs.")
# Drain the queue
while not logs.empty(): 
    print(logs.get())

print("Done")
"""