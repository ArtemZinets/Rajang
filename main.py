import platform
import multiprocessing
import sys

from PySide6.QtWidgets import QApplication, QTableView
from PySide6.QtGui import QStandardItemModel, QStandardItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QTimer

import harddrivelogger_linux
#   =   =   =   =   =   =   =   =   =
# Rajang Activity Monitor Main File
# by Artem Zinets & Ella Sooley
#
# September 14, 2025
#   =   =   =   =   =   =   =   =   =

hdl_log_queue : list = []

#   ===============


# Set up the hard drive logger.
auditter_stop_flag = multiprocessing.Event()
auditter : multiprocessing.Process
auditter_queue : multiprocessing.Queue

if platform.system() == "Linux":
    harddrivelogger_linux.start_monitoring()
    auditter_queue = multiprocessing.Queue()
    auditter = multiprocessing.Process(target=harddrivelogger_linux.audit_function,args=(auditter_stop_flag,auditter_queue))
    auditter.start()

# Set up internet monitoring
# Waiting for Ella to finish packetsniffer.

# Display UI
ui_loader : QUiLoader = QUiLoader()
main_ui_file : QFile = QFile("./main.ui")

# Setup the app
app = QApplication(sys.argv)
window = ui_loader.load(main_ui_file)
main_ui_file.close()

# Show window
window.show()

# Setup the disk activity table
disk_activity_table = window.findChild(QTableView,"diskActivityTable")
assert disk_activity_table is not None
disk_activity_table_model = QStandardItemModel()
disk_activity_table_model.setHorizontalHeaderLabels(["Time","Event ID","Executable","Operation (syscall #)","Result (kernel return)","UserID","Authorized User (AUID)","Process ID"])
disk_activity_table.setModel(disk_activity_table_model)

# Setup the log checker thread and start it
def ui_log_refresh():
    while True:
        try:
            entry = auditter_queue.get_nowait()
            row = []
            for item in [entry["timestamp"],entry["event_id"],entry["executable"],entry["syscall"],entry["kernel_return"],entry["user_id"],entry["authed_user_id"],entry["process_id"]]:
                row.append(QStandardItem(str(item)))
            disk_activity_table_model.insertRow(0,row)
        except Exception:
            break
timer = QTimer() # This timer will run every 100 ms and update the GUI
timer.timeout.connect(ui_log_refresh)
timer.start(100)


app.exec()

timer.stop()
auditter_stop_flag.set()
auditter.join()
harddrivelogger_linux.stop_monitoring()

print("Done")