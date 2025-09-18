import platform
import multiprocessing
import threading
import sys
import os
import ctypes

from PySide6.QtWidgets import QApplication, QTableView, QMessageBox
from PySide6.QtGui import QStandardItemModel, QStandardItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QTimer

import harddrivelogger_linux
import harddrivelogger_windows
import packetsniffer
#   =   =   =   =   =   =   =   =   =
# Rajang Activity Monitor Main File
# by Artem Zinets & Ella Sooley
#
# September 14, 2025
#   =   =   =   =   =   =   =   =   =
def main():
    print("main call")
    # Check for admin/root
    if platform.system() == "Linux":
        if os.geteuid() != 0: #type: ignore
            app = QApplication(sys.argv)
            msg = QMessageBox()
            msg.setWindowTitle("Access Error")
            msg.setText("This program must be run as root")
            msg.exec()
            sys.exit(1)
    elif platform.system() == "Windows":
        admin_check = False
        try:
            admin_check = ctypes.windll.shell32.IsUserAnAdmin() != 0 #type: ignore
        except Exception:
            admin_check = False
        if not admin_check:
            app = QApplication(sys.argv)
            msg = QMessageBox()
            msg.setWindowTitle("Access Error")
            msg.setText("This program must be run as admin")
            msg.exec()
            sys.exit(1)


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
    elif platform.system() == "Windows":
        starter = threading.Thread(target=harddrivelogger_windows.run_thread, daemon=True)
        starter.start()

    # Set up internet monitoring
    packetsniffer_stop_flag = multiprocessing.Event()
    packetsniffer_queue = multiprocessing.Queue()
    packetsniffer_thread = multiprocessing.Process(target=packetsniffer.loop,args=(packetsniffer_stop_flag,packetsniffer_queue))
    packetsniffer_thread.start()

    # Display UI
    ui_loader : QUiLoader = QUiLoader()
    main_ui_file : QFile
    try:
        main_ui_file = QFile(os.path.join(sys._MEIPASS,"main.ui")) #type: ignore
    except Exception:
        main_ui_file = QFile(os.path.join(os.path.abspath("."),"main.ui"))

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
    if platform.system() == "Linux":
        disk_activity_table_model.setHorizontalHeaderLabels(["Time","Event ID","Executable","Operation (syscall #)","Result (kernel return)","UserID","Authorized User (AUID)","Process ID"])
    elif platform.system() == "Windows":
        disk_activity_table_model.setHorizontalHeaderLabels(["Time","PID","Operation","Filename"])
    disk_activity_table.setModel(disk_activity_table_model)

    # Setup the internet activity table
    internet_activity_table = window.findChild(QTableView,"internetActivityTable")
    assert internet_activity_table is not None
    internet_activity_table_model = QStandardItemModel()
    internet_activity_table_model.setHorizontalHeaderLabels(["Time","Protocol","Process ID","Source","Destination","Direction","Location","!DNS"])
    internet_activity_table.setModel(internet_activity_table_model)

    # Setup the log checker thread and start it
    def ui_log_refresh():
        if platform.system() == "Linux":
            while True:
                try:
                    hdl_entry = auditter_queue.get_nowait()
                    hdl_row = []
                    for item in [hdl_entry["timestamp"],hdl_entry["event_id"],hdl_entry["executable"],hdl_entry["syscall"],hdl_entry["kernel_return"],hdl_entry["user_id"],hdl_entry["authed_user_id"],hdl_entry["process_id"]]:
                        hdl_row.append(QStandardItem(str(item)))
                    disk_activity_table_model.insertRow(0,hdl_row)
                except Exception:
                    break
        else:
            while True:
                try:
                    hdl_entry = harddrivelogger_windows.logs.get_nowait()
                    hdl_row = []
                    for item in ["timestamp","pid","operation","filename"]:
                        hdl_row.append(QStandardItem(str(hdl_entry[item])))
                    disk_activity_table_model.insertRow(0,hdl_row)
                except Exception:
                    break
        while True:
            try:
                net_entry = packetsniffer_queue.get_nowait()
                net_row = []
                for item in ["timestamp","protocol","pid","origin","destination","direction","geolocation","url_lookup"]:
                    if item == "origin" or item == "destination":
                        net_row.append(QStandardItem(str(net_entry[item][0])+":"+str(net_entry[item][1])))
                    else:
                        net_row.append(QStandardItem(str(net_entry[item])))
                internet_activity_table_model.insertRow(0,net_row)
            except Exception:
                break
    timer = QTimer() # This timer will run every 100 ms and update the GUI
    timer.timeout.connect(ui_log_refresh)
    timer.start(100)

    app.exec()

    timer.stop()
    try:
        auditter_stop_flag.set()
        auditter.join(5)
        harddrivelogger_linux.stop_monitoring()
    except Exception:
        pass
    packetsniffer_stop_flag.set()
    packetsniffer_thread.join(5)

    print("Done")
    sys.exit(0)

print("Program Start")
if __name__ == "__main__":
    print("__name__ == __main__")
    main()