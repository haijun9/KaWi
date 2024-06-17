import os, sys
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtWidgets
from PyQt5.QtCore import QTimer

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *
from scapy.consts import LINUX, WINDOWS
import cli, sniff

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

form = resource_path('main_GUI.ui')
form_Sniffer = uic.loadUiType(form)[0]

class MainWindow(QMainWindow, form_Sniffer):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.initUI()
        self.setWindowTitle("KaWi")
        self.show()

    def initial_setup(self):
        self.runButton.setEnabled(False)
        header = self.NetworkList.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        sniff.lookup_iface()
        for idx in range(len(sniff.iface_list)):
            iface = sniff.iface_list[idx]
            row_position = self.NetworkList.rowCount()
            self.NetworkList.insertRow(row_position)
            self.NetworkList.setItem(row_position, 0, QTableWidgetItem(f'{idx}'))
            self.NetworkList.setItem(row_position, 1, QTableWidgetItem(f'{iface.name}'))
            self.NetworkList.setItem(row_position, 2, QTableWidgetItem(f'{iface.description}'))
            self.NetworkList.setItem(row_position, 3, QTableWidgetItem(f'{iface.mac}'))

    def set_interface(self):
        managed_num = self.managed_Num.value()
        monitor_num = self.monitor_Num.value()
        if managed_num not in range(len(sniff.iface_list)) or monitor_num not in range(len(sniff.iface_list)):
            QMessageBox.information(self, "KaWi", "Invalid interface number.")
            return

        if sniff.set_two_ifaces_to_use(managed_num, monitor_num, sniff.iface_list):
            QMessageBox.information(self, "KaWi", "Setup was successful.")
        else:
            QMessageBox.information(self, "KaWi", "Setup failed.")
            return

        self.managed_Num.setEnabled(False)
        self.monitor_Num.setEnabled(False)
        self.setInterfaceButton.setEnabled(False)
        self.runButton.setEnabled(True)
        self.commands.clear()
        self.commands.append(r"""
        --------------------------------------------------------------------------------------------------------
            ██╗░░██╗░█████╗░░██╗░░░░░░░██╗██╗
            ██║░██╔╝██╔══██╗░██║░░██╗░░██║██║
            █████═╝░███████║░╚██╗████╗██╔╝██║
            ██╔═██╗░██╔══██║░░████╔═████║░██║
            ██║░╚██╗██║░░██║░░╚██╔╝░╚██╔╝░██║
            ╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝
           (Simple prototype GUI for Wi-Fi analysis tool)
        --------------------------------------------------------------------------------------------------------
        """)

    def runCommand(self):
        command = self.command.currentIndex()
        if command == 0: # Reset network interface to use
            self.managed_Num.setEnabled(True)
            self.monitor_Num.setEnabled(True)
            self.setInterfaceButton.setEnabled(True)
            self.runButton.setEnabled(False)

            self.commands.clear()
            self.commands.append("Please Reset Network Interface")
        elif command == 1: # List nearby WiFi networks
            self.commands.clear()

            channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
            iface = sniff.iface_monitor
            self.commands.append("[monitor] Start passive scan(from beacon frame)...\n")
            for n in channels:
                # Sequential channel switching - Stays for 1 second on each channel
                current_channel = n
                self.commands.append(f"[monitor] Current channel: {n}")
                if not sniff.set_channel(n, iface):
                    self.commands.append("Cannot change channel. First you need to switch your iface to monitor mode.")
                # 비콘 프레임은 보통 100ms마다 송신되기 때문에 timeout=0.1~0.2여도 충분할 것 같다.
                # sniff(iface=iface, monitor=True, timeout=0.5, prn=sniff.handle_scan_AP, store=0)

            self.commands.append("\n[monitor] Done.")
            self.commands.append("\n\n*Network information you are connected to:")
            self.commands.append(f"{sniff.connected_network}")
        elif command == 2: # Collect IP and MAC addresses of all hosts(AP and client)
            cli.handle_command("2")
        elif command == 3: # (not perfect)Send deauth frames(force disconnect the target client from the network)
            return
        elif command == 4: # (not yet supported)Create a Rogue AP
            return
        elif command == 5: # (not yet supported)Test KRACK - 4-way handshake reinstall PTK-TK(used to encrypt data frames)
            return
        elif command == 6: # (not yet supported)Test KRACK - 4-way handshake reinstall GTK(used to encrypt broadcast and multicast frames)
            return
        elif command == 7: # (not yet supported)Test KRACK - 4-way handshake reinstall IGTK(used to encrypt broadcast and multicast frames)
            return


    # Upper Lines are Making
    def initUI(self):
        self.initial_setup()
        self.setInterfaceButton.clicked.connect(self.set_interface)
        self.runButton.clicked.connect(self.runCommand)
    # Lower Lines are Sample Codes

    def toggleProgress(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if isinstance(sender, QPushButton):  # 발생시킨 위젯이 QPushButton이면
            self.progress_value = 0
            if sender.objectName() == "Spoof_toggleButton":
                self.Spoof_timer.start(100)
                if sender.text() == "Start":
                    self.Spoof_Info.clear()
                    sender.setText("Stop")
                else:
                    self.Spoof_timer.stop()
                    sender.setText("Start")

            elif sender.objectName() == "KRACK_toggleButton":
                self.KRACK_timer.start(100)

                if sender.text() == "Start":
                    self.KRACK_Info.clear()
                    sender.setText("Stop")
                    self.radio_Replay_Broadcast.setEnabled(False)
                    self.radio_Test_GTK.setEnabled(False)
                    self.radio_Test_KRACK.setEnabled(False)
                    self.radio_KRACK_Attack.setEnabled(False)
                    self.radio_Entire.setEnabled(False)

                    if self.radio_Replay_Broadcast.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Replay_Broadcast")
                    if self.radio_Test_GTK.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Test_GTK")
                    elif self.radio_Test_KRACK.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Test_KRACK")
                    elif self.radio_KRACK_Attack.isChecked():
                        QMessageBox.information(self, "Radio", "radio_KRACK_Attack")
                    elif self.radio_Entire.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Entire")

                else:
                    sender.setText("Start")
                    self.KRACK_timer.stop()
                    self.radio_Replay_Broadcast.setEnabled(True)
                    self.radio_Test_GTK.setEnabled(True)
                    self.radio_Test_KRACK.setEnabled(True)
                    self.radio_KRACK_Attack.setEnabled(True)
                    self.radio_Entire.setEnabled(True)

    def Spoof_updateProgress(self):
        self.progress_value += 1
        if self.progress_value > 100:
            self.Spoof_timer.stop()
            self.Spoof_toggleButton.setText("Start")
            QMessageBox.information(self, "Spoofing", "작업 완료")
            return
        self.Spoof_Info.append(f'{self.progress_value}')
        self.Spoof_pBar.setValue(self.progress_value)

    def KRACK_updateProgress(self):
        self.progress_value += 1
        if self.progress_value > 100:
            self.KRACK_timer.stop()
            self.KRACK_toggleButton.setText("Start")
            self.radio_Replay_Broadcast.setEnabled(True)
            self.radio_Test_GTK.setEnabled(True)
            self.radio_Test_KRACK.setEnabled(True)
            self.radio_KRACK_Attack.setEnabled(True)
            self.radio_Entire.setEnabled(True)
            QMessageBox.information(self, "KRACK", "작업 완료")
            return
        self.KRACK_Info.append(f'{self.progress_value}')
        self.KRACK_pBar.setValue(self.progress_value)

    def handleButtonClick(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if isinstance(sender, QCheckBox):  # 발생시킨 위젯이 QCheckBox이면
            if sender.isChecked():
                QMessageBox.information(self, "Checkbox Checked", f"{sender.text()} 체크박스 선택")
            else:
                QMessageBox.information(self, "Checkbox Unchecked", f"{sender.text()} 체크박스 해제")
        elif isinstance(sender, QPushButton):  # 발생시킨 위젯이 QPushButton이면
            if sender.text() == "Start":
                QMessageBox.information(self, "Start", "시작 버튼 선택")
                sender.setText("Stop")
            else:
                QMessageBox.information(self, "Stop", "정지 버튼 선택")
                sender.setText("Start")

    def move_to_next_tab(self):
        current_index = self.tabs.currentIndex()
        next_index = (current_index + 1) % self.tabs.count()
        self.tabs.setCurrentIndex(next_index)

    def on_row_selected(self):
        selected_indexes = self.captured_packets.selectionModel().selectedIndexes()
        if selected_indexes:
            selected_row = selected_indexes[0].row()
            QMessageBox.information(self, "Packet", f"{selected_row}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MainWindow()
    sys.exit(app.exec_())
