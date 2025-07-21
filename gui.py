import asyncio
import sys

from PySide6 import QtAsyncio
from PySide6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem

from stun_server import StunServer
from stun_server_test import is_link_ip, StunServerTest
from ui.main import Ui_MainWindow


class MainWindow(Ui_MainWindow):
    def __init__(self):
        self.tasks = set()
        self.main_window = QMainWindow()
        self.setupUi(self.main_window)
        self.pushButton.clicked.connect(lambda: self.create_task(self.check_nat()))

        self.headers = ['server', 'type', 'result', 'response']
        self.tableWidget.setColumnCount(len(self.headers))
        self.tableWidget.setHorizontalHeaderLabels(self.headers)

    def create_task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def show(self):
        self.main_window.show()

    def add_row(self, row: dict):
        row_count = self.tableWidget.rowCount()
        self.tableWidget.setRowCount(row_count + 1)
        for key, value in row.items():
            self.tableWidget.setItem(row_count, self.headers.index(key), QTableWidgetItem(str(value)))
        self.tableWidget.resizeColumnsToContents()

    async def check_nat(self):
        self.tableWidget.setRowCount(0)
        server1 = StunServer('stun.t-online.de')
        server2 = StunServer('stun.1und1.de')

        test1_s1 = StunServerTest(server1)
        await asyncio.to_thread(test1_s1.test)
        self.add_row(test1_s1.get_dict())
        if not test1_s1.result:
            self.statusbar.showMessage('UDP blocked!')
            return

        test2_s1 = StunServerTest(server1, 'ip+port')
        await asyncio.to_thread(test2_s1.test)
        self.add_row(test2_s1.get_dict())
        if is_link_ip(test1_s1.response_host):
            if test2_s1.result:
                self.statusbar.showMessage('Open Internet!')
            else:
                self.statusbar.showMessage('Symmetric Firewall!')
            return
        if test2_s1.result:
            self.statusbar.showMessage('NAT 1, Endpoint-Independent NAT, Full Cone NAT!')
            return

        test1_s2 = StunServerTest(server2)
        await asyncio.to_thread(test1_s2.test)
        self.add_row(test1_s2.get_dict())
        if test1_s1.response_host != test1_s2.response_host:
            self.statusbar.showMessage('NAT 4, Symmetric NAT!')
            return

        test3_s1 = StunServerTest(server1, 'port')
        await asyncio.to_thread(test3_s1.test)
        self.add_row(test3_s1.get_dict())
        if test3_s1.result:
            self.statusbar.showMessage('NAT 2, Address-Dependent NAT, Restricted Cone NAT!')
        else:
            self.statusbar.showMessage('NAT 3, Address- and Port-Dependent NAT, Port Restricted Cone NAT!')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    QtAsyncio.run(handle_sigint=True)
