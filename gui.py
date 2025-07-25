import asyncio
import sys

from PySide6 import QtAsyncio
from PySide6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem

from stun_server_test import check_nat
from ui.main import Ui_MainWindow


class MainWindow(Ui_MainWindow):
    def __init__(self):
        self.tasks = set()
        self.main_window = QMainWindow()
        self.setupUi(self.main_window)
        self.pushButton.clicked.connect(lambda: self.create_task(self.check_nat_ui()))

        self.headers = ['server', 'type', 'result', 'response', 'local']
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

    async def check_nat_ui(self):
        self.tableWidget.setRowCount(0)
        async for response in check_nat():
            if 'result' in response:
                self.statusbar.showMessage(response['result'])
            if 'test' in response:
                self.add_row(response['test'].get_dict())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    QtAsyncio.run(handle_sigint=True)
