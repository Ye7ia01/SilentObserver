from PyQt5.QtWidgets import QMainWindow , QApplication , QAction , QMessageBox
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import Window
import sys
import Recon

class MainWindow(QMainWindow):

    def __init__(self):
        QMainWindow.__init__(self)

        self.setWindowTitle("Silent Observer")
        self.setWindowIcon(QIcon('silent_observer2.png'))
        self.setGeometry(400,200,1100,700)
        self.setFixedSize(1100,700)

        self.form_widget = Window.Window()


        self.setCentralWidget(self.form_widget)


        p = QPalette()
        p.setColor(QPalette.Background,Qt.white)
        self.setAutoFillBackground(True)
        self.setPalette(p)

        menubar = self.menuBar()
        file = menubar.addMenu('file')
        edit = menubar.addMenu('edit')

        help = menubar.addMenu('help')

        open = QAction('open',self)
        save = QAction('save',self)
        exit = QAction('exit',self)
        manual = QAction('guide',self)
        sniff = QAction('how to sniff',self)
        file.addAction(open)
        file.addAction(save)
        file.addAction(exit)
        help.addAction(manual)
        help.addAction(sniff)
        self.show()


    def closeEvent(self, event):

        """print "exiting"

        close = QMessageBox()
        close.setText("You sure?")
        close.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)


        if close == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()"""


        self.form_widget.stop_capture()
        QMessageBox.about(self, "Title", "Quit The Silent Observer ? ")


app = QApplication(sys.argv)

window = MainWindow()
app.exec_()


