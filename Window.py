from PyQt5.QtWidgets import QWidget, QPushButton , QHBoxLayout , QLineEdit , QVBoxLayout, QRadioButton , QLabel , QScrollArea , QTableWidget , QTableWidgetItem , QMessageBox
from PyQt5.QtGui import  QIcon , QPalette
from PyQt5.QtCore import *
import Recon
import threading



class Window(QWidget):

    Device = ""
    stop = False
    info = []
    flag = 0
    det = []
    container = QVBoxLayout()
    details = QVBoxLayout()
    currnet = 0
    http_header = ""
    stopped_before = False


    def __init__(self):

        QWidget.__init__(self)

        self.window()


    def window(self):

        about = QHBoxLayout()

        devices = Recon.find_devs()

        p = QPalette()
        p.setColor(QPalette.Background,Qt.lightGray)


        p2 = QPalette()
        p2.setColor(QPalette.Background,Qt.darkRed)

        capture = QPushButton('')
        capture.setIcon(QIcon('silent_observer.png'))
        capture.setDisabled(True)
        capture.setPalette(p2)

        capture.clicked.connect(lambda: self.capture(self.Device,stop,filter.text(),packets,save,capture))



        stop = QPushButton('')
        stop.setPalette(p2)

        stop.clicked.connect(self.stop_capture)
        stop.setIcon(QIcon('pause3.png'))
        stop.setDisabled(True)

        open = QPushButton()
        open.setIcon(QIcon('file.png'))
        open.setPalette(p2)

        save = QPushButton("")
        save.setIcon(QIcon('save2.png'))
        save.setPalette(p2)
        save.setDisabled(True)
        save.clicked.connect( lambda :self.save(file_name))

        rb = []

        choose = QLabel('Choose An Inetrface To Sniff On : ')
        choose.setAutoFillBackground(True)
        choose.setPalette(p)
        about.addWidget(choose)
        about.addStretch()

        filter = QLineEdit('')
        filter.setAutoFillBackground(True)
        filter.setPalette(p2)





        #search.clicked.connect(lambda : self.search(self.Device,stop,search,filter.text(),packets))

        for i in range(0, len(devices)):
            rb.append(QRadioButton(devices[i]))

            about.addWidget(rb[i])
            rb[i].setWindowIcon(QIcon('_?.png'))
            rb[i].setPalette(p2)

        for i in range(0, len(devices)):
            rb[i].toggled.connect(lambda :self.set_device(capture))



        file_name = QLineEdit("File Name")

        self.container.addLayout(about)

        config = QHBoxLayout()


        config.addWidget(capture)
        config.addWidget(stop)

        config.addWidget(filter)

        config.addStretch()
        config.addWidget(save)
        config.addWidget(file_name)

        config.addStretch()
        config.addWidget(choose)



        self.container.addLayout(config)


        packets_details = QHBoxLayout()


        packets = QTableWidget()
        packets.setRowCount(20000)
        packets.setColumnCount(5)
        packets.setHorizontalHeaderItem(0, QTableWidgetItem("Details .. "))
        packets.setHorizontalHeaderItem(1, QTableWidgetItem("Source "))
        packets.setHorizontalHeaderItem(2, QTableWidgetItem("Destination "))
        packets.setHorizontalHeaderItem(3, QTableWidgetItem("Protocol"))
        packets.setHorizontalHeaderItem(4, QTableWidgetItem("length"))

        packets.itemClicked.connect(lambda row  :self.update_details(row,hex_view))


        packets_details.addWidget(packets)

        hex_view = QLabel("[*]/HEX/VIEW/[*]")
        hex_view.setAutoFillBackground(True)
        hex_view.setPalette(p)

        packets_details.addLayout(self.details)

        widget = QWidget()

        layout = QVBoxLayout(self)
        for i in range(1000):
            self.det.append(QLabel(""))
            layout.addWidget(self.det[i])
        widget.setLayout(layout)

        p3 = QPalette()
        p3.setColor(QPalette.Background, Qt.darkGreen)


        self.det[0].setText("----------------------------------------------------------------------------------------------------------------------")
        self.det[0].setAutoFillBackground(True)
        self.det[0].setPalette(p2)


        self.det[1].setText("             T / H / E  ----------  S / I / L / E / N / T  -------------   0 / B / S / E / R / V / E / R                           ")
        self.det[2].setText("----------------------------------------------------------------------------------------------------------------------")
        self.det[1].setAutoFillBackground(True)
        self.det[1].setPalette(p)

        self.det[1].setAutoFillBackground(True)
        self.det[2].setAutoFillBackground(True)
        self.det[2].setPalette(p2)

        scroll = QScrollArea()
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(False)
        scroll.setWidget(widget)

        self.details.addWidget(scroll)
        self.details.addWidget(hex_view)

        self.container.addLayout(packets_details)

        self.setLayout(self.container)



    # Functions


    def set_device(self,cap):
        rb = self.sender()
        self.Device = rb.text()
        cap.setDisabled(False)

    # Capturing Packets :


    def capture(self,device,stop,filter,packets,save,capture):
        stop.setDisabled(False)
        save.setDisabled(False)
        capture.setDisabled(True)

        if(not self.stopped_before):
            Recon.capture(device)
            self.init_get_packets(filter,packets)

        else:
            self.clear_table(packets)
            for i in self.info:
                for j in i:
                    j=""

            Recon.stop=False
            self.stop = False
            Recon.capture(device)
            self.init_get_packets(filter,packets)


    def init_get_packets(self,filter,packets):

        t = threading.Thread(target=self.get_packets,args=(filter,packets))
        t.start()


    def get_packets(self,filter,packets):
        counter = 0
        search = filter.upper()

        while True:

            packet = Recon.get_packet(counter)
            if (len(packet) == 0):

                continue
            else :

                if(filter == "" ):
                    self.info.append(packet)

                elif (search in packet):

                    self.info.append(packet)


                self.update_table(packets)

            counter += 1
            if (self.stop == True):
                return


    # -----------------------------------------------------------------------


    # Stop Capturing :


    def stop_capture(self):
        #self.stopped_before = True


        self.stop = True
        Recon.stop = True




    #-------------------------------------------------------------------------


    # Search :

    def search(self,device,stop,search,filter,packets):



        if (filter == ""):
            return


        for i in range(0,1999):
            packets.setItem(i, 0 ,QTableWidgetItem(""))

            packets.setItem(i, 1, QTableWidgetItem(""))
            packets.setItem(i, 2, QTableWidgetItem(""))
            packets.setItem(i, 3, QTableWidgetItem(""))
            packets.setItem(i, 4, QTableWidgetItem(""))

        self.capture(device,stop,search,filter,packets)

    # Packet Global Info Representation


    def update_table(self,table):



        if (len(self.info) == 0):


            """do nothing """

        else :



            for i in range(self.flag,len(self.info)):

                #table.setItem(i,0,QTableWidgetItem(str(self.info[i][0])))
                table.setItem(i, 0, QTableWidgetItem("Click"))
                table.setItem(i, 1, QTableWidgetItem(str(self.info[i][2])))
                table.setItem(i, 2, QTableWidgetItem(str(self.info[i][3])))

                if(self.info[i][3] == ""):
                    table.setItem(i, 3, QTableWidgetItem("Un-Known"))

                else:
                    table.setItem(i, 3, QTableWidgetItem(str(self.info[i][4])))


                table.setItem(i, 4, QTableWidgetItem(str(self.info[i][5])))

                self.flag = i



    def update_details(self,row,data):


        r = row.row()
        proto = self.info[r][4]

        p = QPalette()
        p.setColor(QPalette.Background, Qt.lightGray)


        frame = "[*]/Frame/[*] .... : "
        eth = "[*]/Ethernet/[*] .... : "
        ip = "[*]/IP[*] .... : "
        tcp = "[*]/TCP/[*] .... : "
        udp = "[*]/UDP/[*] .... : "
        http = "[*]/HTTP/[*] .... : "
        hex = "[*]/Hex/View/[*] .... : "
        icmp = "[*]/ICMP/[*] ....  : "
        dns = "[*]/DNS/[*] .... : "
        mdns = "[*]/MDNS/[*] ....  : "
        ntp = "[*]/NTP/[*] ....  :  "
        arp = "[*]/ARP/[*] .... : "
        ftp = "[*]/FTP/[*] .... : "
        tls = "[*]/TLS/[*] .... : "



        if(not self.stopped_before):

            self.det[4].setText(frame)
            self.det[4].setAutoFillBackground(True)
            self.det[4].setPalette(p)

            self.det[5].setText("       [ Time Caught : " + str(self.info[r][0]) + " ] ")
            self.det[6].setText("       [ Frame Size  : " + str(self.info[r][5])+ " ] ")
            self.det[7].setText("       [ Packet Number : " + str(self.info[r][1]) + " ] ")
            self.det[8].setText("       [ Interface  : " + self.Device)



            if (proto == "TCP"):
                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]) + " ] ")
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]) + " ] ")
                self.det[13].setText("      [Type             : " + str(self.info[r][7]) + " ] ")


                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]" )
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][21]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) +  " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) +  " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")


                self.det[29].setText(tcp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)

                self.det[30].setText("      [ Source Port           : " +self.info[r][22] +" ] ")
                self.det[31].setText("      [ Destination Port      : " +self.info[r][23]+ " ] ")
                self.det[32].setText("      [ Sequence Number       : " +self.info[r][24]+ " ( Real )  ] ")
                self.det[33].setText("      [ Acknowledgment Number : " +self.info[r][25]+ " ( Real )  ] ")
                self.det[34].setText("      [ Header Length         : " +self.info[r][27]+ " ] ")
                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)
                self.det[35].setText("      [ Reserved Bit          : " +self.info[r][28] +  " ] ")
                self.det[36].setText("      [ Flags                 : " +self.info[r][29] +  " ] ")
                self.det[37].setText("      [ Window Size           : " +str(self.info[r][30]) + " ] ")
                self.det[38].setText("      [ Checksum              : " +str(self.info[r][26])+ " ] ")
                self.det[39].setText("      [ Urgent Pointer        : " +str(self.info[r][31]) +  " ] ")

                self.det[41].setText("")
                self.det[41].setAutoFillBackground(False)
                self.det[41].setPalette(p)

                self.det[42].setText("")
                self.det[43].setText("")
                self.det[44].setText("")
                self.det[45].setText("")
                self.det[46].setText("")
                self.det[47].setText("")
                self.det[48].setText("")
                self.det[49].setText("")
                self.det[50].setText("")
                self.det[51].setText("")
                self.det[52].setText("")
                self.det[53].setText("")

                data.setText(str(self.info[r][32]))

            elif (proto == "UDP"):
                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][8]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setText(udp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)
                self.det[30].setText("      [ Source Port      : "+str(self.info[r][22]) + " ] ")
                self.det[31].setText("      [ Destination Port : " + str(self.info[r][23]) + " ] ")
                self.det[32].setText("      [ Total Length     : " + str(self.info[r][24]) + " ] ")
                self.det[33].setText("      [ Checksum         : " + str(self.info[r][25]) + " ] ")
                self.det[34].setText("")

                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)
                self.det[35].setText("")
                self.det[36].setText("")
                self.det[37].setText("")
                self.det[38].setText("")
                self.det[39].setText("")
                self.det[40].setText("")


                data.setText(hex + "\n" + self.info[r][25])

                self.det[41].setText("")
                self.det[41].setAutoFillBackground(False)
                self.det[41].setPalette(p)

                self.det[42].setText("")
                self.det[43].setText("")
                self.det[44].setText("")
                self.det[45].setText("")
                self.det[46].setText("")
                self.det[47].setText("")
                self.det[48].setText("")
                self.det[49].setText("")
                self.det[50].setText("")
                self.det[51].setText("")
                self.det[52].setText("")
                self.det[53].setText("")





            elif (proto == "ICMP"):

                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)
                self.det[29].setText(icmp)

                self.det[30].setText("      [  Type                   : "+ str(self.info[r][22]) + " ( " + str(self.info[r][27]) + " )    ]")
                self.det[31].setText("      [  Code                   : " + str(self.info[r][23]) + " ]")
                self.det[32].setText("      [  Checksum               : " + str(self.info[r][24]) + " ]")
                self.det[33].setText("      [  Identifier             : " + str(self.info[r][25]) + " ]")
                self.det[34].setText("      [  Sequence Number        : " + str(self.info[r][26]) + " ]")

                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)


                data.setText(hex + "\n" + self.info[r][28])

            elif (proto == "ARP"):

                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)


                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)
                self.det[15].setText(arp)
                self.det[16].setText("Protocol Not Yet Supported")

                for i in range(17,50):
                    self.det[i].setText("")

                self.det[10].setAutoFillBackground(False)
                self.det[15].setAutoFillBackground(False)
                self.det[29].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)
                self.det[41].setAutoFillBackground(False)






            elif (proto == "HTTP"):

                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))


                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")


                self.det[29].setText(tcp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)

                self.det[30].setText("      [ Source Port           : " +self.info[r][22] +" ] ")
                self.det[31].setText("      [ Destination Port      : " +self.info[r][23]+ " ] ")
                self.det[32].setText("      [ Sequence Number       : " +self.info[r][24]+ " ] ")
                self.det[33].setText("      [ Acknowledgment Number : " +self.info[r][25]+ " ] ")
                self.det[34].setText("      [ Header Length         : " +self.info[r][27]+ " ] ")
                self.det[35].setText("      [ Reserved              : " + self.info[r][28] + " ] ")
                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)
                self.det[36].setText("      [ Flags                 : " + self.info[r][29] + " ] ")
                self.det[37].setText("      [ Window                : " +str(self.info[r][30]) + " ] ")
                self.det[38].setText("      [ Checksum              : " +self.info[r][26]+ " ] ")
                self.det[39].setText("      [ Urgent                : " + str(self.info[r][31]) + " ] ")

                self.det[41].setText(http)
                self.det[41].setAutoFillBackground(True)
                self.det[41].setPalette(p)

                pos = 42
                count = 0
                for i in self.info[r][33]:
                    if ( (i=="G")  or  (i=="H" ) or (i == "P")):
                        self.det[42].setText(self.info[r][33][count:count+50])
                        self.det[43].setText(self.info[r][33][count+50:count + 100])
                        self.det[44].setText(self.info[r][33][count+100:count + 150])
                        self.det[45].setText(self.info[r][33][count+150:count + 200])
                        self.det[46].setText(self.info[r][33][count+200:count + 250])
                        self.det[47].setText(self.info[r][33][count+250:count + 300])
                        self.det[48].setText(self.info[r][33][count+300:count + 350])
                        self.det[49].setText(self.info[r][33][count+350:count + 400])
                        break

                    count+=1

                data.setText(hex + "\n" + self.info[r][32][:len(self.info[r][32])/4])




            elif (proto == "DNS"):

                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setText(udp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)
                self.det[30].setText("      [ Source Port      : " + str(self.info[r][22]) + " ] ")
                self.det[31].setText("      [ Destination Port : " + str(self.info[r][23]) + " ] ")
                self.det[32].setText("      [ Total Length     : " + str(self.info[r][24]) + " ] ")
                self.det[33].setText("      [ Checksum         : " + str(self.info[r][25]) + " ] ")
                self.det[34].setText("")

                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(True)
                self.det[36].setPalette(p)
                self.det[35].setText("")
                self.det[36].setText(dns)
                self.det[37].setText("Protocol Not Yet Supported")
                self.det[38].setText("")
                self.det[39].setText("")
                self.det[40].setText("")

                data.setText(hex + "\n" + self.info[r][26])

                self.det[41].setText("")
                self.det[41].setAutoFillBackground(False)
                self.det[41].setPalette(p)

                self.det[42].setText("")
                self.det[43].setText("")
                self.det[44].setText("")
                self.det[45].setText("")
                self.det[46].setText("")
                self.det[47].setText("")
                self.det[48].setText("")
                self.det[49].setText("")
                self.det[50].setText("")
                self.det[51].setText("")
                self.det[52].setText("")
                self.det[53].setText("")


            elif (proto == "MDNS"):
                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setText(udp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)
                self.det[30].setText("      [ Source Port      : " + str(self.info[r][22]) + " ] ")
                self.det[31].setText("      [ Destination Port : " + str(self.info[r][23]) + " ] ")
                self.det[32].setText("      [ Total Length     : " + str(self.info[r][24]) + " ] ")
                self.det[33].setText("      [ Checksum         : " + str(self.info[r][25]) + " ] ")
                self.det[34].setText("")

                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(True)
                self.det[36].setPalette(p)
                self.det[35].setText("")
                self.det[36].setText(mdns)
                self.det[37].setText("")
                self.det[38].setText("")
                self.det[39].setText("")
                self.det[40].setText("")

                data.setText(hex + "\n" + self.info[r][26])

                self.det[41].setText("")
                self.det[41].setAutoFillBackground(False)
                self.det[41].setPalette(p)

                self.det[42].setText("")
                self.det[43].setText("")
                self.det[44].setText("")
                self.det[45].setText("")
                self.det[46].setText("")
                self.det[47].setText("")
                self.det[48].setText("")
                self.det[49].setText("")
                self.det[50].setText("")
                self.det[51].setText("")
                self.det[52].setText("")
                self.det[53].setText("")


            elif (proto == "NTP"):

                self.det[10].setText("")
                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setText(udp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)
                self.det[30].setText("      [ Source Port      : " + str(self.info[r][22]) + " ] ")
                self.det[31].setText("      [ Destination Port : " + str(self.info[r][23]) + " ] ")
                self.det[32].setText("      [ Total Length     : " + str(self.info[r][24]) + " ] ")
                self.det[33].setText("      [ Checksum         : " + str(self.info[r][25]) + " ] ")
                self.det[34].setText("")

                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(True)
                self.det[36].setPalette(p)
                self.det[35].setText("")
                self.det[36].setText(ntp)
                self.det[37].setText("Protocol Not Yet Supported")
                self.det[38].setText("")
                self.det[39].setText("")
                self.det[40].setText("")

                data.setText(hex + "\n" + self.info[r][25])

                self.det[41].setText("")
                self.det[41].setAutoFillBackground(False)
                self.det[41].setPalette(p)

                self.det[42].setText("")
                self.det[43].setText("")
                self.det[44].setText("")
                self.det[45].setText("")
                self.det[46].setText("")
                self.det[47].setText("")
                self.det[48].setText("")
                self.det[49].setText("")
                self.det[50].setText("")
                self.det[51].setText("")
                self.det[52].setText("")
                self.det[53].setText("")


            elif (proto == "FTP"):

                self.det[10].setText(eth)
                self.det[10].setAutoFillBackground(True)
                self.det[10].setPalette(p)

                self.det[11].setText("      [ Destination Mac :  " + str(self.info[r][8]))
                self.det[12].setText("      [ Source Mac      :  " + str(self.info[r][9]))
                self.det[13].setText("      [Type             : " + str(self.info[r][7]))

                self.det[15].setText(ip)
                self.det[15].setAutoFillBackground(True)
                self.det[15].setPalette(p)

                self.det[16].setText("      [ Version                : " + str(self.info[r][10]) + " ]")
                self.det[17].setText("      [ Header Length          : " + str(self.info[r][11]) + " ]")
                self.det[18].setText("      [ Differentiated Service : " + str(self.info[r][19]) + " ]")
                self.det[19].setText("      [ Datagram Length        : " + str(self.info[r][12]) + " ]")
                self.det[20].setText("      [ Datagram ID            : " + str(self.info[r][13]) + " ]")
                self.det[21].setText("      [ Flags                  : " + str(self.info[r][14]) + " ]")
                self.det[22].setText("      [ Fragment Offset        : " + str(self.info[r][15]) + " ]")
                self.det[23].setText("      [ Time To Live           : " + str(self.info[r][16]) + " ]")
                self.det[24].setText("      [ Protocol               : " + str(self.info[r][17]) + " ]")
                self.det[25].setText("      [ Checksum               : " + str(self.info[r][20]) + " ]")
                self.det[26].setText("      [ Souce IP               : " + str(self.info[r][18]) + " ]")
                self.det[27].setText("      [ Destination IP         : " + str(self.info[r][19]) + " ]")

                self.det[29].setText(tcp)
                self.det[29].setAutoFillBackground(True)
                self.det[29].setPalette(p)

                self.det[30].setText("      [ Source Port           : " + str(self.info[r][22]) + " ] ")
                self.det[31].setText("      [ Destination Port      : " + str(self.info[r][23]) + " ] ")
                self.det[32].setText("      [ Sequence Number       : " + str(self.info[r][24]) + " ] ")
                self.det[33].setText("      [ Acknowledgment Number : " + str(self.info[r][25]) + " ] ")
                self.det[34].setText("      [ Header Length         : " + str(self.info[r][27]) + " ] ")
                self.det[35].setText("      [ Reserved              : " + str(self.info[r][28]) + " ] ")
                self.det[35].setAutoFillBackground(False)
                self.det[36].setAutoFillBackground(False)
                self.det[36].setText("      [ Flags                 : " + self.info[r][29] + " ] ")
                self.det[37].setText("      [ Window                : " + str(self.info[r][30]) + " ] ")
                self.det[38].setText("      [ Checksum              : " + self.info[r][26] + " ] ")
                self.det[39].setText("      [ Urgent                : " + str(self.info[r][31]) + " ] ")

                self.det[41].setText(ftp)
                self.det[41].setAutoFillBackground(True)
                self.det[41].setPalette(p)

                self.det[42].setText(self.info[r][33])

                """count = 0
                for i in self.info[r][33]:
                    if ((i == "G") or (i == "H") or (i == "P") or (i=="L") or (i=="Q") ):
                        self.det[42].setText(self.info[r][33][count:count + 50])
                        self.det[43].setText(self.info[r][33][count + 50:count + 100])
                        self.det[44].setText(self.info[r][33][count + 100:count + 150])
                        self.det[45].setText(self.info[r][33][count + 150:count + 200])
                        self.det[46].setText(self.info[r][33][count + 200:count + 250])
                        self.det[47].setText(self.info[r][33][count + 250:count + 300])
                        self.det[48].setText(self.info[r][33][count + 300:count + 350])
                        self.det[49].setText(self.info[r][33][count + 350:count + 400])
                        break
                    count+=1
                #self.det[42].setText(str(self.info[r][36]))"""

                data.setText(self.info[r][32])


            else :




                for i in range(10,50):


                    self.det[i].setText("")

                self.det[12].setText("   PROTOCOL NOT YET SUPPORTED   ")
                self.det[13].setText("   WILL BE SUPPORTED ON NEXT VERSION  ")

                self.det[10].setAutoFillBackground(False)
                self.det[15].setAutoFillBackground(False)
                self.det[29].setAutoFillBackground(False)
                self.det[41].setAutoFillBackground(False)


    def save(self,file_name):

        Recon.save(self.Device,file_name.text())
        file_name.setText("File Saved In The Silent Observer Directory")


    def clear_table(self,table):
        for i in range(0,20000):
            table.setItem(i, 0,QTableWidgetItem(""))
            table.setItem(i, 1, QTableWidgetItem(""))
            table.setItem(i, 2, QTableWidgetItem(""))
            table.setItem(i, 3, QTableWidgetItem(""))
            table.setItem(i, 4, QTableWidgetItem(""))

        for i in range(3,50):
            self.det[i].setText("")



        self.det[10].setAutoFillBackground(False)
        self.det[15].setAutoFillBackground(False)
        self.det[29].setAutoFillBackground(False)
        self.det[36].setAutoFillBackground(False)
        self.det[41].setAutoFillBackground(False)

    def closeEvent(self, QCloseEvent):

        Recon.stop = True
        QMessageBox.about(self, "Title", "Message")
        QCloseEvent.accept()












