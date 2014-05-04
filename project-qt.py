import sys
import urllib2
from bs4 import BeautifulSoup
import os
import re
from PyQt4.QtCore import *
from PyQt4 import QtGui 
from PyQt4.QtGui import *


class AnalyzerWindow(QtGui.QWidget):
    
    def __init__(self):
        super(AnalyzerWindow, self).__init__()
        
        self.initUI()
        
    def initUI(self):       
        
        # Menu action - exit 
        exitAction = QtGui.QAction(QtGui.QIcon('images/exit.png'), '&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit Application')
        exitAction.triggered.connect(QtGui.qApp.quit)

        # Menu action - about
        aboutAction = QtGui.QAction(QtGui.QIcon('images/icon64.png'), '&About', self)
        aboutAction.setShortcut('Ctrl+A')
        aboutAction.setStatusTip('About Amrita Malware Advertisement Analyzer')
        aboutAction.triggered.connect(self.aboutDialog)

        menubar = QtGui.QMenuBar(self)
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(exitAction)
        helpMenu = menubar.addMenu('&Help')
        helpMenu.addAction(aboutAction)
        
        # Label
        self.label = QtGui.QLabel(self.tr('Url to analyze:'), self)

        # Lineedit 
        self.urlInput = QtGui.QLineEdit(self)
        self.urlInput.setMaximumWidth(290)
        self.urlInput.setFixedWidth(300)
        self.urlInput.setMaximumHeight(40)
        self.urlInput.setFixedHeight(30)
        self.label.setBuddy(self.urlInput)

        # Button 
        self.btn = QtGui.QPushButton(self.tr('&Click To Execute'), self) 
        self.btn.setMaximumHeight(30)
        self.btn.setFixedHeight(30)
        self.btn.setMaximumWidth(120)
        self.btn.setFixedWidth(130)
        self.btn.setCursor(QCursor(Qt.PointingHandCursor))
        
        # Style for the button
        """
        self.btn.setStyleSheet('QPushButton { margin: 1px;' \
                'border-color: #6BC260;' \
                'border-style: outset;' \
                'border-radius: 3px;' \
                'border-width: 0.2px;' \
                'color: white;' \
                'font-weight: bold;' \
                'background-color: #6BC260;' \
                '}' \
                'QPushButton:hover {' \
                'background-color: #0BC260;' \
                '}')
        """
        # Layout for the input field
        self.inputLayout = QtGui.QHBoxLayout()
        self.inputLayout.addWidget(self.label)
        self.inputLayout.addWidget(self.urlInput)
        self.inputLayout.addWidget(self.btn)

        # Security Status
        self.securityStatusLabel = QtGui.QLabel(self.tr('Result:'), self)
        self.securityStatusLine = QtGui.QLineEdit(self)
        self.securityStatusLine.setMaximumWidth(430)
        self.securityStatusLine.setFixedWidth(435)
        self.securityStatusLine.setMaximumHeight(40)
        self.securityStatusLine.setFixedHeight(30)
        self.securityStatusLine.setReadOnly(True)
        self.securityStatusLabel.setBuddy(self.securityStatusLine)
        
        # Layout for security status
        self.securityStatusLayout = QtGui.QHBoxLayout()
        self.securityStatusLayout.addWidget(self.securityStatusLabel)
        self.securityStatusLayout.addWidget(self.securityStatusLine)

        # Frame count display
        self.frameCountLabel = QtGui.QLabel(self.tr('Frame Count:'), self)
        self.frameCountLine = QtGui.QLineEdit(self)
        self.frameCountLine.setMaximumHeight(40)
        self.frameCountLine.setFixedHeight(30)
        self.frameCountLine.setMaximumWidth(160)
        self.frameCountLine.setFixedWidth(175)
        self.frameCountLine.setReadOnly(True)
        self.frameCountLine.setAlignment(Qt.AlignLeft)
        self.frameCountLabel.setBuddy(self.frameCountLine)
       
        # White space details
        self.whitespaceLabel = QtGui.QLabel(self.tr('White Spaces:'), self)
        self.whitespaceLine = QtGui.QLineEdit(self)
        self.whitespaceLine.setMaximumWidth(170)
        self.whitespaceLine.setFixedWidth(183)
        self.whitespaceLine.setMaximumHeight(40)
        self.whitespaceLine.setFixedHeight(30)
        self.whitespaceLine.setReadOnly(True)
        self.whitespaceLine.setAlignment(Qt.AlignLeft)
        self.whitespaceLabel.setBuddy(self.whitespaceLine)
        
        # Layout for the white space count display
        self.whiteFrameLayout = QtGui.QHBoxLayout()
        self.whiteFrameLayout.addWidget(self.whitespaceLabel)
        self.whiteFrameLayout.addWidget(self.whitespaceLine)
        self.whiteFrameLayout.addWidget(self.frameCountLabel)
        self.whiteFrameLayout.addWidget(self.frameCountLine)
        
        # Escape function count
        self.escapeLabel = QtGui.QLabel(self.tr('Escape Fun:'), self)
        self.escapeLine = QtGui.QLineEdit(self)
        self.escapeLine.setMaximumWidth(160)
        self.escapeLine.setFixedWidth(183)
        self.escapeLine.setMaximumHeight(25)
        self.escapeLine.setFixedHeight(30)
        self.escapeLine.setReadOnly(True)
        self.escapeLine.setAlignment(Qt.AlignLeft)
        self.escapeLabel.setBuddy(self.escapeLine)

        # Eval function count 
        self.evalLabel = QtGui.QLabel(self.tr('Eval Fun:'), self)
        self.evalLine = QtGui.QLineEdit(self)
        self.evalLine.setMaximumWidth(160)
        self.evalLine.setFixedWidth(175)
        self.evalLine.setMaximumHeight(25)
        self.evalLine.setFixedHeight(30)
        self.evalLine.setReadOnly(True)
        self.evalLabel.setBuddy(self.evalLine)

        # Layout for eval + escape funciton
        self.escapeEvalLayout = QtGui.QHBoxLayout()
        self.escapeEvalLayout.addWidget(self.escapeLabel)
        self.escapeEvalLayout.addWidget(self.escapeLine)
        self.escapeEvalLayout.addWidget(self.evalLabel)
        self.escapeEvalLayout.addWidget(self.evalLine)

        # A log about the iframes in a link
        self.frameLogLabel = QtGui.QLabel(self.tr('Frame log:'), self)
        self.frameLogLine = QtGui.QTextEdit(self)
        self.frameLogLine.setReadOnly(True)
        self.frameLogLine.setMaximumWidth(500)
        self.frameLogLine.setFixedWidth(510)
        self.frameLogLine.setMaximumHeight(200)
        self.frameLogLine.setFixedHeight(205)
        self.frameLogLine.setLineWrapMode(QtGui.QTextEdit.NoWrap)
        
        self.font = self.frameLogLine.font()
        self.font.setFamily('Courier')
        self.font.setPointSize(10)
        self.frameLogLine.verticalScrollBar()
        
        # Layout for frame logs
        self.frameLogLayout = QtGui.QVBoxLayout()
        self.frameLogLayout.addWidget(self.frameLogLabel)
        self.frameLogLayout.addWidget(self.frameLogLine)
    
        # A log about suspicious links
        self.suspiciousLabel = QtGui.QLabel(self.tr('Suspicious Links'), self)
        self.suspiciousLine = QtGui.QTextEdit(self)
        self.suspiciousLine.setReadOnly(True)
        self.suspiciousLine.setMaximumWidth(500)
        self.suspiciousLine.setFixedWidth(510)
        self.suspiciousLine.setMaximumHeight(100)
        self.suspiciousLine.setFixedHeight(105)
        self.suspiciousLabel.setBuddy(self.securityStatusLine)
        self.suspiciousLine.setLineWrapMode(QtGui.QTextEdit.NoWrap)
        self.suspiciousLine.verticalScrollBar()
    
        # Layout of suspicous links 
        self.suspiciousLayout = QtGui.QVBoxLayout()
        self.suspiciousLayout.addWidget(self.suspiciousLabel)
        self.suspiciousLayout.addWidget(self.suspiciousLine)
    
        # Merges framecount and input layouts
        self.verticalLayout = QtGui.QVBoxLayout(self)
        self.verticalLayout.addLayout(self.inputLayout)
        self.verticalLayout.addLayout(self.securityStatusLayout)
        self.verticalLayout.addLayout(self.whiteFrameLayout)
        self.verticalLayout.addLayout(self.escapeEvalLayout)
        self.verticalLayout.addLayout(self.frameLogLayout)
        self.verticalLayout.addLayout(self.suspiciousLayout)

        self.verticalLayout.setSizeConstraint(QLayout.SetFixedSize)
        self.setContentsMargins(0, 0, 0, 0)
        
        # On button click activity
        self.btn.clicked.connect(self.AnalyzeUrl)
        self.setLayout(self.verticalLayout)
        self.setWindowIcon(QtGui.QIcon("images/icon64.png"))
        self.setWindowTitle('Amrita Malicious Advertisement Analyzer (AMAA)')
        self.show()
   
    def AnalyzeUrl(self):
        """
        Function to analyze the given input and act accordingly
        """

        self.url_input = self.urlInput.text()
        self.frameCount = 0
        self.scriptCount = 0
        self.staticFrames = 0
        self.securityStatus = ''
        self.outLog = ''
        self.frameCount = 0
        self.malwareFrames = 0
        self.totalObject = 0
        self.iframeNoSize = 0
        self.totalEmbed = 0
        self.linkLabel = ''
        
        if self.url_input != "":
            """txdata = None
            txheaders = {   
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
            'Accept-Language': 'en-us',
            'Accept-Encoding': 'gzip, deflate, compress;q=0.9',
            'Keep-Alive': '300',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            }
            req_site = urllib2.Request(url_input, txdata, txheaders)"""

            # Sending get request
            self.get = urllib2.urlopen(str(self.url_input)).read()
            self.dom = BeautifulSoup(self.get)
            # Fetching all the iframes in the page
            self.iframe_data = self.dom.findAll('iframe')
            self.iframe_analysis = []
            for i in self.iframe_data:
                self.frameCount = int(self.frameCount) + 1
                # Calling function to Analyze each frame
                self.result = self.AnalyzeIframe(i)

                if isinstance(self.result, list):
                    self.iframe_analysis.append(self.result)
                else:
                    self.staticFrames = int(staticFrames) + 1

            self.frameCount = 0               
            for i in self.iframe_analysis:
                if i != None:
                    self.frameCount = int(self.frameCount) + 1
                    try:
                        self.outLog = self.outLog + "iFrame " + \
                        str(self.frameCount) + " Height: " + str(i[0][0]) +  \
                        " Width: " + str(i[0][1]) + "\n";

                        if ((int(i[0][0]) < 10) and (int(i[0][1] < 10))):
                            self.malwareFrames = int(self.malwareFrames) + 1
                            self.linkLabel = self.linkLabel + "\n" + str(i[3])
                        if (int(i[1]) > 0):
                            self.totalObject = int(self.totalObject) + 1
                        if (int(i[2]) >=4):
                            self.totalEmbed = int(self.totalEmbed) + 1
                    except IndexError:
                        pass
            # Calculates the count of escape, space and no of chars in the
            # script
            self.escapeCount = 0
            self.spaceCount = 0
            self.charCount = 0
            self.scriptData = self.dom.findAll('script')
            for script in self.scriptData:
                for line in script:
                    self.charCount = self.charCount + len(line)
                    self.spaceCount = self.spaceCount + (len(line)  - \
                            len(line.strip()))

            # Sets the count of escape function
            self.escapeData = self.dom.findAll('escape')
            self.escapeValue = ''
            for escape in self.escapeData:
                self.escapeCount = self.escapeCount + 1
                self.escapeValue = self.escapeValue + escape

            # Calculates and sets the value of count of eval function in the
            # page
            self.evalData = self.dom.findAll('eval')
            self.evalCount = 0
            for i in self.evalData:
                self.evalCount = self.evalCount + 1
            
            # Special error logs if Suspicious iframes are found
            if ((self.malwareFrames > 0) or (self.totalObject > 0) or \
                    (self.totalEmbed > 3)):
                self.outLog = self.outLog + "\nSuspicious Content Found!\nSmall frames found\n"
                self.outLog = self.outLog + "Total of " +str(self.totalObject)+\
                " object tags\nTotal of " + str(self.totalEmbed)+ " embed tags"\
                "Total of " + str(self.staticFrames) + " static frames\n\n"
                self.securityStatus = 'Malicious Advertisements found!'
            else:
                self.securityStatus = 'Advertisements are safe!'
                self.linkLabel = "No Suspicious URLs found"
            
            self.securityStatusLine.setText(self.securityStatus)
            self.frameCountLine.setText(str(self.frameCount))
            self.whitespaceLine.setText(str(self.spaceCount))
            self.frameLogLine.setText(self.outLog)
            self.escapeLine.setText(str(self.escapeCount))
            self.evalLine.setText(str(self.evalCount))
            self.suspiciousLine.setText(self.linkLabel)

    def aboutDialog(self):
        """
        To invoke About class
        """
        self.dialog = About()
        self.dialog.exec_()

    def AnalyzeIframe(self, iframe_ana):
        """
        Function to analyze the input iframe
        """
        iframe_child_ans=[]
        iframe_size=[]
        object_cnt=0
        embed_cnt=0

        h = iframe_ana.get('height')
        w = iframe_ana.get('width') 

        try:
            if ((h.isdigit()) and (w.isdigit())):
                iframe_size.append(h)
                iframe_size.append(w)

            elif ((len(h) > 0) and (len(w) > 0)):
                iframe_escaped = True		
        except Exception:
            pass

        new_url = iframe_ana.get('src')
        file_type = self.getContentType(new_url)

        #checking if the url points to an html page
        if ('html' in file_type):
            iframe_child_ans.append(iframe_size)
            child_get = urllib2.urlopen(new_url).read()
            child_dom = BeautifulSoup(child_get)
            object_data = child_dom.findAll('object')
            embed_data = child_dom.findAll('embed')

            for i in object_data:
                object_cnt = int(object_cnt)+1

            for i in embed_data:
                embed_cnt = int(embed_cnt)+1

            iframe_child_ans.append(object_cnt)
            iframe_child_ans.append(embed_cnt)
            iframe_src = iframe_ana.get('src')
            iframe_child_ans.append(iframe_src)
            return iframe_child_ans

        else:
            return "not_dynamic"
        
    def getContentType(self,pageUrl):
        try:
            page = urllib2.urlopen(pageUrl)
            pageHeaders = page.headers
            contentType = pageHeaders.getheader('content-type')
            return contentType
        except Exception:
            return "unknown"

class About(QtGui.QDialog):
    def __init__(self):
        QtGui.QDialog.__init__(self)

        self.setWindowIcon(QtGui.QIcon('images/icon64.png'))
        self.setWindowTitle(self.tr('About'))

        self.iconLabel = QtGui.QLabel()
        self.iconLabel.setPixmap(QtGui.QPixmap('images/toxlogo.png'))
        self.iconLabel.setFixedSize(64, 64)
        
        self.appNameLabel = QtGui.QLabel(self.tr('Amrita Malicious\nAdvertisement \nAnalyzer (AMAA)'))
        self.font = QtGui.QFont(self.appNameLabel.font().family(), 14)
        self.font.setBold(True)
        self.appNameLabel.setFont(self.font)

        self.titleLayout = QtGui.QHBoxLayout()
        self.titleLayout.addWidget(self.iconLabel)
        self.titleLayout.addWidget(self.appNameLabel)
        self.titleLayout.setAlignment(Qt.AlignLeft)

        self.devLabel = QtGui.QLabel(self.tr('Developer: Bala Gopal'))
        self.devLabel.setAlignment(Qt.AlignCenter)

        self.copyRight = QtGui.QLabel(self.tr('(c) 2013-2014'))
        self.copyRight.setAlignment(Qt.AlignCenter)

        self.aboutLayout = QtGui.QVBoxLayout()
        self.aboutLayout.addLayout(self.titleLayout)
        self.aboutLayout.addWidget(self.devLabel)
        self.aboutLayout.addWidget(self.copyRight)
        self.setLayout(self.aboutLayout)
        self.aboutLayout.setSizeConstraint(QLayout.SetFixedSize)
    
def main():
    
    app = QtGui.QApplication(sys.argv)
    ex = AnalyzerWindow()
    sys.exit(app.exec_())


if __name__ == '__main__':
    
    main()
