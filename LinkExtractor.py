import re
from urlparse import urlparse, urljoin
from datetime import datetime
from burp import IBurpExtender, ITab, IHttpListener
from java.lang import Boolean, String
from java.io import PrintWriter
from java.util import ArrayList
from java.awt import Font, Dimension
from java.awt.event import KeyEvent
from javax import swing
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer


def getExtension(path):
    twig = path.split("/")[-1]
    if "." in twig: return twig.split(".")[-1]
    else: return ""

def setFixedSize(component, width, height):
    component.setMinimumSize(Dimension(width, height))
    component.setMaximumSize(Dimension(width, height))
    component.setPreferredSize(Dimension(width, height))


class BurpExtender(IBurpExtender, IHttpListener, ITab):
   
    def registerExtenderCallbacks(self, callbacks):
        
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True) # for debugging
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("LinkExtractor")

        self.linkExtractor = LinkExtractor()
        self.actionHandler = ActionHandler(self)
        self.eventHandler = EventHandler(self.actionHandler)
        self.settings = Settings()
        self.initUi()

        callbacks.registerHttpListener(self)


    def initUi(self):
        
        self.tabbedPane = swing.JTabbedPane()
        self.fileChooser = swing.JFileChooser()

        ### Findings Tab ###

        self.sourcesModel = SourcesModel()
        self.sourcesTable = SourcesTable(self.sourcesModel, self) 
        self.sourcesTable.setAutoCreateRowSorter(True)
        self.sourcesTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_OFF)
        sourcesColumnWidthPercentages = (0.05, 0.2, 0.4, 0.05, 0.05, 0.05, 0.05, 0.05, 0.1)
        sourcesColumnModel = self.sourcesTable.getColumnModel()
        #sourcesTotalWidth = sourcesColumnModel.getTotalColumnWidth()
        sourcesTotalWidth = 1920
        for i in range(self.sourcesTable.getColumnCount()):
            width = int(round(sourcesTotalWidth * sourcesColumnWidthPercentages[i]))
            sourcesColumnModel.getColumn(i).setPreferredWidth(width)

        self.linksModel = LinksModel()
        self.linksTable = LinksTable(self.linksModel) 
        self.linksTable.setAutoCreateRowSorter(True)
        self.linksTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_OFF)
        linksColumnWidthPercentages = (0.05, 0.9, 0.05)
        linksColumnModel = self.linksTable.getColumnModel()
        #linksTotalWidth = linksColumnModel.getTotalColumnWidth()
        linksTotalWidth = 1920
        for i in range(self.linksTable.getColumnCount()):
            width = int(round(linksTotalWidth * linksColumnWidthPercentages[i]))
            linksColumnModel.getColumn(i).setPreferredWidth(width)

        ftSourcesScrollPane = swing.JScrollPane(self.sourcesTable)
        ftLinksScrollPane = swing.JScrollPane(self.linksTable)
        ftSplitPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        ftSplitPane.setTopComponent(ftSourcesScrollPane)
        ftSplitPane.setBottomComponent(ftLinksScrollPane)

        ### Settings Tab ###

        self.stStrings = {
            "section1HeaderLabel": "Processing",
            "section2HeaderLabel": "Exclusions (Regexes for Source URLs)",
            "section3HeaderLabel": "Misc",
            "group1RadioButton1": "Only process JavaScript files",
            "group1RadioButton2": "Process all responses",
            "group1RadioButton3": "Pause LinkExtractor",
            "exportLabel": "Export findings as:",
            "clearFindingsDialog": "Are you sure you want to clear all findings by LinkExtractor? This cannot be undone.",
            "editExclusionDialog": ""
        }

        stHeaderFont = swing.JLabel().getFont().deriveFont(Font.BOLD, 15)

        # Section 1 #

        stSection1HeaderLabel = swing.JLabel(self.stStrings["section1HeaderLabel"])
        stSection1HeaderLabel.setFont(stHeaderFont)
        stSection1HeaderLabel.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 10, 0))
        
        stGroup1RadioButton1 = swing.JRadioButton(self.stStrings["group1RadioButton1"])
        stGroup1RadioButton1.setSelected(True)
        stGroup1RadioButton1.setActionCommand("setProcess1")
        stGroup1RadioButton1.addActionListener(self.eventHandler)
        
        stGroup1RadioButton2 = swing.JRadioButton(self.stStrings["group1RadioButton2"])
        stGroup1RadioButton2.setActionCommand("setProcess2")
        stGroup1RadioButton2.addActionListener(self.eventHandler)
        
        stGroup1RadioButton3 = swing.JRadioButton(self.stStrings["group1RadioButton3"])
        stGroup1RadioButton3.setActionCommand("setProcess0")
        stGroup1RadioButton3.addActionListener(self.eventHandler)
        
        stButtonGroup1 = swing.ButtonGroup()
        stButtonGroup1.add(stGroup1RadioButton1)
        stButtonGroup1.add(stGroup1RadioButton2)
        stButtonGroup1.add(stGroup1RadioButton3)
        
        stSeparator1 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator1, 1920, 5)
 
        # Section 2 #

        stSection2HeaderLabel = swing.JLabel(self.stStrings["section2HeaderLabel"])
        stSection2HeaderLabel.setFont(stHeaderFont)
        stSection2HeaderLabel.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 15, 0))
        
        stEditButton = swing.JButton("Edit"); setFixedSize(stEditButton, 76, 22)
        stEditButton.setActionCommand("editExclusion")
        stEditButton.addActionListener(self.eventHandler)
        stEditButton.setMnemonic(KeyEvent.VK_E)

        stRemoveButton = swing.JButton("Remove"); setFixedSize(stRemoveButton, 76, 22)
        stRemoveButton.setActionCommand("removeSelectedExclusions")
        stRemoveButton.addActionListener(self.eventHandler)
        stRemoveButton.setMnemonic(KeyEvent.VK_R)
        
        stClearButton = swing.JButton("Clear"); setFixedSize(stClearButton, 76, 22)
        stClearButton.setActionCommand("clearExclusions")
        stClearButton.addActionListener(self.eventHandler)
        stClearButton.setMnemonic(KeyEvent.VK_C)
        
        stLoadButton = swing.JButton("Load ..."); setFixedSize(stLoadButton, 76, 22)
        stLoadButton.setActionCommand("loadExclusions")
        stLoadButton.addActionListener(self.eventHandler)
        stLoadButton.setMnemonic(KeyEvent.VK_L)
        
        stToggleButton = swing.JButton("Toggle"); setFixedSize(stToggleButton, 76, 22) # enable/disable exclusion(s)
        stToggleButton.setActionCommand("toggleExclusions")
        stToggleButton.addActionListener(self.eventHandler)
        stToggleButton.setMnemonic(KeyEvent.VK_T)
        
        stAddButton = swing.JButton("Add"); setFixedSize(stAddButton, 76, 22)
        stAddButton.setActionCommand("addExclusion")
        stAddButton.addActionListener(self.eventHandler)
        
        self.exclusionsModel = ExclusionsModel(self.settings.exclusions)
        self.exclusionsTable = ExclusionsTable(self.exclusionsModel)
        exclusionsTotalWidth = 500
        stExclusionsScrollPane = swing.JScrollPane(self.exclusionsTable); setFixedSize(stExclusionsScrollPane, exclusionsTotalWidth, 200)
        exclusionsColumnWidthPercentages = (0.12, 0.88)
        exclusionsColumnModel = self.exclusionsTable.getColumnModel()
        for i in range(self.exclusionsTable.getColumnCount()):
            width = int(round(exclusionsTotalWidth * exclusionsColumnWidthPercentages[i]))
            exclusionsColumnModel.getColumn(i).setPreferredWidth(width)
        centerCellRenderer = DefaultTableCellRenderer()
        centerCellRenderer.setHorizontalAlignment(swing.SwingConstants.CENTER)
        exclusionsColumnModel.getColumn(0).setCellRenderer(centerCellRenderer)

        stAddExclusionTextField = swing.JTextField(); setFixedSize(stAddExclusionTextField, 500, 22)
        stAddExclusionTextField.setActionCommand("addExclusion")
        stAddExclusionTextField.addActionListener(self.eventHandler)
        self.stAddExclusionTextField = stAddExclusionTextField
        
        stSeparator2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator2, 1920, 5)

        # Section 3 #

        stSection3HeaderLabel = swing.JLabel(self.stStrings["section3HeaderLabel"])
        stSection3HeaderLabel.setFont(stHeaderFont)

        stExportLabel = swing.JLabel(self.stStrings["exportLabel"])
        
        stTextButton = swing.JButton("Text"); setFixedSize(stTextButton, 76, 22)
        stTextButton.setActionCommand("exportAsText")
        stTextButton.addActionListener(self.eventHandler)
       
        stClearFindingsButton = swing.JButton("Clear Findings"); setFixedSize(stTextButton, 100, 22)
        stClearFindingsButton.setActionCommand("clearFindings")
        stClearFindingsButton.addActionListener(self.eventHandler)
        
        stSeparator3 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator3, 1920, 5)

        ### Layout Setup ###

        stPanel = swing.JPanel()
        stPanel.setBorder(swing.BorderFactory.createEmptyBorder(10, 20, 10, 20))
        stLayout = swing.GroupLayout(stPanel)
        stPanel.setLayout(stLayout)
        stLayout.setAutoCreateGaps(True)
        stLayout.setAutoCreateContainerGaps(True)
        stScrollPane = swing.JScrollPane(stPanel)
        stScrollPane.setHorizontalScrollBarPolicy(swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
 
        stLayout.setHorizontalGroup(
            stLayout.createSequentialGroup()
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stSection1HeaderLabel) # Section 1
                    .addGroup(stLayout.createSequentialGroup()
                        .addGroup(stLayout.createParallelGroup()
                            .addComponent(stGroup1RadioButton1)
                            .addComponent(stGroup1RadioButton2)
                            .addComponent(stGroup1RadioButton3)
                        )
                    )
                    .addComponent(stSeparator1)
                    .addComponent(stSection2HeaderLabel) # Section 2
                    .addGroup(stLayout.createSequentialGroup()
                        .addGroup(stLayout.createParallelGroup()
                            .addComponent(stEditButton)
                            .addComponent(stRemoveButton)
                            .addComponent(stClearButton)
                            .addComponent(stLoadButton)
                            .addComponent(stToggleButton)
                        )
                        .addComponent(stExclusionsScrollPane)
                    )
                    .addGroup(stLayout.createSequentialGroup()
                        .addComponent(stAddButton)
                        .addComponent(stAddExclusionTextField)
                    )
                    .addComponent(stSeparator2)
                    .addComponent(stSection3HeaderLabel) # Section 3
                    .addGroup(stLayout.createSequentialGroup()
                        .addComponent(stExportLabel)
                        .addComponent(stTextButton)
                    )
                    .addComponent(stClearFindingsButton)
                    .addComponent(stSeparator3)
                )
        )

        stLayout.setVerticalGroup(
            stLayout.createSequentialGroup()
                .addComponent(stSection1HeaderLabel) # Section 1
                .addGroup(stLayout.createSequentialGroup()
                    .addComponent(stGroup1RadioButton1)
                    .addComponent(stGroup1RadioButton2)
                    .addComponent(stGroup1RadioButton3)
                )
                .addComponent(stSeparator1)
                .addComponent(stSection2HeaderLabel) # Section 2
                .addGroup(stLayout.createSequentialGroup()
                    .addGroup(stLayout.createParallelGroup()
                        .addGroup(stLayout.createSequentialGroup()
                            .addComponent(stEditButton)
                            .addComponent(stRemoveButton)
                            .addComponent(stClearButton)
                            .addComponent(stLoadButton)
                            .addComponent(stToggleButton)
                        )
                        .addComponent(stExclusionsScrollPane)
                    )
                )
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stAddButton)
                    .addComponent(stAddExclusionTextField)
                )
                .addComponent(stSeparator2)
                .addComponent(stSection3HeaderLabel) # Section 3
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stExportLabel)
                    .addComponent(stTextButton)
                )
                .addComponent(stClearFindingsButton)
                .addComponent(stSeparator3)
        )

        self.callbacks.customizeUiComponent(self.tabbedPane)
        self.tabbedPane.addTab("Findings", ftSplitPane)
        self.tabbedPane.addTab("Settings", stScrollPane)
        self.callbacks.addSuiteTab(self)


    # implementing ITab

    def getTabCaption(self):
        return "LinkExtractor"
    
    def getUiComponent(self):
        return self.tabbedPane


    # implementing IHttpListener

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if messageIsRequest or self.settings.process == 0: return

        analyzedRequest = self.helpers.analyzeRequest(messageInfo)
        analyzedResponse = self.helpers.analyzeResponse(messageInfo.getResponse())
        responseContent = self.helpers.bytesToString(messageInfo.getResponse())

        urlObj = analyzedRequest.getUrl()
        url = str(urlObj)
        parsedUrl = urlparse(str(urlObj))
        host = "%s://%s" % (parsedUrl.scheme, parsedUrl.hostname)
        path = "%s?%s" % (parsedUrl.path, parsedUrl.query) if parsedUrl.query else parsedUrl.path
        method = analyzedRequest.getMethod()
        statusCode = analyzedResponse.getStatusCode()
        extension = getExtension(parsedUrl.path)

        regexes = [self.settings.exclusions.get(i).regex for i in range(self.settings.exclusions.size())]
        if self.settings.process == 1 and extension != "js" or any([regex.search(url) for regex in regexes]): return

        if self.callbacks.isInScope(urlObj) and not self.sourcesModel.entryExists(host, path, method, statusCode):
            length = len(responseContent)
            mimeType = analyzedResponse.getStatedMimeType()
            time = str(datetime.now())
            links = self.linkExtractor.extractLinks(responseContent, host)
            sourceEntry = self.sourcesModel.addEntry(host, path, method, statusCode, length, mimeType, extension, time)
            for i in links:
                linkEntry = self.linksModel.addEntry(i, sourceEntry)
                sourceEntry.addLink(linkEntry)
            self.sourcesModel.refreshTable()


class LinkExtractor():

    regexStr = r"""

        (?:"|')                             # Start newline delimiter
        (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
        |
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
        |
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
        |
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)            # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
        )
        (?:"|')                             # End newline delimiter

        """

    regex = re.compile(regexStr, re.VERBOSE)

    def extractLinks(self, content, host):
        matches = self.regex.findall(content)
        links = list(set([urljoin(host, list(set(i))[1]) for i in matches if i != ""]))
        return links


# Sources

class SourceEntry():
    
    def __init__(self, id, host, path, method, statusCode, length, mimeType, extension, time):
        self.id = id
        self.host = host
        self.path = path
        self.method = method
        self.statusCode = statusCode
        self.length = length
        self.mimeType = mimeType
        self.extension = extension
        self.time = time
        self.links = []

    def addLink(self, link):
        for i in self.links:
            if link.url == i.url: return False
        self.links.append(link)
        return True


class SourcesModel(AbstractTableModel):

    columnNames = ("#", "Host", "Path", "Method", "Status Code", "Length", "MIME Type", "Extension", "Time")

    def __init__(self):
        self.entries = ArrayList()
        self.displayedEntries = ArrayList()
        self.lastId = 0

    def addEntry(self, host, path, method, statusCode, length, mimeType, extension, time):
        self.lastId += 1
        id =  self.lastId
        entry = SourceEntry(id, host, path, method, statusCode, length, mimeType, extension, time)
        self.entries.add(entry)
        self.fireTableDataChanged()
        return entry 

    def entryExists(self, host, path, method, statusCode):
        for i in range(self.entries.size()):
            entry = self.entries.get(i)
            if host == entry.host and path == entry.path and method == entry.method and statusCode == entry.StatusCode: return True
        return False

    def clearEntries(self):
        self.displayedEntries.clear()
        self.entries.clear()
        self.fireTableDataChanged()

    def getEntryById(self, id):
        for i in range(self.entries.size()):
            entry = self.entries.get(i)
            if id == entry.id: return entry

    def refreshTable(self):
        self.displayedEntries.clear()
        for entry in self.entries:
            if len(entry.links) > 0: self.displayedEntries.add(entry)
        self.fireTableDataChanged()

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getRowCount(self):
        return self.displayedEntries.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getValueAt(self, rowIndex, columnIndex):
        entry = self.displayedEntries.get(rowIndex)
        if columnIndex == 0: return entry.id
        elif columnIndex == 1: return entry.host
        elif columnIndex == 2: return entry.path
        elif columnIndex == 3: return entry.method
        elif columnIndex == 4: return entry.statusCode
        elif columnIndex == 5: return entry.length
        elif columnIndex == 6: return entry.mimeType
        elif columnIndex == 7: return entry.extension
        elif columnIndex == 8: return entry.time
        else: return ""


class SourcesTable(swing.JTable):

    def __init__(self, model, extender):
           self.setModel(model)
           self.extender = extender

    def changeSelection(self, rowIndex, columnIndex, toggle, extend):
        self.extender.linksModel.displayedEntries.clear()
        linkEntries = self.model.getEntryById(self.model.getValueAt(rowIndex, 0)).links
        for i in linkEntries: self.extender.linksModel.displayedEntries.add(i)
        self.extender.linksModel.fireTableDataChanged()
        swing.JTable.changeSelection(self, rowIndex, columnIndex, toggle, extend)


# Links

class LinkEntry():
    
    def __init__(self, id, url, source):
        self.id = id
        self.url = url
        self.sources = [source]

    def hasSource(self, source):
        return True if source in self.sources else False

    def addSource(self, source):
        if not self.hasSource(source): self.sources.append(source)


class LinksModel(AbstractTableModel):

    columnNames = ("#", "URL")

    def __init__(self):
        self.entries = ArrayList()
        self.displayedEntries = ArrayList()
        self.lastId = 0

    def addEntry(self, url, source):
        for i in range(self.entries.size()):
            entry = self.entries.get(i)
            if url == entry.url:
                entry.addSource(source)
                return entry
        self.lastId += 1
        id =  self.lastId
        entry = LinkEntry(id, url, source)
        self.entries.add(entry)
        return entry

    def clearEntries(self):
        self.displayedEntries.clear()
        self.entries.clear()
        self.fireTableDataChanged()

    def getAllUrls(self):
        return [self.entries.get(i).url for i in range(self.entries.size())]

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getRowCount(self):
        return self.displayedEntries.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getValueAt(self, rowIndex, columnIndex):
        entry = self.displayedEntries.get(rowIndex)
        if columnIndex == 0: return entry.id
        elif columnIndex == 1: return entry.url
        else: return ""


class LinksTable(swing.JTable):

    def __init__(self, model):
        self.setModel(model)


# Exclusions

class ExclusionEntry():

    def __init__(self, regexStr, enabled=True):
        self.regex = re.compile(regexStr)
        self.enabled = enabled

    def editRegex(self, regexStr):
        self.regex = re.compile(regexStr)

    def toggle(self):
        self.enabled = not self.enabled

class ExclusionsModel(AbstractTableModel):

    columnNames = ("Enabled", "Regex")

    def __init__(self, exclusions):
        self.entries = exclusions

    def addEntry(self, regexStr):
        entry = ExclusionEntry(regexStr)
        self.entries.add(entry)
        self.fireTableDataChanged()

    def editEntryRegex(self, index, regexStr):
        self.entries.get(index).editRegex(regexStr)
        self.fireTableDataChanged()

    def removeEntry(self, index):
        self.entries.remove(index)
        self.fireTableDataChanged()

    def toggleEntries(self, indexes):
        for i in indexes: self.entries.get(i).toggle()
        self.fireTableDataChanged()

    def clearEntries(self):
        self.entries.clear()
        self.fireTableDataChanged()

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getRowCount(self):
        return self.entries.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getValueAt(self, rowIndex, columnIndex):
        entry = self.entries.get(rowIndex)
        if columnIndex == 0: return u"\u2714" if entry.enabled else ""
        elif columnIndex == 1: return entry.regex.pattern
        else: return ""


class ExclusionsTable(swing.JTable):

    def __init__(self, model):
        self.setModel(model)


class Settings():

    def __init__(self):
        self.process = 1 # (the verb), 0 => nothing, 1 => only JS, 2 => anything
        self.exclusions = ArrayList()


class ActionHandler():

    def __init__(self, extender):
        self.extender = extender

    def setProcessSetting(self, value):
        self.extender.settings.process = value

    def addExclusion(self):
        regexStr = self.extender.stAddExclusionTextField.getText()
        if len(regexStr) > 0:
            self.extender.exclusionsModel.addEntry(regexStr)
            self.extender.stAddExclusionTextField.setText("")
            self.extender.stAddExclusionTextField.requestFocus()
        
    def editExclusion(self):
        index = self.extender.exclusionsTable.getSelectedRow()
        if index != -1 :
            exclusionToEdit = self.extender.exclusionsModel.entries.get(index)
            regexStr = exclusionToEdit.regex.pattern
            result = swing.JOptionPane.showInputDialog(self.extender.tabbedPane, \
                                                    self.extender.stStrings["editExclusionDialog"], \
                                                    "Edit Exclusion", \
                                                    swing.JOptionPane.PLAIN_MESSAGE, \
                                                    None, None, regexStr)
            if result != None: self.extender.exclusionsModel.editEntryRegex(index, result)

    def removeSelectedExclusions(self):
        selectedRowIndexes = self.extender.exclusionsTable.getSelectedRows()
        for i in selectedRowIndexes[::-1]: self.extender.exclusionsModel.removeEntry(i)

    def clearExclusions(self):
        self.extender.exclusionsModel.clearEntries()

    def loadExclusions(self):
        result = self.extender.fileChooser.showOpenDialog(self.extender.tabbedPane)
        if result == swing.JFileChooser.APPROVE_OPTION:
            selectedFile = self.extender.fileChooser.getSelectedFile()
            with open(selectedFile.getCanonicalPath(), "r") as infile:
                regexStrings = [i for i in infile.read().splitlines() if len(i) > 0]
                for regexStr in regexStrings: self.extender.exclusionsModel.addEntry(regexStr)

    def toggleExclusions(self):
        selectedRowIndexes = self.extender.exclusionsTable.getSelectedRows()
        if len(selectedRowIndexes) > 0:
            self.extender.exclusionsModel.toggleEntries(selectedRowIndexes)

    def exportAsText(self):
        try:
            result = self.extender.fileChooser.showSaveDialog(self.extender.tabbedPane)
            if result == swing.JFileChooser.APPROVE_OPTION:
                selectedFile = self.extender.fileChooser.getSelectedFile()
                with open(selectedFile.getCanonicalPath(), "w") as outfile:
                    outfile.write("\n".join(self.extender.linksModel.getAllUrls()))
        except Exception as e:
            self.extender.stderr.println("[-] Failed exporting to file: %s" % e.__class__.__name__)

    def clearFindings(self):
        result = swing.JOptionPane.showOptionDialog(self.extender.tabbedPane, \
                                                        self.extender.stStrings["clearFindingsDialog"], \
                                                        "Clear Findings", \
                                                        swing.JOptionPane.YES_NO_OPTION, \
                                                        swing.JOptionPane.WARNING_MESSAGE, \
                                                        None, None, None)
        if result == swing.JOptionPane.YES_OPTION:
            self.extender.sourcesModel.clearEntries()
            self.extender.linksModel.clearEntries()
        


class EventHandler(swing.AbstractAction):
    
    def __init__(self, actionHandler):
        self.actionHandler = actionHandler

    def actionPerformed(self, actionEvent):
        if actionEvent.getActionCommand() == "setProcess0": self.actionHandler.setProcessSetting(0)
        elif actionEvent.getActionCommand() == "setProcess1": self.actionHandler.setProcessSetting(1)
        elif actionEvent.getActionCommand() == "setProcess2": self.actionHandler.setProcessSetting(2)

        elif actionEvent.getActionCommand() == "addExclusion": self.actionHandler.addExclusion()
        elif actionEvent.getActionCommand() == "editExclusion": self.actionHandler.editExclusion()
        elif actionEvent.getActionCommand() == "removeSelectedExclusions": self.actionHandler.removeSelectedExclusions()
        elif actionEvent.getActionCommand() == "clearExclusions": self.actionHandler.clearExclusions()
        elif actionEvent.getActionCommand() == "loadExclusions": self.actionHandler.loadExclusions()
        elif actionEvent.getActionCommand() == "toggleExclusions": self.actionHandler.toggleExclusions()

        elif actionEvent.getActionCommand() == "exportAsText": self.actionHandler.exportAsText()
        elif actionEvent.getActionCommand() == "clearFindings": self.actionHandler.clearFindings()
