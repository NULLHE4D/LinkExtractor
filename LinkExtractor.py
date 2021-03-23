import re, json
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
        #self.stdout = PrintWriter(callbacks.getStdout(), True) # for debugging
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("LinkExtractor")

        self.linkExtractor = LinkExtractor()
        self.actionHandler = ActionHandler(self)
        self.eventHandler = EventHandler(self.actionHandler)
        self.settings = Settings(self)
        self.initUi()
        self.settings.loadSettings()

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
            "section2HeaderLabel": "Source Exclusions",
            "section3HeaderLabel": "Link Exclusions",
            "section4HeaderLabel": "Misc",
            "inScopeOnlyCheckBox": "Only process in-scope URLs",
            "ignoreDupsCheckBox": "Ignore duplicate items based on URL, query parameters, request method and response status code",
            "ignoreDupsLabel": "*may impact performance",
            "processLabel": "Select what you want LinkExtractor to do:",
            "group1RadioButton1": "Only process JavaScript files",
            "group1RadioButton2": "Process all responses",
            "group1RadioButton3": "Pause LinkExtractor",
            "toolSelectionLabel": "Select which tools you want LinkExtractor to process responses from:",
            "sourceExclusionsLabel": "Any responses from requests to URLs that match any of the Regular Expression patterns below will not be processed.",
            "linkExclusionsLabel": "Any links found in processed responses that match any of the Regular Expression patterns below will not be saved nor displayed.",
            "exportLabel": "Export findings as:",
            "clearFindingsDialog": "Are you sure you want to clear all findings by LinkExtractor? This cannot be undone.",
            "editExclusionDialog": ""
        }

        stHeaderFont = swing.JLabel().getFont().deriveFont(Font.BOLD, 15)

        # Section 1 #

        stSection1HeaderLabel = swing.JLabel(self.stStrings["section1HeaderLabel"])
        stSection1HeaderLabel.setFont(stHeaderFont)
        stSection1HeaderLabel.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 10, 0))

        self.stInScopeOnlyCheckBox = swing.JCheckBox(self.stStrings["inScopeOnlyCheckBox"], None, True)
        self.stInScopeOnlyCheckBox.setActionCommand("toggleInScopeOnly")
        self.stInScopeOnlyCheckBox.addActionListener(self.eventHandler)
       
        self.stIgnoreDupsCheckBox = swing.JCheckBox(self.stStrings["ignoreDupsCheckBox"], None, True)
        self.stIgnoreDupsCheckBox.setActionCommand("toggleIgnoreDups")
        self.stIgnoreDupsCheckBox.addActionListener(self.eventHandler)
        self.stIgnoreDupsCheckBox.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 15, 0))
        
        stIgnoreDupsLabel = swing.JLabel(self.stStrings["ignoreDupsLabel"])
        stIgnoreDupsLabel.setFont(swing.JLabel().getFont().deriveFont(Font.ITALIC))
       
        stToolSelectionLabel = swing.JLabel(self.stStrings["toolSelectionLabel"])

        self.stToolSelectionCheckBox1 = swing.JCheckBox("Proxy", None, True)
        self.stToolSelectionCheckBox1.setActionCommand("toggleToolSelectionProxy")
        self.stToolSelectionCheckBox1.addActionListener(self.eventHandler)
        self.stToolSelectionCheckBox1.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 15, 15))

        self.stToolSelectionCheckBox2 = swing.JCheckBox("Spider", None, False)
        self.stToolSelectionCheckBox2.setActionCommand("toggleToolSelectionSpider")
        self.stToolSelectionCheckBox2.addActionListener(self.eventHandler)
        self.stToolSelectionCheckBox2.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 0, 15))
       
        self.stToolSelectionCheckBox3 = swing.JCheckBox("Scanner", None, False)
        self.stToolSelectionCheckBox3.setActionCommand("toggleToolSelectionScanner")
        self.stToolSelectionCheckBox3.addActionListener(self.eventHandler)
        self.stToolSelectionCheckBox3.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 0, 0))
       
        stProcessLabel = swing.JLabel(self.stStrings["processLabel"])

        self.stGroup1RadioButton1 = swing.JRadioButton(self.stStrings["group1RadioButton1"], None, True)
        self.stGroup1RadioButton1.setActionCommand("setProcess1")
        self.stGroup1RadioButton1.addActionListener(self.eventHandler)
        
        self.stGroup1RadioButton2 = swing.JRadioButton(self.stStrings["group1RadioButton2"])
        self.stGroup1RadioButton2.setActionCommand("setProcess2")
        self.stGroup1RadioButton2.addActionListener(self.eventHandler)
        
        self.stGroup1RadioButton3 = swing.JRadioButton(self.stStrings["group1RadioButton3"])
        self.stGroup1RadioButton3.setActionCommand("setProcess0")
        self.stGroup1RadioButton3.addActionListener(self.eventHandler)
        
        stButtonGroup1 = swing.ButtonGroup()
        stButtonGroup1.add(self.stGroup1RadioButton1)
        stButtonGroup1.add(self.stGroup1RadioButton2)
        stButtonGroup1.add(self.stGroup1RadioButton3)
        
        stSeparator1 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator1, 1920, 5)
 
        # Section 2 #

        stSection2HeaderLabel = swing.JLabel(self.stStrings["section2HeaderLabel"])
        stSection2HeaderLabel.setFont(stHeaderFont)
        stSection2HeaderLabel.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 8, 0))

        stSourceExclusionsLabel = swing.JLabel(self.stStrings["sourceExclusionsLabel"])

        stEditButton = swing.JButton("Edit"); setFixedSize(stEditButton, 76, 22)
        stEditButton.setActionCommand("editSourceExclusion")
        stEditButton.addActionListener(self.eventHandler)
        stEditButton.setMnemonic(KeyEvent.VK_E)

        stRemoveButton = swing.JButton("Remove"); setFixedSize(stRemoveButton, 76, 22)
        stRemoveButton.setActionCommand("removeSelectedSourceExclusions")
        stRemoveButton.addActionListener(self.eventHandler)
        stRemoveButton.setMnemonic(KeyEvent.VK_R)
        
        stClearButton = swing.JButton("Clear"); setFixedSize(stClearButton, 76, 22)
        stClearButton.setActionCommand("clearSourceExclusions")
        stClearButton.addActionListener(self.eventHandler)
        stClearButton.setMnemonic(KeyEvent.VK_C)
        
        stLoadButton = swing.JButton("Load ..."); setFixedSize(stLoadButton, 76, 22)
        stLoadButton.setActionCommand("loadSourceExclusions")
        stLoadButton.addActionListener(self.eventHandler)
        stLoadButton.setMnemonic(KeyEvent.VK_L)
        
        stToggleButton = swing.JButton("Toggle"); setFixedSize(stToggleButton, 76, 22) # enable/disable source exclusion(s)
        stToggleButton.setActionCommand("toggleSourceExclusions")
        stToggleButton.addActionListener(self.eventHandler)
        stToggleButton.setMnemonic(KeyEvent.VK_T)
        
        stAddButton = swing.JButton("Add"); setFixedSize(stAddButton, 76, 22)
        stAddButton.setActionCommand("addSourceExclusion")
        stAddButton.addActionListener(self.eventHandler)
        
        self.sourceExclusionsTable = ExclusionsTable(self.settings.sourceExclusionsModel)
        sourceExclusionsTotalWidth = 500
        stSourceExclusionsScrollPane = swing.JScrollPane(self.sourceExclusionsTable); setFixedSize(stSourceExclusionsScrollPane, sourceExclusionsTotalWidth, 200)
        sourceExclusionsColumnWidthPercentages = (0.12, 0.88)
        sourceExclusionsColumnModel = self.sourceExclusionsTable.getColumnModel()
        for i in range(self.sourceExclusionsTable.getColumnCount()):
            width = int(round(sourceExclusionsTotalWidth * sourceExclusionsColumnWidthPercentages[i]))
            sourceExclusionsColumnModel.getColumn(i).setPreferredWidth(width)
        centerCellRenderer = DefaultTableCellRenderer()
        centerCellRenderer.setHorizontalAlignment(swing.SwingConstants.CENTER)
        sourceExclusionsColumnModel.getColumn(0).setCellRenderer(centerCellRenderer)

        stAddExclusionTextField = swing.JTextField(); setFixedSize(stAddExclusionTextField, 500, 22)
        stAddExclusionTextField.setActionCommand("addSourceExclusion")
        stAddExclusionTextField.addActionListener(self.eventHandler)
        self.stAddExclusionTextField = stAddExclusionTextField
        
        stSeparator2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator2, 1920, 5)
        
        # Section 3 #

        stSection3HeaderLabel = swing.JLabel(self.stStrings["section3HeaderLabel"])
        stSection3HeaderLabel.setFont(stHeaderFont)
        stSection3HeaderLabel.setBorder(swing.BorderFactory.createEmptyBorder(0, 0, 8, 0))

        stLinkExclusionsLabel = swing.JLabel(self.stStrings["linkExclusionsLabel"])

        stEdit2Button = swing.JButton("Edit"); setFixedSize(stEdit2Button, 76, 22)
        stEdit2Button.setActionCommand("editLinkExclusion")
        stEdit2Button.addActionListener(self.eventHandler)

        stRemove2Button = swing.JButton("Remove"); setFixedSize(stRemove2Button, 76, 22)
        stRemove2Button.setActionCommand("removeSelectedLinkExclusions")
        stRemove2Button.addActionListener(self.eventHandler)
        
        stClear2Button = swing.JButton("Clear"); setFixedSize(stClear2Button, 76, 22)
        stClear2Button.setActionCommand("clearLinkExclusions")
        stClear2Button.addActionListener(self.eventHandler)
        
        stLoad2Button = swing.JButton("Load ..."); setFixedSize(stLoad2Button, 76, 22)
        stLoad2Button.setActionCommand("loadLinkExclusions")
        stLoad2Button.addActionListener(self.eventHandler)
        
        stToggle2Button = swing.JButton("Toggle"); setFixedSize(stToggle2Button, 76, 22) # enable/disable link exclusion(s)
        stToggle2Button.setActionCommand("toggleLinkExclusions")
        stToggle2Button.addActionListener(self.eventHandler)
        
        stAdd2Button = swing.JButton("Add"); setFixedSize(stAdd2Button, 76, 22)
        stAdd2Button.setActionCommand("addLinkExclusion")
        stAdd2Button.addActionListener(self.eventHandler)
        
        self.linkExclusionsTable = ExclusionsTable(self.settings.linkExclusionsModel)
        linkExclusionsTotalWidth = 500
        stLinkExclusionsScrollPane = swing.JScrollPane(self.linkExclusionsTable); setFixedSize(stLinkExclusionsScrollPane, linkExclusionsTotalWidth, 200)
        linkExclusionsColumnWidthPercentages = (0.12, 0.88)
        linkExclusionsColumnModel = self.linkExclusionsTable.getColumnModel()
        for i in range(self.linkExclusionsTable.getColumnCount()):
            width = int(round(linkExclusionsTotalWidth * linkExclusionsColumnWidthPercentages[i]))
            linkExclusionsColumnModel.getColumn(i).setPreferredWidth(width)
        #centerCellRenderer = DefaultTableCellRenderer()
        #centerCellRenderer.setHorizontalAlignment(swing.SwingConstants.CENTER)
        linkExclusionsColumnModel.getColumn(0).setCellRenderer(centerCellRenderer) # same centerCellRenderer as with sourceExclusionsColumnModel

        stAddExclusion2TextField = swing.JTextField(); setFixedSize(stAddExclusion2TextField, 500, 22)
        stAddExclusion2TextField.setActionCommand("addLinkExclusion")
        stAddExclusion2TextField.addActionListener(self.eventHandler)
        self.stAddExclusion2TextField = stAddExclusion2TextField
        
        stSeparator3 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator3, 1920, 5)
        
        # Section 4 #

        stSection4HeaderLabel = swing.JLabel(self.stStrings["section4HeaderLabel"])
        stSection4HeaderLabel.setFont(stHeaderFont)

        stExportLabel = swing.JLabel(self.stStrings["exportLabel"])
        
        stTextButton = swing.JButton("Text"); setFixedSize(stTextButton, 76, 22)
        stTextButton.setActionCommand("exportAsText")
        stTextButton.addActionListener(self.eventHandler)
       
        stClearFindingsButton = swing.JButton("Clear Findings"); setFixedSize(stTextButton, 100, 22)
        stClearFindingsButton.setActionCommand("clearFindings")
        stClearFindingsButton.addActionListener(self.eventHandler)
        
        stSeparator4 = swing.JSeparator(swing.SwingConstants.HORIZONTAL); setFixedSize(stSeparator4, 1920, 5)

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
                            .addComponent(self.stInScopeOnlyCheckBox)
                            .addGroup(stLayout.createSequentialGroup()
                                .addComponent(self.stIgnoreDupsCheckBox)
                                .addComponent(stIgnoreDupsLabel)
                            )
                            .addComponent(stToolSelectionLabel)
                            .addGroup(stLayout.createSequentialGroup()
                                .addComponent(self.stToolSelectionCheckBox1)
                                .addComponent(self.stToolSelectionCheckBox2)
                                .addComponent(self.stToolSelectionCheckBox3)
                            )
                            .addComponent(stProcessLabel)
                            .addComponent(self.stGroup1RadioButton1)
                            .addComponent(self.stGroup1RadioButton2)
                            .addComponent(self.stGroup1RadioButton3)
                        )
                    )
                    .addComponent(stSeparator1)
                    .addComponent(stSection2HeaderLabel) # Section 2
                    .addComponent(stSourceExclusionsLabel)
                    .addGroup(stLayout.createSequentialGroup()
                        .addGroup(stLayout.createParallelGroup()
                            .addComponent(stEditButton)
                            .addComponent(stRemoveButton)
                            .addComponent(stClearButton)
                            .addComponent(stLoadButton)
                            .addComponent(stToggleButton)
                        )
                        .addComponent(stSourceExclusionsScrollPane)
                    )
                    .addGroup(stLayout.createSequentialGroup()
                        .addComponent(stAddButton)
                        .addComponent(stAddExclusionTextField)
                    )
                    .addComponent(stSeparator2)
                    .addComponent(stSection3HeaderLabel) # Section 3
                    .addComponent(stLinkExclusionsLabel)
                    .addGroup(stLayout.createSequentialGroup()
                        .addGroup(stLayout.createParallelGroup()
                            .addComponent(stEdit2Button)
                            .addComponent(stRemove2Button)
                            .addComponent(stClear2Button)
                            .addComponent(stLoad2Button)
                            .addComponent(stToggle2Button)
                        )
                        .addComponent(stLinkExclusionsScrollPane)
                    )
                    .addGroup(stLayout.createSequentialGroup()
                        .addComponent(stAdd2Button)
                        .addComponent(stAddExclusion2TextField)
                    )
                    .addComponent(stSeparator3)
                    .addComponent(stSection4HeaderLabel) # Section 4
                    .addGroup(stLayout.createSequentialGroup()
                        .addComponent(stExportLabel)
                        .addComponent(stTextButton)
                    )
                    .addComponent(stClearFindingsButton)
                    .addComponent(stSeparator4)
                )
        )

        stLayout.setVerticalGroup(
            stLayout.createSequentialGroup()
                .addComponent(stSection1HeaderLabel) # Section 1
                .addGroup(stLayout.createSequentialGroup()
                    .addComponent(self.stInScopeOnlyCheckBox)
                    .addGroup(stLayout.createParallelGroup()
                        .addComponent(self.stIgnoreDupsCheckBox)
                        .addComponent(stIgnoreDupsLabel)
                    )
                    .addComponent(stToolSelectionLabel)
                    .addGroup(stLayout.createParallelGroup()
                        .addComponent(self.stToolSelectionCheckBox1)
                        .addComponent(self.stToolSelectionCheckBox2)
                        .addComponent(self.stToolSelectionCheckBox3)
                    )
                    .addComponent(stProcessLabel)
                    .addComponent(self.stGroup1RadioButton1)
                    .addComponent(self.stGroup1RadioButton2)
                    .addComponent(self.stGroup1RadioButton3)
                )
                .addComponent(stSeparator1)
                .addComponent(stSection2HeaderLabel) # Section 2
                .addComponent(stSourceExclusionsLabel)
                .addGroup(stLayout.createSequentialGroup()
                    .addGroup(stLayout.createParallelGroup()
                        .addGroup(stLayout.createSequentialGroup()
                            .addComponent(stEditButton)
                            .addComponent(stRemoveButton)
                            .addComponent(stClearButton)
                            .addComponent(stLoadButton)
                            .addComponent(stToggleButton)
                        )
                        .addComponent(stSourceExclusionsScrollPane)
                    )
                )
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stAddButton)
                    .addComponent(stAddExclusionTextField)
                )
                .addComponent(stSeparator2)
                .addComponent(stSection3HeaderLabel) # Section 3
                .addComponent(stLinkExclusionsLabel)
                .addGroup(stLayout.createSequentialGroup()
                    .addGroup(stLayout.createParallelGroup()
                        .addGroup(stLayout.createSequentialGroup()
                            .addComponent(stEdit2Button)
                            .addComponent(stRemove2Button)
                            .addComponent(stClear2Button)
                            .addComponent(stLoad2Button)
                            .addComponent(stToggle2Button)
                        )
                        .addComponent(stLinkExclusionsScrollPane)
                    )
                )
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stAdd2Button)
                    .addComponent(stAddExclusion2TextField)
                )
                .addComponent(stSeparator3)
                .addComponent(stSection4HeaderLabel) # Section 4
                .addGroup(stLayout.createParallelGroup()
                    .addComponent(stExportLabel)
                    .addComponent(stTextButton)
                )
                .addComponent(stClearFindingsButton)
                .addComponent(stSeparator4)
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

        if messageIsRequest or self.settings.process == 0 or not toolFlag in self.settings.toolSelection: return

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

        regexes = [i.regex for i in self.settings.sourceExclusionsModel.entries if i.enabled]
        if self.settings.process == 1 and extension != "js" or any([regex.search(url) for regex in regexes]): return

        scopeBool = self.settings.inScopeOnly and self.callbacks.isInScope(urlObj) or not self.settings.inScopeOnly
        dupBool = self.settings.ignoreDups and not self.sourcesModel.entryExists(host, path, method, statusCode) or not self.settings.ignoreDups

        if scopeBool and dupBool:
            length = len(responseContent)
            mimeType = analyzedResponse.getStatedMimeType()
            time = str(datetime.now())
            links = self.linkExtractor.extractLinks(responseContent, host)
            sourceEntry = self.sourcesModel.addEntry(host, path, method, statusCode, length, mimeType, extension, time)
            
            regexes = [i.regex for i in self.settings.linkExclusionsModel.entries if i.enabled]
            for i in links:
                if any([regex.search(i) for regex in regexes]): continue
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
        self.regex = re.compile(regexStr, re.IGNORECASE)
        self.enabled = enabled

    def editRegex(self, regexStr):
        self.regex = re.compile(regexStr, re.IGNORECASE)

    def toggle(self):
        self.enabled = not self.enabled

class ExclusionsModel(AbstractTableModel):

    columnNames = ("Enabled", "Regex")

    def __init__(self, exclusions):
        self.entries = exclusions # array (not ArrayList)

    def addEntry(self, regexStr, enabled=True):
        entry = ExclusionEntry(regexStr, enabled)
        self.entries.append(entry)
        self.fireTableDataChanged()

    def editEntryRegex(self, index, regexStr):
        self.entries[index].editRegex(regexStr)
        self.fireTableDataChanged()

    def removeEntry(self, index):
        del self.entries[index]
        self.fireTableDataChanged()

    def toggleEntries(self, indexes):
        for i in indexes: self.entries[i].toggle()
        self.fireTableDataChanged()

    def clearEntries(self):
        del self.entries[:]
        self.fireTableDataChanged()

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getRowCount(self):
        return len(self.entries)

    def getColumnCount(self):
        return len(self.columnNames)

    def getValueAt(self, rowIndex, columnIndex):
        entry = self.entries[rowIndex]
        if columnIndex == 0: return u"\u2714" if entry.enabled else ""
        elif columnIndex == 1: return entry.regex.pattern
        else: return ""


class ExclusionsTable(swing.JTable):

    def __init__(self, model):
        self.setModel(model)


# Settings

class Settings():

    def __init__(self, extender):
        self.extender = extender
        self.inScopeOnly = True
        self.ignoreDups = True
        self.toolSelection = [self.extender.callbacks.TOOL_PROXY]
        self.process = 1 # (the verb), 0 => nothing, 1 => only JS, 2 => anything
        self.sourceExclusionsModel = ExclusionsModel([])
        self.linkExclusionsModel = ExclusionsModel([])

    def loadSettings(self):
        if self.extender.callbacks.loadExtensionSetting("LENotFirstTime-2d9e389a") == None:
            defaultExclusionRegexStr = "\.(png|jpg|jpeg|gif|ico|woff|woff2|ttf)($|\?)"
            self.sourceExclusionsModel.addEntry(defaultExclusionRegexStr)
            self.linkExclusionsModel.addEntry(defaultExclusionRegexStr)
            self.extender.callbacks.saveExtensionSetting("LENotFirstTime-2d9e389a", "yes")
            self.saveSettings()
        else:
            settingsDict = json.loads(self.extender.callbacks.loadExtensionSetting("LESettings"), encoding="utf-8")
            
            self.inScopeOnly = settingsDict["inScopeOnly"]
            self.extender.stInScopeOnlyCheckBox.setSelected(self.inScopeOnly)
            self.ignoreDups = settingsDict["ignoreDups"]
            self.extender.stIgnoreDupsCheckBox.setSelected(self.ignoreDups)

            self.toolSelection = settingsDict["toolSelection"]
            self.extender.stToolSelectionCheckBox1.setSelected(self.extender.callbacks.TOOL_PROXY in self.toolSelection)
            self.extender.stToolSelectionCheckBox2.setSelected(self.extender.callbacks.TOOL_SPIDER in self.toolSelection)
            self.extender.stToolSelectionCheckBox3.setSelected(self.extender.callbacks.TOOL_SCANNER in self.toolSelection)

            self.process = settingsDict["process"]
            if self.process == 0: self.extender.stGroup1RadioButton3.setSelected(True)
            if self.process == 1: self.extender.stGroup1RadioButton1.setSelected(True)
            if self.process == 2: self.extender.stGroup1RadioButton2.setSelected(True)
            
            for k,v in settingsDict["sourceExclusions"].iteritems(): self.sourceExclusionsModel.addEntry(k, v)
            for k,v in settingsDict["linkExclusions"].iteritems(): self.linkExclusionsModel.addEntry(k, v)

    def saveSettings(self):
        settingsDict = {"process": self.process, "inScopeOnly": self.inScopeOnly, "ignoreDups": self.ignoreDups, "toolSelection": self.toolSelection}
        settingsDict["sourceExclusions"] = {i.regex.pattern:i.enabled for i in self.sourceExclusionsModel.entries}
        settingsDict["linkExclusions"] = {i.regex.pattern:i.enabled for i in self.linkExclusionsModel.entries}
        self.extender.callbacks.saveExtensionSetting("LESettings", json.dumps(settingsDict))


# Event Handling

class ActionHandler():

    def __init__(self, extender):
        self.extender = extender

    def toggleInScopeOnly(self):
        self.extender.settings.inScopeOnly = not self.extender.settings.inScopeOnly
        self.extender.settings.saveSettings()

    def toggleIgnoreDups(self):
        self.extender.settings.ignoreDups = not self.extender.settings.ignoreDups
        self.extender.settings.saveSettings()

    def toggleToolSelection(self, tool):
        toolFlag = {"proxy": self.extender.callbacks.TOOL_PROXY, "spider": self.extender.callbacks.TOOL_SPIDER, "scanner": self.extender.callbacks.TOOL_SCANNER}[tool]
        if toolFlag in self.extender.settings.toolSelection: self.extender.settings.toolSelection.remove(toolFlag)
        else: self.extender.settings.toolSelection.append(toolFlag)
        self.extender.settings.saveSettings()

    def setProcessSetting(self, value):
        self.extender.settings.process = value
        self.extender.settings.saveSettings()

    def addSourceExclusion(self):
        regexStr = self.extender.stAddExclusionTextField.getText()
        if len(regexStr) > 0:
            try: self.extender.settings.sourceExclusionsModel.addEntry(regexStr)
            except Exception as e: self.extender.stderr.println("[-] Failed adding source exclusion: %s" % e.__class__.__name__)
            self.extender.stAddExclusionTextField.setText("")
            self.extender.stAddExclusionTextField.requestFocus()
        self.extender.settings.saveSettings()
        
    def editSourceExclusion(self):
        index = self.extender.sourceExclusionsTable.getSelectedRow()
        if index != -1 :
            exclusionToEdit = self.extender.settings.sourceExclusionsModel.entries[index]
            regexStr = exclusionToEdit.regex.pattern
            result = swing.JOptionPane.showInputDialog(self.extender.tabbedPane, \
                                                    self.extender.stStrings["editExclusionDialog"], \
                                                    "Edit Exclusion", \
                                                    swing.JOptionPane.PLAIN_MESSAGE, \
                                                    None, None, regexStr)
            if result != None:
                try: self.extender.settings.sourceExclusionsModel.editEntryRegex(index, result)
                except Exception as e: self.extender.stderr.println("[-] Failed editing source exclusion: %s" % e.__class__.__name__)
        self.extender.settings.saveSettings()

    def removeSelectedSourceExclusions(self):
        selectedRowIndexes = self.extender.sourceExclusionsTable.getSelectedRows()
        for i in selectedRowIndexes[::-1]: self.extender.settings.sourceExclusionsModel.removeEntry(i)
        self.extender.settings.saveSettings()

    def clearSourceExclusions(self):
        self.extender.settings.sourceExclusionsModel.clearEntries()
        self.extender.settings.saveSettings()

    def loadSourceExclusions(self):
        try:
            result = self.extender.fileChooser.showOpenDialog(self.extender.tabbedPane)
            if result == swing.JFileChooser.APPROVE_OPTION:
                selectedFile = self.extender.fileChooser.getSelectedFile()
                with open(selectedFile.getCanonicalPath(), "r") as infile:
                    regexStrings = [i for i in infile.read().splitlines() if len(i) > 0]
                    for regexStr in regexStrings: self.extender.settings.sourceExclusionsModel.addEntry(regexStr)
        except Exception as e: self.extender.stderr.println("[-] Failed loading source exclusion(s) from file: %s" % e.__class__.__name__)
        self.extender.settings.saveSettings()

    def toggleSourceExclusions(self):
        selectedRowIndexes = self.extender.sourceExclusionsTable.getSelectedRows()
        if len(selectedRowIndexes) > 0:
            self.extender.settings.sourceExclusionsModel.toggleEntries(selectedRowIndexes)
        self.extender.settings.saveSettings()

    def addLinkExclusion(self):
        regexStr = self.extender.stAddExclusion2TextField.getText()
        if len(regexStr) > 0:
            try: self.extender.settings.linkExclusionsModel.addEntry(regexStr)
            except Exception as e: self.extender.stderr.println("[-] Failed adding link exclusion: %s" % e.__class__.__name__)
            self.extender.stAddExclusion2TextField.setText("")
            self.extender.stAddExclusion2TextField.requestFocus()
            self.applyLinkExclusions()
        self.extender.settings.saveSettings()
        
    def editLinkExclusion(self):
        index = self.extender.linkExclusionsTable.getSelectedRow()
        if index != -1 :
            exclusionToEdit = self.extender.settings.linkExclusionsModel.entries[index]
            regexStr = exclusionToEdit.regex.pattern
            result = swing.JOptionPane.showInputDialog(self.extender.tabbedPane, \
                                                    self.extender.stStrings["editExclusionDialog"], \
                                                    "Edit Exclusion", \
                                                    swing.JOptionPane.PLAIN_MESSAGE, \
                                                    None, None, regexStr)
            if result != None:
                try: self.extender.settings.linkExclusionsModel.editEntryRegex(index, result)
                except Exception as e: self.extender.stderr.println("[-] Failed editing link exclusion: %s" % e.__class__.__name__)
                self.applyLinkExclusions()
        self.extender.settings.saveSettings()

    def removeSelectedLinkExclusions(self):
        selectedRowIndexes = self.extender.linkExclusionsTable.getSelectedRows()
        for i in selectedRowIndexes[::-1]: self.extender.settings.linkExclusionsModel.removeEntry(i)
        self.applyLinkExclusions()
        self.extender.settings.saveSettings()

    def clearLinkExclusions(self):
        self.extender.settings.linkExclusionsModel.clearEntries()
        #self.applyLinkExclusions() # has no effect
        self.extender.settings.saveSettings()

    def loadLinkExclusions(self):
        try:
            result = self.extender.fileChooser.showOpenDialog(self.extender.tabbedPane)
            if result == swing.JFileChooser.APPROVE_OPTION:
                selectedFile = self.extender.fileChooser.getSelectedFile()
                with open(selectedFile.getCanonicalPath(), "r") as infile:
                    regexStrings = [i for i in infile.read().splitlines() if len(i) > 0]
                    for regexStr in regexStrings: self.extender.settings.linkExclusionsModel.addEntry(regexStr)
                    self.applyLinkExclusions()
        except Exception as e: self.extender.stderr.println("[-] Failed loading link exclusion(s) from file: %s" % e.__class__.__name__)
        self.extender.settings.saveSettings()
            

    def toggleLinkExclusions(self):
        selectedRowIndexes = self.extender.linkExclusionsTable.getSelectedRows()
        if len(selectedRowIndexes) > 0:
            self.extender.settings.linkExclusionsModel.toggleEntries(selectedRowIndexes)
            self.applyLinkExclusions()
        self.extender.settings.saveSettings()
    
    def applyLinkExclusions(self):
        regexes = [i.regex for i in self.extender.settings.linkExclusionsModel.entries if i.enabled]
        for i in range(self.extender.linksModel.entries.size()-1, -1, -1):
            if any([regex.search(self.extender.linksModel.entries.get(i).url) for regex in regexes]): self.extender.linksModel.entries.remove(i)
        for i in range(self.extender.sourcesModel.entries.size()):
            entry = self.extender.sourcesModel.entries.get(i)
            for j in range(len(entry.links)-1, -1, -1):
                if any([regex.search(entry.links[j].url) for regex in regexes]): del entry.links[j]

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
        if actionEvent.getActionCommand() == "toggleInScopeOnly": self.actionHandler.toggleInScopeOnly()
        elif actionEvent.getActionCommand() == "toggleIgnoreDups": self.actionHandler.toggleIgnoreDups()

        elif actionEvent.getActionCommand() == "toggleToolSelectionProxy": self.actionHandler.toggleToolSelection("proxy")
        elif actionEvent.getActionCommand() == "toggleToolSelectionSpider": self.actionHandler.toggleToolSelection("spider")
        elif actionEvent.getActionCommand() == "toggleToolSelectionScanner": self.actionHandler.toggleToolSelection("scanner")

        elif actionEvent.getActionCommand() == "setProcess0": self.actionHandler.setProcessSetting(0)
        elif actionEvent.getActionCommand() == "setProcess1": self.actionHandler.setProcessSetting(1)
        elif actionEvent.getActionCommand() == "setProcess2": self.actionHandler.setProcessSetting(2)
        
        elif actionEvent.getActionCommand() == "addSourceExclusion": self.actionHandler.addSourceExclusion()
        elif actionEvent.getActionCommand() == "editSourceExclusion": self.actionHandler.editSourceExclusion()
        elif actionEvent.getActionCommand() == "removeSelectedSourceExclusions": self.actionHandler.removeSelectedSourceExclusions()
        elif actionEvent.getActionCommand() == "clearSourceExclusions": self.actionHandler.clearSourceExclusions()
        elif actionEvent.getActionCommand() == "loadSourceExclusions": self.actionHandler.loadSourceExclusions()
        elif actionEvent.getActionCommand() == "toggleSourceExclusions": self.actionHandler.toggleSourceExclusions()

        elif actionEvent.getActionCommand() == "addLinkExclusion": self.actionHandler.addLinkExclusion()
        elif actionEvent.getActionCommand() == "editLinkExclusion": self.actionHandler.editLinkExclusion()
        elif actionEvent.getActionCommand() == "removeSelectedLinkExclusions": self.actionHandler.removeSelectedLinkExclusions()
        elif actionEvent.getActionCommand() == "clearLinkExclusions": self.actionHandler.clearLinkExclusions()
        elif actionEvent.getActionCommand() == "loadLinkExclusions": self.actionHandler.loadLinkExclusions()
        elif actionEvent.getActionCommand() == "toggleLinkExclusions": self.actionHandler.toggleLinkExclusions()

        elif actionEvent.getActionCommand() == "exportAsText": self.actionHandler.exportAsText()
        elif actionEvent.getActionCommand() == "clearFindings": self.actionHandler.clearFindings()
