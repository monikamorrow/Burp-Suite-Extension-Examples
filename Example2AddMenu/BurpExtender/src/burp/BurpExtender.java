package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
import javax.swing.JMenuItem;
import java.util.ArrayList;
import javax.swing.JOptionPane;

public class BurpExtender implements IBurpExtender, IContextMenuFactory
{
    private IBurpExtenderCallbacks mCallbacks;
    private IContextMenuInvocation mInvocation;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("Add Menu Mark & Scan");
        mCallbacks = callbacks;
        
        callbacks.registerContextMenuFactory(this);
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        List<JMenuItem> menuList = new ArrayList<>();
        mInvocation = invocation;
        
        if(mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY) {
            JMenuItem markScan = new JMenuItem("Mark & Scan");
            markScan.addActionListener(new ActionListener() {
               @Override
               public void actionPerformed(ActionEvent arg0) {
                   if(arg0.getActionCommand().equals("Mark & Scan")) {
                       MarkAndScan(mInvocation.getSelectedMessages());
                   }
               }
            });
            menuList.add(markScan);
        }
        
        return menuList;
    }
    
    private void MarkAndScan(IHttpRequestResponse[] messages)
    {
        for(int i=0; i < messages.length; i++) {
            try {
            URL url = new URL(  messages[i].getHttpService().getProtocol(), 
                                messages[i].getHttpService().getHost(),
                                messages[i].getHttpService().getPort(), "");
            if(!mCallbacks.isInScope(url)) {
                int ans = JOptionPane.showConfirmDialog(null, 
                             "This item is not in scope. Would you like to add it?\r\n" +
                                url.toString(), 
                             "Add to Scope?", 
                             JOptionPane.YES_NO_OPTION);
                if(ans == JOptionPane.YES_OPTION) {
                    mCallbacks.includeInScope(url);
                }
            }
            if(mCallbacks.isInScope(url)) {
                mCallbacks.doActiveScan(
                    messages[i].getHttpService().getHost(),
                    messages[i].getHttpService().getPort(), 
                    messages[i].getHttpService().getProtocol().equalsIgnoreCase("HTTPS"),
                    messages[i].getRequest());
                messages[i].setHighlight("pink");
                messages[i].setComment("Sent to scanner");
            }
            } // try
            catch (Exception e) {
                PrintWriter stdErr = new PrintWriter(mCallbacks.getStderr(), true);
                stdErr.println("Error creating URL: " + e.getMessage());
            }
        }
    }
}
