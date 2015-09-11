package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    private final String mPluginName = "Plugin Name";
    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelper;
    private PrintWriter mStdOut;
    private PrintWriter mStdErr;
    private BurpSuiteTab mTab;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        mCallbacks = callbacks;
        mHelper = mCallbacks.getHelpers();
        
        callbacks.setExtensionName(mPluginName);
        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerHttpListener(this); // For processHttpMessage
        
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run(){
                mTab = new BurpSuiteTab(mPluginName, mCallbacks);
                mCallbacks.customizeUiComponent(mTab);
                mCallbacks.addSuiteTab(mTab);
            }
        });
        mStdOut.println("Settings for " + mPluginName + " can be edited in the " + mPluginName + " tab.");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
        URL url = new URL(messageInfo.getHttpService().getProtocol(),
                          messageInfo.getHttpService().getHost(),
                          messageInfo.getHttpService().getPort(), "");
        
        if((mCallbacks.isInScope(url) 
            || mTab.processAllRequests()) 
            && mTab.isToolSelected(toolFlag))
        {
            if(messageIsRequest)
            {
                String retMessage = doSpecialThing(messageInfo);
                messageInfo.setRequest(retMessage.getBytes());
            }
            else
            {
                // Response handling goes here
            }
        }
        } //try
        catch(MalformedURLException e) {
            mStdErr.println("Error creating URL: " + e.getMessage());
        }
    }

    private String doSpecialThing(IHttpRequestResponse messageInfo)
    {
        String requestStr = mHelper.bytesToString(messageInfo.getRequest());
        mStdOut.println("doSpecialThing triggered.");
        return requestStr;
    }
}
