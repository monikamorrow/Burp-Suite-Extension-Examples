package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import javax.swing.SwingUtilities;

public abstract class BurpGUIExtender implements IBurpExtender, IExtensionStateListener, IHttpListener, ITab {
    protected String mPluginName = "Plugin Name";
    protected String mUsageStatement = "Usage Statement";
    protected IBurpExtenderCallbacks mCallbacks;
    protected IExtensionHelpers mHelper;
    protected PrintWriter mStdOut;
    protected PrintWriter mStdErr;
    protected BurpSuiteTab mTab;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        init();
        mCallbacks = callbacks;
        mHelper = mCallbacks.getHelpers();
        
        callbacks.setExtensionName(mPluginName);
        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerHttpListener(this); // For processHttpMessage
        
        callbacks.registerExtensionStateListener(this); // For notification of unload extension
        
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run(){
                mTab = new BurpSuiteTab(mCallbacks);
                mCallbacks.customizeUiComponent(mTab);
                mCallbacks.addSuiteTab(BurpGUIExtender.this);
            }
        });
        mStdOut.println("Settings for " + mPluginName + " can be edited in the " + mPluginName + " tab.");
        mStdOut.println(mUsageStatement);
    }
    
    @Override
    public void extensionUnloaded() {
        mTab.saveSettings();
    }
            
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
        URL url = new URL(messageInfo.getHttpService().getProtocol(),
                          messageInfo.getHttpService().getHost(),
                          messageInfo.getHttpService().getPort(), "");
        
        if((mCallbacks.isInScope(url) || mTab.processAllRequests()) 
            && mTab.isToolSelected(toolFlag)) {
            processSelectedMessage(messageInfo, messageIsRequest);
        }
        } catch(MalformedURLException e) {
            mStdErr.println("Error creating URL: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return mPluginName;
    }

    @Override
    public Component getUiComponent() {
        return mTab;
    }
    
    protected abstract void init();
    
    protected abstract IHttpRequestResponse processSelectedMessage(IHttpRequestResponse messageInfo, boolean isRequest);
}
