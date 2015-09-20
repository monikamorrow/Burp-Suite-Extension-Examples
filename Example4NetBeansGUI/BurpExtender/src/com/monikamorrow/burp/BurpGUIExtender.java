package com.monikamorrow.burp;

import burp.IBurpExtender;
import burp.IExtensionStateListener;
import burp.IHttpListener;
import burp.ITab;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import java.awt.Component;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;

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
        
        mTab = new BurpSuiteTab(mPluginName, mCallbacks);
        mCallbacks.customizeUiComponent(mTab); // Is this needed? ::TODO::
        mCallbacks.addSuiteTab(mTab);
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
    
    /**
     * Override to assign custom values to mPluginName and mUsageStatement
     */
    protected abstract void init();
    
    /**
     * Override to process all Burp requests/responses as indicated in the configuration tab
     * 
     * The request and response along with auxiliary information such as any 
     * comments and highlight states are available. See IHttpRequestResponse
     * documentation for information on limitations.
     *
     * @param  messageInfo The contents of a messageInfo object that meets the criteria for processing
     * @param  isRequest   boolean indicating if the messageInfo object is a request or response
     * @return The modified messageInfo object
     */
    protected abstract IHttpRequestResponse processSelectedMessage(IHttpRequestResponse messageInfo, boolean isRequest);
}
