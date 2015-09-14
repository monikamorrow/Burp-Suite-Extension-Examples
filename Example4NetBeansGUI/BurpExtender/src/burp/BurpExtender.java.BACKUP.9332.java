package burp;

<<<<<<< HEAD
public class BurpExtender extends BurpGUIExtender {
    /**
     * Assign custom values to mPluginName and mUsageStatement
     */
    @Override
    public void init() {
        mPluginName = "MYPROJECT";
        mUsageStatement = "Usage statement for " + mPluginName;
=======
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
>>>>>>> master
    }
    /**
     * Process all Burp requests/responses as indicated in the configuration tab
     * 
     * The request and response along with auxiliary information such as any 
     * comments and highlight states are available. See IHttpRequestResponse
     * documentation for information on limitations.
     *
     * @param  messageInfo The contents of a messageInfo object that meets the criteria for processing
     * @param  isRequest   boolean indicating if the messageInfo object is a request or response
     * @return The modified messageInfo object
     */
    @Override
    protected IHttpRequestResponse processSelectedMessage(IHttpRequestResponse messageInfo, boolean isRequest) {
        if(isRequest) {
            mStdOut.println("processSelectedMessage triggered for request");
            messageInfo.setComment("Request processed");
        } else {
            mStdOut.println("processSelectedMessage triggered for response");
            messageInfo.setComment(messageInfo.getComment() + "/Response processed");
        }
<<<<<<< HEAD
        return messageInfo;
=======
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
>>>>>>> master
    }
}
