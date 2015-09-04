package burp;

public class BurpExtender extends BurpGUIExtender {
    /**
     * Assign custom values to mPluginName and mUsageStatement
     */
    @Override
    public void init() {
        mPluginName = "MYPROJECT";
        mUsageStatement = "Usage statement for " + mPluginName;
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
        return messageInfo;
    }
}
