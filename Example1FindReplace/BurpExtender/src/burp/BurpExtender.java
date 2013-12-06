package burp;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.StringReader;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    private PrintWriter mStdOut;
    private PrintWriter mStdErr;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("Find & Replace");

        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.registerHttpListener(this);
    }
    
    @Override
    public void processHttpMessage(int toolFlag,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo)
    {
        mStdOut.println("processHttpMessage called");
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY)
        {
            if(messageIsRequest)
            {
                messageInfo = MyCustomFunctionFindReplace(messageInfo);
            }
        }     
    }
    
    private IHttpRequestResponse MyCustomFunctionFindReplace(IHttpRequestResponse messageInfo)
    {
        String message = new String(messageInfo.getRequest());
        
        String search = "ReplaceMe";
        String replace = "" + System.currentTimeMillis();
        StringBuilder newString = new StringBuilder(message.length() - search.length() + replace.length());
        
        try {
            BufferedReader reader = new BufferedReader(new StringReader(message));
            String line;

            while((line = reader.readLine()) != null) {
                if(line != null) {
                    if(line.contains(search)) {
                        line = line.replaceAll(search, replace);
                    }
                    newString.append(line).append("\r\n");                 }
            }
        }
        catch (Exception e) {
            mStdErr.println("Error replacing text: " + e.getMessage());
        }
        
        messageInfo.setRequest(newString.toString().getBytes());
        return messageInfo;
    }
    
}
