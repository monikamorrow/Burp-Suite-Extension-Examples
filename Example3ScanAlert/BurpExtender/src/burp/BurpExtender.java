package burp;

import java.awt.Toolkit;
import java.util.Timer;
import java.util.TimerTask;
import javax.swing.JOptionPane;

public class BurpExtender extends TimerTask implements IBurpExtender, IHttpListener
{
    private long mScanTime;
    private Timer mTimer;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("Scan Alert");
        mScanTime = 0;
        
        mTimer = new Timer();
        mTimer.scheduleAtFixedRate(this, 0, 5000);

        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // If Scanner Update/Check Time
        if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER &&
           messageIsRequest)
        {
            // Start or Update the Timer
            mScanTime = System.currentTimeMillis();            
        }
    }
    
    @Override
    public void run()
    {
        if(mScanTime > 0 && 
          (System.currentTimeMillis() - mScanTime) > 30000)
        {
            Toolkit.getDefaultToolkit().beep();
            JOptionPane.showMessageDialog(null,
                                    "Scanner is finished!",
                                    "Scanner Finished",
                                    JOptionPane.INFORMATION_MESSAGE);
            mScanTime = 0;
        }
    }
}
