package com.monikamorrow.burp;

import burp.ITab;
import burp.IBurpExtenderCallbacks;
import java.awt.Component;
import javax.swing.JPanel;

public class BurpSuiteTab extends javax.swing.JPanel implements ITab {
    IBurpExtenderCallbacks mCallbacks;
    String tabName; 
    JPanel userDefinedPanel;
    
    /**
     * Creates new form BurpSuiteTab
     * @param tabName   The name displayed on the tab
     * @param callbacks For UI Look and Feel
     */
    public BurpSuiteTab(String tabName, IBurpExtenderCallbacks callbacks) {
        this(new JPanel(), tabName, callbacks);
    }
    
    /**
     * Creates new form BurpSuiteTab
     * @param customPanel The panel to be added to the GUI
     * @param tabName     The name displayed on the tab
     * @param callbacks   For UI Look and Feel
     */
    public BurpSuiteTab(JPanel customPanel, String tabName, IBurpExtenderCallbacks callbacks) {
	this.tabName = tabName;
        mCallbacks = callbacks;
        
        userDefinedPanel = (JPanel) this.add(customPanel);
        this.doLayout();
        userDefinedPanel.setLocation(275, 0);
        
	initComponents();
        mCallbacks.customizeUiComponent(jRadioButtonInScopeRequests);
        mCallbacks.customizeUiComponent(jRadioButtonAllRequests);
        
        mCallbacks.customizeUiComponent(jCheckBoxProxy);
        mCallbacks.customizeUiComponent(jCheckBoxRepeater);
        mCallbacks.customizeUiComponent(jCheckBoxScanner);
        mCallbacks.customizeUiComponent(jCheckBoxIntruder);
        mCallbacks.customizeUiComponent(jCheckBoxSequencer);
        mCallbacks.customizeUiComponent(jCheckBoxSpider);
        
        jCheckBoxProxy.setBackground(jRadioButtonInScopeRequests.getBackground());
        jCheckBoxRepeater.setBackground(jRadioButtonInScopeRequests.getBackground());
        jCheckBoxScanner.setBackground(jRadioButtonInScopeRequests.getBackground());
        jCheckBoxIntruder.setBackground(jRadioButtonInScopeRequests.getBackground());
        jCheckBoxSequencer.setBackground(jRadioButtonInScopeRequests.getBackground());
        jCheckBoxSpider.setBackground(jRadioButtonInScopeRequests.getBackground());
        
        buttonGroupDefineScope.add(jRadioButtonInScopeRequests);
        buttonGroupDefineScope.add(jRadioButtonAllRequests);
        
        restoreSavedSettings();
    }

    /**
     * Restores any found saved settings
     * @return 
     */
    public void restoreSavedSettings() {
        boolean proxySel = false;
        boolean repeaterSel = false;
        boolean scannerSel = false;
        boolean intruderSel = false;
        boolean sequencerSel = false;
        boolean spiderSel = false;
        boolean scopeAllSel = false;
        
        if(mCallbacks.loadExtensionSetting("O_TOOL_PROXY") != null ) {
            proxySel = getSetting("O_TOOL_PROXY");
        }
        if(mCallbacks.loadExtensionSetting("O_TOOL_REPEATER") != null ) {
            repeaterSel = getSetting("O_TOOL_REPEATER");
        }
        if(mCallbacks.loadExtensionSetting("O_TOOL_SCANNER") != null ) {
            scannerSel = getSetting("O_TOOL_SCANNER");
        }
        if(mCallbacks.loadExtensionSetting("O_TOOL_INTRUDER") != null ) {
            intruderSel = getSetting("O_TOOL_INTRUDER");
        }
        if(mCallbacks.loadExtensionSetting("O_TOOL_SEQUENCER") != null ) {
            sequencerSel = getSetting("O_TOOL_SEQUENCER");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_SPIDER") != null ) {
            spiderSel = getSetting("O_TOOL_SPIDER");
        }
        if(mCallbacks.loadExtensionSetting("O_SCOPE") != null ) {
            scopeAllSel = getSetting("O_SCOPE");
        }
        jCheckBoxProxy.setSelected(proxySel);
        jCheckBoxRepeater.setSelected(repeaterSel);
        jCheckBoxScanner.setSelected(scannerSel);
        jCheckBoxIntruder.setSelected(intruderSel);
        jCheckBoxSequencer.setSelected(sequencerSel);
        jCheckBoxSpider.setSelected(spiderSel);
        jRadioButtonAllRequests.setSelected(scopeAllSel);
    }
    
    /**
     * Get the boolean value of the requested setting
     * @param name
     * @return whether the setting was selected
     */
    private boolean getSetting(String name) {
        if(name.equals("O_SCOPE") && mCallbacks.loadExtensionSetting(name).equals("ALL") == true) {
            return true;
        }
        else return mCallbacks.loadExtensionSetting(name).equals("ENABLED") == true;
    }

    /**
     * Save all configured settings
     */
    public void saveSettings() {
        // Clear settings
        mCallbacks.saveExtensionSetting("O_TOOL_PROXY", null);
        mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", null);
        mCallbacks.saveExtensionSetting("O_SCOPE", null);
        // Set any selected checkboxes in settings
        if(jCheckBoxProxy.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_PROXY", "ENABLED");
        }
        if(jCheckBoxRepeater.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", "ENABLED");
        }
        if(jCheckBoxScanner.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", "ENABLED");
        }
        if(jCheckBoxIntruder.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", "ENABLED");
        }
        if(jCheckBoxSequencer.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", "ENABLED");
        }
        if(jCheckBoxSpider.isSelected()) {
            mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", "ENABLED");
        }
        if(jRadioButtonAllRequests.isSelected()) {
            mCallbacks.saveExtensionSetting("O_SCOPE", "ALL");
        }
    }
    
    /**
     * Returns true if all response times should be calculated
     * @return true if the GUI indicates all requests should be processed
     */
    public boolean processAllRequests() {
        return jRadioButtonAllRequests.isSelected();
    }
    /**
     * Returns true if the requested tool is selected in the GUI
     * @param tool
     * @return whether the selected tool is selected
     */
    public boolean isToolSelected(int tool) {
        boolean selected = false;
        switch (tool) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                selected = jCheckBoxProxy.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                selected = jCheckBoxRepeater.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                selected = jCheckBoxScanner.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                selected = jCheckBoxIntruder.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                selected = jCheckBoxSequencer.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                selected = jCheckBoxSpider.isSelected();
                break;
            case IBurpExtenderCallbacks.TOOL_TARGET:
                break;
            default:
                break;
        }
        return selected;
    }   
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroupDefineScope = new javax.swing.ButtonGroup();
        buttonGroupChars = new javax.swing.ButtonGroup();
        jLabel1 = new javax.swing.JLabel();
        jRadioButtonInScopeRequests = new javax.swing.JRadioButton();
        jRadioButtonAllRequests = new javax.swing.JRadioButton();
        jCheckBoxProxy = new javax.swing.JCheckBox();
        jCheckBoxRepeater = new javax.swing.JCheckBox();
        jCheckBoxScanner = new javax.swing.JCheckBox();
        jCheckBoxIntruder = new javax.swing.JCheckBox();
        jCheckBoxSequencer = new javax.swing.JCheckBox();
        jCheckBoxSpider = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(229, 137, 0));
        jLabel1.setText("Tools Scope");

        jRadioButtonInScopeRequests.setSelected(true);
        jRadioButtonInScopeRequests.setText("In scope requests");

        jRadioButtonAllRequests.setText("All requests");

        jCheckBoxProxy.setSelected(true);
        jCheckBoxProxy.setText("Proxy");

        jCheckBoxRepeater.setSelected(true);
        jCheckBoxRepeater.setText("Repeater");

        jCheckBoxScanner.setText("Scanner");

        jCheckBoxIntruder.setText("Intruder");

        jCheckBoxSequencer.setText("Sequencer");

        jCheckBoxSpider.setText("Spider");

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(229, 137, 0));
        jLabel3.setText("URL Scope");

        jLabel4.setText("Select the tools that this extenstion will act on:");

        jLabel5.setText("Select the configuration this extenstion will act on:");

        jLabel2.setText("jLabel2");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(jLabel2)
                .addContainerGap(307, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel2)
                .addContainerGap(381, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel4)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel5)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jCheckBoxProxy)
                                    .addComponent(jCheckBoxRepeater)
                                    .addComponent(jCheckBoxScanner))
                                .addGap(22, 22, 22)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jCheckBoxSpider)
                                    .addComponent(jCheckBoxSequencer)
                                    .addComponent(jCheckBoxIntruder))))
                        .addComponent(jRadioButtonInScopeRequests)
                        .addComponent(jRadioButtonAllRequests)))
                .addGap(34, 34, 34)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(35, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jCheckBoxProxy)
                            .addComponent(jCheckBoxIntruder))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jCheckBoxRepeater)
                            .addComponent(jCheckBoxSequencer))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jCheckBoxScanner)
                            .addComponent(jCheckBoxSpider))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jRadioButtonInScopeRequests)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jRadioButtonAllRequests)))
                .addContainerGap(37, Short.MAX_VALUE))
        );

        jLabel1.getAccessibleContext().setAccessibleDescription("");
        jLabel5.getAccessibleContext().setAccessibleName("Select the configuration this extenstion applies to:");
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroupChars;
    private javax.swing.ButtonGroup buttonGroupDefineScope;
    private javax.swing.JCheckBox jCheckBoxIntruder;
    private javax.swing.JCheckBox jCheckBoxProxy;
    private javax.swing.JCheckBox jCheckBoxRepeater;
    private javax.swing.JCheckBox jCheckBoxScanner;
    private javax.swing.JCheckBox jCheckBoxSequencer;
    private javax.swing.JCheckBox jCheckBoxSpider;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JRadioButton jRadioButtonAllRequests;
    private javax.swing.JRadioButton jRadioButtonInScopeRequests;
    // End of variables declaration//GEN-END:variables

    @Override
    public String getTabCaption() {
	return tabName;
    }

    @Override
    public Component getUiComponent() {
	return this;
    }
}
