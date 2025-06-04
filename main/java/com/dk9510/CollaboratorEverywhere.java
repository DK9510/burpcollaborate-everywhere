package com.dk9510;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.collaborator.DnsQueryType;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class CollaboratorEverywhere implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private CollaboratorClient client;
    private Map<String, PayloadInfo> payloadMap;
    private List<InjectionRule> injectionRules;
    private DefaultTableModel tableModel;
    private ScheduledExecutorService executor;

    private static class PayloadInfo {
        String url;
        String type;
        String name;
        String valueTemplate;
        String requestId;

        PayloadInfo(String url, String type, String name, String valueTemplate, String requestId) {
            this.url = url;
            this.type = type;
            this.name = name;
            this.valueTemplate = valueTemplate;
            this.requestId = requestId;
        }
    }

    private static class InjectionRule {
        String type;
        String name;
        String valueTemplate;

        InjectionRule(String type, String name, String valueTemplate) {
            this.type = type;
            this.name = name;
            this.valueTemplate = valueTemplate;
        }
    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.logging = api.logging();
        this.payloadMap = new HashMap<>();
        this.injectionRules = new ArrayList<>();

        try {
            this.client = api.collaborator().createClient();
            logging.logToOutput("CollaboratorClient created successfully");
        } catch (Exception e) {
            logging.logToError("Error creating CollaboratorClient: " + e.getMessage());
            return;
        }

        loadInjectionRules();
        api.extension().setName("Collaborator Everywhere");
        api.http().registerHttpHandler(new CollaboratorHttpHandler());
        setupUI(api.userInterface());

        // Start polling for interactions
        startInteractionPolling();
    }

    private void setupUI(UserInterface ui) {
        JTabbedPane tabbedPane = new JTabbedPane();

        // Log tab
        String[] columnNames = { "Payload", "URL", "Type", "Name", "Client IP", "Interaction Type", "Timestamp", "Nonce ID" };
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        JScrollPane logScrollPane = new JScrollPane(table);
        tabbedPane.addTab("Log", logScrollPane);

        // Configuration tab
        JPanel configPanel = new JPanel(new GridLayout(0, 1));
        JTextField typeField = new JTextField(10);
        JTextField nameField = new JTextField(10);
        JTextField valueField = new JTextField(10);
        JButton addButton = new JButton("Add Rule");

        configPanel.add(new JLabel("Type (header/param):"));
        configPanel.add(typeField);
        configPanel.add(new JLabel("Name:"));
        configPanel.add(nameField);
        configPanel.add(new JLabel("Value Template (use %s for payload):"));
        configPanel.add(valueField);
        configPanel.add(addButton);

        addButton.addActionListener(e -> {
            String type = typeField.getText().trim();
            String name = nameField.getText().trim();
            String valueTemplate = valueField.getText().trim();
            if (!type.isEmpty() && !name.isEmpty() && !valueTemplate.isEmpty()) {
                injectionRules.add(new InjectionRule(type, name, valueTemplate));
                logging.logToOutput("Added new rule: " + type + ", " + name + ", " + valueTemplate);
                typeField.setText("");
                nameField.setText("");
                valueField.setText("");
            } else {
                logging.logToError("Invalid rule: Type, Name, and Value Template must not be empty");
            }
        });

        tabbedPane.addTab("Configuration", configPanel);

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        ui.registerSuiteTab("Collaborator Everywhere Log", mainPanel);
        logging.logToOutput("UI setup complete. To correlate requests, filter by 'X-Collaborator-Request-ID' in Burp's Logger UI.");
    }

    private void loadInjectionRules() {
        injectionRules.add(new InjectionRule("param", "u", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "href", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "action", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "host", "%s"));
        injectionRules.add(new InjectionRule("param", "http_host", "%s"));
        injectionRules.add(new InjectionRule("param", "email", "root@%s"));
        injectionRules.add(new InjectionRule("param", "url", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "load", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "preview", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "target", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "proxy", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "from", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "src", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "ref", "https://%s/"));
        injectionRules.add(new InjectionRule("param", "referrer", "https://%s/"));
        injectionRules.add(new InjectionRule("header", "Contact", "root@%s"));
        injectionRules.add(new InjectionRule("header", "From", "root@%s"));
        injectionRules.add(new InjectionRule("header", "User-Agent", "root@%s"));
        injectionRules.add(new InjectionRule("header", "Referer", "https://%s"));
        injectionRules.add(new InjectionRule("header", "X-Wap-Profile", "https://%s/wap.xml"));
        injectionRules.add(new InjectionRule("header", "X-Forwarded-For", "%s"));
        injectionRules.add(new InjectionRule("header", "True-Client-IP", "%s"));
        injectionRules.add(new InjectionRule("header", "Client-IP", "%s"));
        injectionRules.add(new InjectionRule("header", "X-Client-IP", "%s"));
        injectionRules.add(new InjectionRule("header", "X-Real-IP", "%s"));
        injectionRules.add(new InjectionRule("header", "X-Originating-IP", "%s"));
        injectionRules.add(new InjectionRule("header", "CF-Connecting_IP", "%s"));
        injectionRules.add(new InjectionRule("header", "Forwarded", "for=%s;by=%s;host=%s"));
        logging.logToOutput("Injection rules loaded: " + injectionRules.size());
    }

    private void startInteractionPolling() {
        executor = Executors.newScheduledThreadPool(1);
        executor.scheduleAtFixedRate(this::pollInteractions, 0, 60, TimeUnit.SECONDS);
    }

    private String processDNSQuery(Interaction interaction) {
        String hostvalue = null; 
        if (interaction.dnsDetails().isPresent()) {
            DnsDetails dnsQueryDetails = interaction.dnsDetails().get();
            ByteArray dnsQueryByteArray = dnsQueryDetails.query();
            hostvalue = decodeDnsQuery(dnsQueryByteArray); // decodeDnsQuery is expected to return non-null String (hostname or error string)
            
            if (hostvalue != null) { 
                // Log the raw decoded value before toLowerCase, as toLowerCase might not be ideal for error strings like "Invalid..."
                logging.logToOutput("Decoded DNS Query: " + hostvalue);
                return hostvalue.toLowerCase();
            }
        }
        // If dnsDetails is not present, or if decodeDnsQuery somehow returned null
        return null; 
    }

    // Helper method to decode DNS query ByteArray into a hostname
    private String decodeDnsQuery(ByteArray byteArray) {
        byte[] bytes = byteArray.getBytes();
        StringBuilder hostname = new StringBuilder();
        int index = 0;

        // Skip the first 12 bytes (DNS header)
        if (bytes.length < 12) {
            return "Invalid DNS query";
        }
        index = 12;

        // Parse the QNAME field (hostname) in the DNS query
        while (index < bytes.length && bytes[index] != 0) {
            int labelLength = bytes[index] & 0xFF; // Convert to unsigned
            index++;
            if (index + labelLength > bytes.length) {
                return "Invalid DNS query format";
            }
            // Append the label characters
            for (int i = 0; i < labelLength; i++) {
                hostname.append((char) bytes[index++]);
            }
            // Add a dot between labels (if not at the end)
            if (index < bytes.length && bytes[index] != 0) {
                hostname.append('.');
            }
        }

        return hostname.length() > 0 ? hostname.toString().toLowerCase() : "Empty DNS query";
    }

    private String processCollaboratorInteractionRequest(Interaction interaction) {
        String hostvalue = null; // Initialize to null
        // Check if httpDetails is present
        if (interaction.httpDetails().isPresent()) {
            // Get the HttpDetails interface implementation
            HttpDetails httpDetails = interaction.httpDetails().get();
            // Get the HttpRequestResponse interface implementation
            HttpRequestResponse httpRequestResponse = httpDetails.requestResponse();
            
            // Ensure request is not null and the header exists before trying to access its value
            if (httpRequestResponse.request() != null && httpRequestResponse.request().hasHeader("Host")) {
                hostvalue = httpRequestResponse.request().header("Host").value().toLowerCase();
            }
        }
        return hostvalue; // Return the extracted hostvalue (or null if not found)
    }

    private void pollInteractions() {
        try {
            logging.logToOutput("Starting interaction polling at " + Instant.now());
            List<Interaction> interactions = client.getAllInteractions();
             
            logging.logToOutput("Retrieved " + interactions.size() + " interactions from Collaborator server");
            for (Interaction interaction : interactions) {
                String hostvalue = processCollaboratorInteractionRequest(interaction);
                String dnsvalue = processDNSQuery(interaction); // Assuming processDNSQuery handles null/empty and returns it lowercased or consistently
                
                String payloadKey = "Unmatched"; // Initialize with a default

                if (interaction.type().equals(InteractionType.HTTP)) {
                    if (hostvalue != null) {
                        String[] parts = hostvalue.split("\\.");
                        if (parts.length >= 2) {
                            payloadKey = parts[0] + "." + parts[1]; // Expected: nonce.collaboratorsubdomain
                        } else {
                            payloadKey = "UnmatchedHttpFormat_" + hostvalue;
                        }
                    } else {
                        payloadKey = "UnmatchedHttpNullHost";
                    }
                } else if (interaction.type().equals(InteractionType.DNS)) {
                    if (dnsvalue != null && !dnsvalue.isEmpty()) { // dnsvalue is already lowercased by processDNSQuery
                        String[] parts = dnsvalue.split("\\.");
                        if (parts.length >= 2) {
                            payloadKey = parts[0] + "." + parts[1]; // Expected: nonce.collaboratorsubdomain
                        } else {
                            payloadKey = "UnmatchedDnsFormat_" + dnsvalue;
                        }
                    } else {
                        payloadKey = "UnmatchedDnsNullOrEmpty";
                    }
                } else {
                    // Potentially handle other interaction types or log them
                    payloadKey = "UnmatchedInteractionType_" + interaction.type().toString();
                }
                                    
                logging.logToOutput("Processing interaction: derived payloadKey='" + payloadKey + "', type=" + interaction.type() +", clientIP=" + (interaction.clientIp() != null ? interaction.clientIp().toString() : "Unknown") +", timestamp=" + (interaction.timeStamp() != null ? interaction.timeStamp().toString() : "Unknown"));
                
                PayloadInfo info = null;
                if (!payloadKey.startsWith("Unmatched")) {
                    info = payloadMap.get(payloadKey);
                }

                if (info != null) {
                    logging.logToOutput("Found matching PayloadInfo for key "+ payloadKey +": URL=" + info.url + ", type=" + info.type + ", name=" + info.name + ", requestId=" + info.requestId);
                    boolean exists = false;
                    String displayablePayloadPart = "ErrorInPayloadKeyFormat";
                    if (payloadKey.contains(".")) {
                         String[] payloadKeyParts = payloadKey.split("\\.");
                         if (payloadKeyParts.length >= 2) {
                            displayablePayloadPart = payloadKeyParts[1]; // This is 'collaboratorsubdomain'
                         }
                    }


                    for (int i = 0; i < tableModel.getRowCount(); i++) {
                        Object tablePayloadObj = tableModel.getValueAt(i, 0);
                        Object tableRequestIdObj = tableModel.getValueAt(i, 7); // Column 7 is Request ID

                        if (tablePayloadObj instanceof String && tablePayloadObj.equals(displayablePayloadPart) &&
                            tableRequestIdObj instanceof String && tableRequestIdObj.equals(info.requestId)) {
                            exists = true;
                            break;
                        }
                    }

                    if (!exists) {
                        String clientIP = interaction.clientIp() != null ? interaction.clientIp().toString() : "Unknown";
                        String interactionTypeStr = interaction.type().toString(); // Renamed to avoid conflict if a field 'interactionType' exists
                        String timestampStr = interaction.timeStamp() != null ? interaction.timeStamp().toString() : "Unknown"; // Renamed
                        String currentRequestId = info.requestId; // Extracted from info
                        
                        final String finalDisplayablePayloadPart = displayablePayloadPart;
                        final String finalUrl = info.url;
                        final String finalType = info.type;
                        final String finalName = info.name;
                        final String finalClientIP = clientIP;
                        final String finalInteractionType = interactionTypeStr;
                        final String finalTimestamp = timestampStr;
                        final String finalRequestId = currentRequestId;

                        SwingUtilities.invokeLater(() -> {
                            tableModel.addRow(new Object[]{
                                finalDisplayablePayloadPart, 
                                finalUrl,
                                finalType,
                                finalName,
                                finalClientIP,
                                finalInteractionType,
                                finalTimestamp,
                                finalRequestId
                            });
                            logging.logToOutput("Added new row to table for displayable payload: " + finalDisplayablePayloadPart + ", requestId: " + finalRequestId);
                        });
                    } else {
                        logging.logToOutput("Interaction already exists in table for displayable payload: " + displayablePayloadPart + ", requestId: " + info.requestId);
                    }
                } else { // This means info is null, either payloadKey was "Unmatched..." or not found in map
                    logging.logToOutput("No PayloadInfo found for payload key: " + payloadKey + ", logging as unmatched or original format was problematic.");
                    String clientIP = interaction.clientIp() != null ? interaction.clientIp().toString() : "Unknown";
                    String interactionTypeStr = interaction.type().toString(); // Renamed
                    String timestampStr = interaction.timeStamp() != null ? interaction.timeStamp().toString() : "Unknown"; // Renamed
                    
                    final String finalPayloadKeyForTable = payloadKey; 
                    final String finalClientIP = clientIP;
                    final String finalInteractionType = interactionTypeStr;
                    final String finalTimestamp = timestampStr;

                    SwingUtilities.invokeLater(() -> {
                        tableModel.addRow(new Object[]{
                            finalPayloadKeyForTable, 
                            "Unmatched",
                            "N/A",
                            "N/A",
                            finalClientIP,
                            finalInteractionType,
                            finalTimestamp,
                            "N/A"
                        });
                        logging.logToOutput("Added unmatched/error interaction to table for payload key: " + finalPayloadKeyForTable);
                    });
                }
            }
            logging.logToOutput("Completed interaction polling cycle");
        } catch (Exception e) {
            logging.logToError("Error during interaction polling: " + e.getMessage());
        }
    }

    private void stopInteractionPolling() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
        }
    }


    public static String generateRandomAlphanumericString(int length) {
        String characters = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            sb.append(characters.charAt(randomIndex));
        }

        return sb.toString(); }
        private class CollaboratorHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (!api.scope().isInScope(requestToBeSent.url())) {
                // logging.logToOutput("Skipping request, not in scope: " + requestToBeSent.url());
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            HttpRequest modifiedRequest = requestToBeSent;
            List<HttpParameter> parameters = new ArrayList<>();
            List<String> injected = new ArrayList<>();
            String requestId = generateRandomAlphanumericString(10);

            try {
                logging.logToOutput("Processing request for URL: " + requestToBeSent.url() + ", requestId: " + requestId);
                modifiedRequest = modifiedRequest.withAddedHeader(HttpHeader.httpHeader("X-Collaborator-Request-ID", requestId));
                boolean isProxyRequest = requestToBeSent.toolSource().isFromTool(ToolType.PROXY);
                CollaboratorPayload payload = client.generatePayload();
                    String fullGeneratedPayload = payload.toString(); // e.g., fsjkdfnrsbgknfd.oastify.com
                    String payloadKey = fullGeneratedPayload.split("\\.")[0]; // e.g., fsjkdfnrsbgknfd - This is the map key
                    logging.logToOutput( fullGeneratedPayload + "::" + payloadKey);

                for (InjectionRule rule : injectionRules) {
                    if (isProxyRequest && rule.type.equals("param")) {
                        continue; // Skip parameter injection for Proxy requests
                    }
                    String nonce = generateRandomAlphanumericString(10);
                    String value = rule.valueTemplate.replace("%s", nonce+"."+fullGeneratedPayload); // Inject the FULL payload

                    if (rule.type.equals("header")) {
                        HttpHeader existing = requestToBeSent.header(rule.name);
                        if (existing != null) {
                            modifiedRequest = modifiedRequest.withUpdatedHeader(rule.name, value);
                        } else {
                            modifiedRequest = modifiedRequest.withAddedHeader(HttpHeader.httpHeader(rule.name, value));
                        }
                    } else if (rule.type.equals("param")) {
                        parameters.add(HttpParameter.parameter(rule.name, value, HttpParameterType.URL));
                    }
                    payloadMap.put(nonce +"."+ payloadKey, new PayloadInfo(
                            requestToBeSent.url(), rule.type, rule.name, rule.valueTemplate,
                            nonce));
                    logging.logToOutput("Stored payload in map: " + payloadKey + " (from " + fullGeneratedPayload + ") for " + rule.name + " (" + rule.type + "), requestId: " + nonce);
                    injected.add(payloadKey);
                }

                if (!parameters.isEmpty() && !isProxyRequest) {
                    modifiedRequest = modifiedRequest.withAddedParameters(parameters);
                }

            } catch (Exception e) {
                logging.logToError("Injection error: " + e.getMessage());
            }

            if (!injected.isEmpty()) {
                logging.logToOutput("Injected " + injected.size() + " payloads into " + requestToBeSent.url() + ", requestId: " + requestId);
            }

            return RequestToBeSentAction.continueWith(modifiedRequest);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}