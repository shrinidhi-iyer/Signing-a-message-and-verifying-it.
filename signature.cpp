import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * DigitalSignatureApp.java
 * Final version with a completely new, professional UI and MySQL integration.
 */
public class DigitalSignatureApp extends JFrame {

    //region --- Core Logic (Exceptions, Keys, Services) ---

    // ----------------------------
    // Exceptions
    // ----------------------------
    static class CryptoException extends Exception {
        public CryptoException(String msg) { super(msg); }
    }
    static class KeyNotFoundException extends CryptoException {
        public KeyNotFoundException(String msg) { super(msg); }
    }

    // ----------------------------
    // Key Data Structures
    // ----------------------------
    static class StoredPublicKey {
        private final String keyId;
        private final byte[] encodedKey;
        private final Timestamp createdAt;

        public StoredPublicKey(String id, byte[] encodedKey, Timestamp createdAt) {
            this.keyId = id;
            this.encodedKey = encodedKey;
            this.createdAt = createdAt;
        }

        public String getKeyId() { return keyId; }
        public byte[] getEncodedKey() { return encodedKey; }
        public Timestamp getCreatedAt() { return createdAt; }

        public PublicKey toPublicKey() throws CryptoException {
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
                return kf.generatePublic(spec);
            } catch (Exception e) {
                throw new CryptoException("Failed to rebuild public key: " + e.getMessage());
            }
        }
    }

    static class GeneratedKeyPair {
        private final String keyId;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        public GeneratedKeyPair(String keyId, PrivateKey priv, PublicKey pub) {
            this.keyId = keyId;
            this.privateKey = priv;
            this.publicKey = pub;
        }
        public String getKeyId() { return keyId; }
        public PrivateKey getPrivateKey() { return privateKey; }
        public PublicKey getPublicKey() { return publicKey; }
    }

    // ----------------------------
    // Database Service (MySQL)
    // ----------------------------
    static class KeyStoreDB {
        private static final String DB_URL = "jdbc:mysql://localhost:3306/digital_signatures";
        private static final String DB_USER = "root";
        private static final String DB_PASSWORD = "shri2006"; // YOUR PASSWORD IS SET HERE

        private Connection getConnection() throws SQLException {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
            } catch (ClassNotFoundException e) {
                throw new SQLException("MySQL JDBC Driver not found!", e);
            }
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        }

        public void put(GeneratedKeyPair gkp) {
            String sql = "INSERT INTO public_keys (key_id, public_key_base64) VALUES (?, ?)";
            try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, gkp.getKeyId());
                pstmt.setString(2, Base64.getEncoder().encodeToString(gkp.getPublicKey().getEncoded()));
                pstmt.executeUpdate();
            } catch (SQLException e) {
                System.err.println("Database Error (put): " + e.getMessage());
            }
        }

        public StoredPublicKey get(String keyId) {
            String sql = "SELECT public_key_base64, created_at FROM public_keys WHERE key_id = ?";
            try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, keyId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        byte[] encodedKey = Base64.getDecoder().decode(rs.getString("public_key_base64"));
                        Timestamp createdAt = rs.getTimestamp("created_at");
                        return new StoredPublicKey(keyId, encodedKey, createdAt);
                    }
                }
            } catch (SQLException e) {
                System.err.println("Database Error (get): " + e.getMessage());
            }
            return null;
        }

        public List<StoredPublicKey> getAll() {
            List<StoredPublicKey> keys = new ArrayList<>();
            String sql = "SELECT key_id, public_key_base64, created_at FROM public_keys";
            try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(sql); ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    keys.add(new StoredPublicKey(
                            rs.getString("key_id"),
                            Base64.getDecoder().decode(rs.getString("public_key_base64")),
                            rs.getTimestamp("created_at")
                    ));
                }
            } catch (SQLException e) {
                System.err.println("Database Error (getAll): " + e.getMessage());
            }
            return keys;
        }

        public boolean remove(String keyId) {
            String sql = "DELETE FROM public_keys WHERE key_id = ?";
            try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, keyId);
                return pstmt.executeUpdate() > 0;
            } catch (SQLException e) {
                System.err.println("Database Error (remove): " + e.getMessage());
            }
            return false;
        }
    }

    // ----------------------------
    // Cryptographic Services
    // ----------------------------
    static class KeyGeneratorService {
        public GeneratedKeyPair generate(int keySize) throws CryptoException {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(keySize);
                KeyPair kp = kpg.generateKeyPair();
                String id = UUID.randomUUID().toString();
                return new GeneratedKeyPair(id, kp.getPrivate(), kp.getPublic());
            } catch (Exception e) {
                throw new CryptoException("Key generation failed: " + e.getMessage());
            }
        }
    }

    static class SignatureService {
        public String sign(byte[] data, PrivateKey privateKey) throws CryptoException {
            try {
                Signature s = Signature.getInstance("SHA256withRSA");
                s.initSign(privateKey);
                s.update(data);
                byte[] signature = s.sign();
                return Base64.getEncoder().encodeToString(signature);
            } catch (Exception e) {
                throw new CryptoException("Signing failed: " + e.getMessage());
            }
        }

        public boolean verify(byte[] data, String signatureBase64, PublicKey publicKey) throws CryptoException {
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(publicKey);
                sig.update(data);
                byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
                return sig.verify(signatureBytes);
            } catch (Exception e) {
                throw new CryptoException("Verification failed: " + e.getMessage());
            }
        }
    }
    //endregion

    //region --- UI Components and Styling ---

    // Services and Data
    private final KeyGeneratorService keyGenService = new KeyGeneratorService();
    private final SignatureService signatureService = new SignatureService();
    private final KeyStoreDB keyStore = new KeyStoreDB();
    private final Map<String, GeneratedKeyPair> sessionKeys = new HashMap<>(); // Holds private keys for the session

    // UI Components
    private final JTextArea logArea = new JTextArea();
    private JTable keyTable;
    private DefaultTableModel keyTableModel;

    // UI Styling
    private static final Color BG_DARK = new Color(0x1E1E1E);
    private static final Color BG_PANEL = new Color(0x2D2D30);
    private static final Color ACCENT_BLUE = new Color(0x007ACC);
    private static final Color ACCENT_GREEN = new Color(0x6A9955);
    private static final Color ACCENT_RED = new Color(0xD16969);
    private static final Color ACCENT_YELLOW = new Color(0xDCDCAA);
    private static final Color TEXT_LIGHT = new Color(0xD4D4D4);
    private static final Font FONT_UI = new Font("Segoe UI", Font.PLAIN, 14);
    private static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 14);
    private static final Border BORDER_PANEL = new CompoundBorder(new LineBorder(BG_DARK, 2), new EmptyBorder(15, 15, 15, 15));
    private static final Border BORDER_FIELD = new CompoundBorder(new LineBorder(new Color(0x555555)), new EmptyBorder(5, 8, 5, 8));

    public DigitalSignatureApp() {
        initUI();
        log("System initialized. Welcome to SecureSign Studio.", ACCENT_YELLOW);
    }

    private void initUI() {
        setTitle("SecureSign Studio");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 800);
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);

        JTabbedPane tabbedPane = createTabbedPane();
        add(tabbedPane, BorderLayout.CENTER);
        add(createLogPanel(), BorderLayout.SOUTH);
    }

    private JTabbedPane createTabbedPane() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(FONT_UI);
        tabs.addTab("Sign & Verify", createSignVerifyPanel());
        tabs.addTab("Key Management", createKeyManagementPanel());
        return tabs;
    }
    //endregion

    //region --- UI Panel Creation ---

    private JPanel createSignVerifyPanel() {
        JPanel panel = createStyledPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // --- Data Input Area ---
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(createStyledLabel("Data to Sign / Verify:"), gbc);

        JTextArea dataArea = createStyledTextArea("Enter text data here or select a file...");
        gbc.gridy++; gbc.weightx = 1.0; gbc.weighty = 0.4; gbc.fill = GridBagConstraints.BOTH;
        panel.add(new JScrollPane(dataArea), gbc);

        // --- File Selection ---
        JTextField filePathField = createStyledTextField("No file selected", 30);
        filePathField.setEditable(false);
        gbc.gridy++; gbc.gridwidth = 1; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(filePathField, gbc);

        JButton browseButton = createStyledButton("Browse File...");
        gbc.gridx = 1; gbc.weightx = 0;
        panel.add(browseButton, gbc);

        // --- Signature Area ---
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        panel.add(createStyledLabel("Signature (Base64):"), gbc);

        JTextArea signatureArea = createStyledTextArea("Signature will appear here...");
        gbc.gridy++; gbc.weighty = 0.2; gbc.fill = GridBagConstraints.BOTH;
        panel.add(new JScrollPane(signatureArea), gbc);

        // --- Key ID Field ---
        gbc.gridy++; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(createStyledLabel("Key ID (for Signing: session key | for Verifying: DB key):"), gbc);
        JTextField keyIdField = createStyledTextField("Enter Key ID...", 30);
        gbc.gridy++;
        panel.add(keyIdField, gbc);

        // --- Action Buttons ---
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setOpaque(false);
        JButton signButton = createStyledButton("Sign Data", ACCENT_BLUE);
        JButton verifyButton = createStyledButton("Verify Signature", ACCENT_GREEN);
        buttonPanel.add(signButton);
        buttonPanel.add(verifyButton);

        gbc.gridy++; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
        panel.add(buttonPanel, gbc);

        // --- Event Listeners ---
        browseButton.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                filePathField.setText(file.getAbsolutePath());
                try {
                    String content = new String(Files.readAllBytes(file.toPath()));
                    dataArea.setText(content);
                    log("Loaded file: " + file.getName(), TEXT_LIGHT);
                } catch (IOException ex) {
                    log("Error reading file: " + ex.getMessage(), ACCENT_RED);
                }
            }
        });

        signButton.addActionListener(e -> {
            String keyId = keyIdField.getText().trim();
            GeneratedKeyPair gkp = sessionKeys.get(keyId);
            if (gkp == null) {
                log("Error: Private key for ID '" + keyId + "' not found in current session. Generate a key first.", ACCENT_RED);
                return;
            }
            try {
                byte[] dataToSign = dataArea.getText().getBytes();
                String signature = signatureService.sign(dataToSign, gkp.getPrivateKey());
                signatureArea.setText(signature);
                log("Data signed successfully with key ID: " + keyId, ACCENT_GREEN);
            } catch (CryptoException ex) {
                log("Signing failed: " + ex.getMessage(), ACCENT_RED);
            }
        });

        verifyButton.addActionListener(e -> {
            String keyId = keyIdField.getText().trim();
            String signature = signatureArea.getText().trim();
            if (keyId.isEmpty() || signature.isEmpty()) {
                log("Key ID and Signature fields are required for verification.", ACCENT_YELLOW);
                return;
            }
            try {
                StoredPublicKey spk = keyStore.get(keyId);
                if (spk == null) throw new KeyNotFoundException("Public key for ID '" + keyId + "' not found in database.");

                byte[] dataToVerify = dataArea.getText().getBytes();
                boolean isValid = signatureService.verify(dataToVerify, signature, spk.toPublicKey());

                if (isValid) {
                    log("SUCCESS: Signature is VALID.", ACCENT_GREEN);
                } else {
                    log("FAILURE: Signature is INVALID.", ACCENT_RED);
                }
            } catch (CryptoException ex) {
                log("Verification failed: " + ex.getMessage(), ACCENT_RED);
            }
        });

        return panel;
    }

    private JPanel createKeyManagementPanel() {
        JPanel panel = createStyledPanel(new BorderLayout(10, 10));

        // --- Top controls for generation and removal ---
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setOpaque(false);

        JComboBox<String> keySizeCombo = new JComboBox<>(new String[]{"2048", "3072"});
        styleComboBox(keySizeCombo);
        JButton generateButton = createStyledButton("Generate & Store New Key", ACCENT_BLUE);
        JButton removeButton = createStyledButton("Remove Selected Key", ACCENT_RED);
        JButton refreshButton = createStyledButton("Refresh List", ACCENT_YELLOW);

        topPanel.add(new JLabel("Key Size:"));
        topPanel.add(keySizeCombo);
        topPanel.add(generateButton);
        topPanel.add(removeButton);
        topPanel.add(refreshButton);

        // --- Table for displaying keys ---
        String[] columnNames = {"Key ID", "Creation Date"};
        keyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table cells not editable
            }
        };
        keyTable = new JTable(keyTableModel);
        styleTable(keyTable);
        JScrollPane tableScrollPane = new JScrollPane(keyTable);
        tableScrollPane.setBorder(new LineBorder(new Color(0x555555)));

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        // --- Event Listeners ---
        generateButton.addActionListener(e -> {
            int keySize = Integer.parseInt((String) keySizeCombo.getSelectedItem());
            new Thread(() -> {
                try {
                    log("Generating " + keySize + "-bit RSA key pair...", TEXT_LIGHT);
                    GeneratedKeyPair gkp = keyGenService.generate(keySize);
                    sessionKeys.put(gkp.getKeyId(), gkp); // Store private key in session
                    keyStore.put(gkp); // Store public key in DB
                    log("Key pair generated. Private key available in this session. Public key stored in DB.", ACCENT_GREEN);
                    log("New Key ID: " + gkp.getKeyId(), ACCENT_YELLOW);
                    SwingUtilities.invokeLater(this::refreshKeyTable);
                } catch (CryptoException ex) {
                    log("Key generation failed: " + ex.getMessage(), ACCENT_RED);
                }
            }).start();
        });

        removeButton.addActionListener(e -> {
            int selectedRow = keyTable.getSelectedRow();
            if (selectedRow == -1) {
                log("Please select a key from the table to remove.", ACCENT_YELLOW);
                return;
            }
            String keyId = (String) keyTableModel.getValueAt(selectedRow, 0);
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Are you sure you want to delete key '" + keyId + "' from the database?",
                    "Confirm Deletion", JOptionPane.YES_NO_OPTION);

            if (confirm == JOptionPane.YES_OPTION) {
                if (keyStore.remove(keyId)) {
                    log("Key ID '" + keyId + "' removed from the database.", ACCENT_GREEN);
                    refreshKeyTable();
                } else {
                    log("Failed to remove key ID '" + keyId + "'.", ACCENT_RED);
                }
            }
        });

        refreshButton.addActionListener(e -> refreshKeyTable());

        // Initial load
        refreshKeyTable();

        return panel;
    }

    private JScrollPane createLogPanel() {
        logArea.setEditable(false);
        logArea.setFont(FONT_MONO);
        logArea.setBackground(new Color(0x252526));
        logArea.setForeground(TEXT_LIGHT);
        logArea.setBorder(new EmptyBorder(10, 10, 10, 10));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(-1, 200));
        scrollPane.setBorder(new LineBorder(BG_DARK, 2));
        return scrollPane;
    }
    //endregion

    //region --- Helper & Utility Methods ---

    // UI Component Styling Helpers
    private JPanel createStyledPanel(LayoutManager layout) {
        JPanel panel = new JPanel(layout);
        panel.setBackground(BG_PANEL);
        panel.setBorder(BORDER_PANEL);
        return panel;
    }

    private JLabel createStyledLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_UI);
        label.setForeground(TEXT_LIGHT);
        return label;
    }

    private JTextField createStyledTextField(String placeholder, int columns) {
        JTextField textField = new JTextField(columns);
        textField.setFont(FONT_MONO);
        textField.setBackground(BG_DARK);
        textField.setForeground(TEXT_LIGHT);
        textField.setCaretColor(ACCENT_YELLOW);
        textField.setBorder(BORDER_FIELD);
        // Placeholder text handling
        textField.setText(placeholder);
        textField.setForeground(Color.GRAY);
        textField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (textField.getText().equals(placeholder)) {
                    textField.setText("");
                    textField.setForeground(TEXT_LIGHT);
                }
            }
            @Override
            public void focusLost(FocusEvent e) {
                if (textField.getText().isEmpty()) {
                    textField.setText(placeholder);
                    textField.setForeground(Color.GRAY);
                }
            }
        });
        return textField;
    }

    private JTextArea createStyledTextArea(String placeholder) {
        JTextArea textArea = new JTextArea();
        textArea.setFont(FONT_MONO);
        textArea.setBackground(BG_DARK);
        textArea.setForeground(TEXT_LIGHT);
        textArea.setCaretColor(ACCENT_YELLOW);
        textArea.setBorder(BORDER_FIELD);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        // Placeholder text handling
        textArea.setText(placeholder);
        textArea.setForeground(Color.GRAY);
        textArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (textArea.getText().equals(placeholder)) {
                    textArea.setText("");
                    textArea.setForeground(TEXT_LIGHT);
                }
            }
            @Override
            public void focusLost(FocusEvent e) {
                if (textArea.getText().isEmpty()) {
                    textArea.setText(placeholder);
                    textArea.setForeground(Color.GRAY);
                }
            }
        });
        return textArea;
    }

    private JButton createStyledButton(String text) {
        return createStyledButton(text, new Color(0x3E3E42));
    }

    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setFont(FONT_UI.deriveFont(Font.BOLD));
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(8, 15, 8, 15));
        return button;
    }

    private void styleComboBox(JComboBox<String> comboBox) {
        comboBox.setFont(FONT_UI);
        comboBox.setBackground(BG_DARK);
        comboBox.setForeground(TEXT_LIGHT);
        comboBox.setBorder(BORDER_FIELD);
    }

    private void styleTable(JTable table) {
        table.setFont(FONT_MONO);
        table.setBackground(BG_DARK);
        table.setForeground(TEXT_LIGHT);
        table.setGridColor(new Color(0x555555));
        table.setRowHeight(25);
        table.getTableHeader().setFont(FONT_UI.deriveFont(Font.BOLD));
        table.getTableHeader().setBackground(BG_PANEL);
        table.getTableHeader().setForeground(ACCENT_BLUE);
        table.setSelectionBackground(ACCENT_BLUE);
        table.setSelectionForeground(Color.WHITE);
    }

    // Logging and Table Refresh
    private void log(String message, Color color) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(String.format("[%s] %s\n",
                    new SimpleDateFormat("HH:mm:ss").format(new java.util.Date()),
                    message));
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void refreshKeyTable() {
        new Thread(() -> {
            List<StoredPublicKey> keys = keyStore.getAll();
            SwingUtilities.invokeLater(() -> {
                keyTableModel.setRowCount(0); // Clear table
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                for (StoredPublicKey key : keys) {
                    keyTableModel.addRow(new Object[]{
                            key.getKeyId(),
                            sdf.format(key.getCreatedAt())
                    });
                }
                log("Refreshed key list from database. " + keys.size() + " key(s) found.", TEXT_LIGHT);
            });
        }).start();
    }
    //endregion

    // ----------------------------
    // Main Method
    // ----------------------------
    public static void main(String[] args) {
        // Use a modern Look and Feel for better component rendering
        try {
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> {
            DigitalSignatureApp app = new DigitalSignatureApp();
            app.setVisible(true);
        });
    }
}
