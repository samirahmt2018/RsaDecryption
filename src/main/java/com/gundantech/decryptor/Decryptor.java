package com.gundantech.decryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Decryptor extends JFrame {

    private final JButton selectButton;
    private final JButton decryptButton;
    private final JLabel selectedFileLabel;
    private final JLabel passwordLabel;
    private final JFileChooser fileChooser;
    private final JPasswordField passwordField;
    private File selectedFile;

    public Decryptor() {
        super("File Decryption");
         Image icon = Toolkit.getDefaultToolkit().getImage("resources/naredevd.png");
         this.setIconImage(icon);

        selectButton = new JButton("Select File");
        selectButton.addActionListener((ActionEvent e) -> {
            openFileChooser();
        });

        selectedFileLabel = new JLabel("Selected File: ");
        selectedFileLabel.setHorizontalAlignment(SwingConstants.LEFT); // Align left component to the right

        passwordLabel = new JLabel("Decryption Password: ");
        passwordLabel.setHorizontalAlignment(SwingConstants.RIGHT); // Align left component to the right

        passwordField = new JPasswordField(20);

        decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener((ActionEvent e) -> {
            decryptSelectedFile();
        });

        fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setMultiSelectionEnabled(false);

        // Use GridBagLayout instead of GridLayout
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();

        // Align left components to the right
        constraints.anchor = GridBagConstraints.LINE_END;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(10, 10, 0, 0);
        constraints.gridx = 0;
        constraints.gridy = 0;
        panel.add(selectButton, constraints);

        constraints.gridx = 1;
        constraints.gridy = 0;
        panel.add(selectedFileLabel, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        panel.add(passwordLabel, constraints);

        constraints.gridx = 1;
        constraints.gridy = 1;
        panel.add(passwordField, constraints);

        // Reset anchor to default (left)
        constraints.anchor = GridBagConstraints.CENTER;

        constraints.gridwidth = 2;
        constraints.gridx = 0;
        constraints.gridy = 2;
        panel.add(decryptButton, constraints);

        add(panel);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void openFileChooser() {
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
            selectedFileLabel.setText("Selected File: " + selectedFile.getName());
        }
    }

    private void decryptSelectedFile() {
        if (selectedFile != null && selectedFile.exists()) {
            char[] password = passwordField.getPassword();
            if (password.length == 0) {
                showMessage("Please enter the decryption password.");
                return;
            }
            try {
                decryptFile(selectedFile, new String(password));
            } catch (DecryptionException e) {
                showMessage(e.getMessage());
            } finally {
                Arrays.fill(password, '0'); // Clear the password from memory
            }
        } else {
            showMessage("Please select a file to decrypt.");
        }
    }

    private void decryptFile(File file, String password) throws DecryptionException {
        try {
            // Read the encrypted file into a byte array

            String path = file.getPath();
            String encryptedText = readEncryptedFile(path);

            String decryptedText = decryptText(encryptedText, password);
            String newPath = path.replaceAll(".b64", "");
            writeDecryptedFile(newPath, decryptedText);
            System.out.println("Decryption successful. Decrypted data saved to " + newPath);

            showMessage("File successfully decrypted and saved as: " + newPath);
        } catch (IOException e) {
            throw new DecryptionException("Error reading or writing the file.");
        } catch (Exception ex) {
            showMessage("Error occured during decryption, wrong password?");
            Logger.getLogger(Decryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static String decryptText(String encryptedData, String password) throws Exception {
        byte[] binaryEncryptedData = java.util.Base64.getDecoder().decode(encryptedData);

        // Extract the salt, IV, and encrypted text from the binary data
        byte[] salt = java.util.Arrays.copyOfRange(binaryEncryptedData, 0, 16);
        byte[] iv = java.util.Arrays.copyOfRange(binaryEncryptedData, 16, 32);
        byte[] encryptedText = java.util.Arrays.copyOfRange(binaryEncryptedData, 32, binaryEncryptedData.length);

        // Derive the encryption key using the same password and salt used during encryption
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Decrypt the data using AES-256-CBC with zero padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        System.out.println(key);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        byte[] decryptedBytes = cipher.doFinal(encryptedText);

        // Remove the padding from the decrypted text
        int padding = decryptedBytes[decryptedBytes.length - 1];
        String decryptedText = new String(decryptedBytes, 0, decryptedBytes.length - padding, StandardCharsets.UTF_8);

        return decryptedText;
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
            IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static String readEncryptedFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }

    public static void writeDecryptedFile(String filePath, String decryptedText) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filePath))) {
            bw.write(decryptedText);
        }
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "File Decryption", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Decryptor::new);
    }

    private static class DecryptionException extends Exception {

        public DecryptionException(String message) {
            super(message);
        }
    }
}
