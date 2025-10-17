# SecureSign Studio: A Digital Signature Application

SecureSign Studio is a desktop application built with Java Swing that provides a complete and secure environment for creating and verifying digital signatures. It uses the robust RSA algorithm combined with SHA-256 hashing to ensure data authenticity and integrity. The application features a professional dark-themed UI, persistent public key storage via a MySQL database, and secure, password-protected storage for private keys.

---
## ✨ Features

* **RSA Key Pair Generation**: Create secure 2048-bit or 3072-bit RSA key pairs.
* **Secure Private Key Storage**: Private keys are encrypted with a user-provided password (using AES and PBKDF2) and saved to a file, never stored in plain text.
* **MySQL Database Integration**: Public keys are stored in a central MySQL database for easy lookup and management.
* **Sign Data & Files**: Sign any text data or file content using a loaded, password-protected private key.
* **Verify Signatures**: Verify the authenticity and integrity of data by checking its signature against the corresponding public key from the database.
* **Key Management**: A user-friendly interface to view all public keys stored in the database, generate new keys, and remove old ones.
* **Modern UI**: A polished, multi-tabbed interface with a live log panel that provides real-time feedback on all cryptographic operations.

---
## 🛠️ Technology Stack

* **Language**: **Java**
* **User Interface**: **Java Swing**
* **Cryptography**: **Java Cryptography Architecture (JCA)**
    * Algorithm: `SHA256withRSA`
    * Private Key Encryption: `AES` with `PBKDF2WithHmacSHA256`
* **Database**: **MySQL**
* **Driver**: **MySQL Connector/J** (JDBC Driver)

---
## 🚀 Getting Started

Follow these steps to set up and run the project on your local machine.

### Prerequisites

Before you begin, ensure you have the following installed:
1.  **Java Development Kit (JDK)**: Version 8 or newer.
2.  **MySQL Server**: A running MySQL instance.
3.  **MySQL Connector/J**: The JDBC driver `.jar` file.

### 1. Database Setup

First, you need to create the database and table for storing public keys.

1.  Log in to your MySQL server (e.g., using the MySQL Command-Line Client).
2.  Run the following SQL commands:

    ```sql
    -- Create the database
    CREATE DATABASE digital_signatures;

    -- Select the database to use it
    USE digital_signatures;

    -- Create the table for public keys
    CREATE TABLE public_keys (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_id VARCHAR(255) NOT NULL UNIQUE,
        public_key_base64 TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ```

### 2. Project Configuration

1.  **Place the JDBC Driver**: Copy your MySQL driver file (e.g., `mysql-connector-j-9.4.0.jar`) and place it in the same directory as your `.java` files.
2.  **Update Password**: Open the `KeyStoreDB.java` file and update the `DB_PASSWORD` variable with your MySQL root password.
    ```java
    private static final String DB_PASSWORD = "shri2006"; // Update this line
    ```

### 3. Compile and Run

1.  Open a command prompt or terminal in your project directory.
2.  **Compile all `.java` files** using the classpath flag to include the MySQL driver:
    ```bash
    javac -cp ".;mysql-connector-j-9.4.0.jar" *.java
    ```
    *(**Note**: Replace `mysql-connector-j-9.4.0.jar` with the exact filename of your driver.)*

3.  **Run the application**:
    ```bash
    java -cp ".;mysql-connector-j-9.4.0.jar" DigitalSignatureApp
    ```

The SecureSign Studio application will now launch.

---
## 📖 How to Use the Application

1.  **Generate a Key**: Go to the **"Key Management"** tab, select a key size, and click **"Generate & Save New Key"**. You will be prompted to create a password to encrypt and save your private key to a `.key` file. The public key will be automatically stored in the MySQL database.
2.  **Load a Private Key**: To sign data, you must first load a private key into the current session. Go to the **"Sign & Verify"** tab and click **"Load Private Key..."**. Select the `.key` file you saved and enter the correct password.
3.  **Sign Data**: Enter text or browse for a file. Paste the corresponding **Key ID** into its field and click **"Sign Data"**. The signature will appear.
4.  **Verify a Signature**: To verify, ensure the original data, the signature, and the public **Key ID** are in their fields. Click **"Verify Signature"**. The application will fetch the public key from the database and confirm if the signature is valid.
