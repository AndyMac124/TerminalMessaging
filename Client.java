import java.io.*;
import java.net.Socket;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;

/**
 * Client class
 * Establishes a connection with a server and sends valid commands
 * to that server based on protocol in protocol.pdf.
 */
public class Client {
    private Socket socket;
    private PrintWriter outgoing;
    private BufferedReader incoming;
    private BufferedReader consoleInput;
    private String username; // Username for client object
    private String response; // Var to hold the servers response
    private KeyPair keypair; // Client private keys
    private SecretKey symmetricKey; // Will receive from Server
    boolean debug = false; // Purely for debugging

    /**
     * Constructor for a client object
     * @param host hostname as a String
     * @param port port number as an int
     */
    public Client(String host, int port) {
        try {
            // Requirements for communication
            socket = new Socket(host, port);
            outgoing = new PrintWriter(socket.getOutputStream(), true);
            incoming = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            consoleInput = new BufferedReader(new InputStreamReader(System.in));

            sendRSAPublicKey();

            if (keypair != null) {
                receiveSymmetricKey();
            }

            if (symmetricKey != null) {
                logIn();
                if (username != null) {
                    messagingOpen();
                }
            }

            if (socket.isClosed()) {
                System.out.println("Socket is closed. Exiting Program.");
                System.exit(0);
            }

        } catch (Exception e) {
            System.out.println("Socket failed: " + e.getMessage());
        }
    }

    /**
     * Method to generate RSA keys and send public key to server
     */
    private void sendRSAPublicKey() {
        try {
            keypair = generateRSAKkeyPair();
            byte[] clientPublicKeyBytes = keypair.getPublic().getEncoded();
            String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKeyBytes);
            outgoing.println(clientPublicKeyString);
        } catch (Exception e) {
            System.out.println("Failed to generate and send RSA Public key: " + e.getMessage());
        }
    }

    /**
     * Method to receive the symmetric key from the server
     */
    private void receiveSymmetricKey() {
        try {
            String encryptedKeyBase64 = incoming.readLine();
            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyBase64);
            byte[] aesKeyBytes = decryptRSA(encryptedKeyBytes, keypair.getPrivate());
            symmetricKey = new SecretKeySpec(aesKeyBytes, "AES");
        } catch (Exception e) {
            System.out.println("Failed to receive symmetric key: " + e.getMessage());
        }
    }

    /**
     * Method to decrypt a message that was encrypted with the clients public RSA key.
     * @param cipherText to decrypt
     * @param privateKey Clients private key.
     * @return Decrypted message in bytes
     */
    public static byte[] decryptRSA(byte[] cipherText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            System.out.println("Failed to decrypt using RSA: " + e.getMessage());
        }
        return null;
    }

    /**
     * Method to encrypt plaintext with AES
     * @param plainText String to encrypt
     * @return Encrypted String
     */
    private String encryptAES(String plainText) {
        String plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey);
            byte[] byteCipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            plaintext = Base64.getEncoder().encodeToString(byteCipherText);
        } catch (Exception e) {
            System.out.println("Failed to encrypt with AES: " + e.getMessage());
        }
        return plaintext;
    }

    /**
     * Method to decrypt messages received from the client with AES
     * @param ciphertext the encrypted String
     * @return decrypted String
     */
    private String decryptAES(String ciphertext) {
        String plaintext = null;
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey);
            byte[] plainBytes = cipher.doFinal(cipherBytes);
            plaintext = new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Failed to decrypt with AES: " + e.getMessage());
        }
        return plaintext;
    }

    /**
     * Method to generate the clients RSA keys
     * @return The public/Private key pair
     */
    public KeyPair generateRSAKkeyPair() {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048, secureRandom);
            return generator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Failed to generate RSA keys: " + e.getMessage());
        }
        return null;
    }

    /**
     * Method to process a users request to log into an existing account.
     */
    private void login() {
        sendToServer("LOGIN");
        String name = enterCredentials();
        response = readFromServer();
        if (response.startsWith("LOGGED IN AS: ")) {
            loggedIn(name);
        } else {
            System.out.println(response);
        }
    }

    /**
     * Method for a user to enter username and password
     * @return the String of their username
     */
    private String enterCredentials() {
        // Username
        System.out.println(readFromServer());
        String username = readFromUser();
        sendToServer(username);

        // Password
        System.out.println(readFromServer());
        sendToServer(readPasswordFromUser());

        return username;
    }

    /**
     * Method for printing response of successfull log in
     * @param name entered username to assign to this client
     */
    private void loggedIn(String name) {
        username = name;
        System.out.println("Logged in as: " + username);
        System.out.println("Unread messages: " + readFromServer());
    }

    /**
     * Method to process a user request to create a new account.
     */
    private void createAccount(){
        sendToServer("CREATE");
        String name = enterCredentials();
        response = readFromServer();
        if (response.startsWith("LOGGED IN AS: ")) {
            loggedIn(name);
        } else if (response.startsWith("Invalid password: ")) {
            System.out.println(response);
            printPasswordRules();
        } else {
            System.out.println(response);
        }
    }

    /**
     * Executes when client first connects.
     * Client needs to either log in, create an account, or exit program
     */
    private void logIn() {
        while (username == null) {
            System.out.println("Please enter either LOGIN or CREATE or EXIT: ");
            String message = readFromUser();
            switch (message) {
                case "LOGIN":
                    login();
                    break;
                case "CREATE":
                    createAccount();
                    break;
                case "EXIT":
                    sendToServer("EXIT");
                    return; // Jumping out of this method
                default:
                    System.out.println("Error: Invalid command");
            }
        }
    }

    /**
     * Method to print the rules for a valid password.
     */
    private void printPasswordRules() {
        System.out.println("""
                -----------------------------------------
                Password must:
                Be between 8-64 characters long.
                Contain at least one lowercase letter.
                Contain at least one uppercase letter.
                Contain at least one special character.
                NOT CONTAIN or be equal to your username.
                Note: It CAN contain the space character.
                -----------------------------------------
                """);
    }

    /**
     * Method to print message when awaiting user input.
     */
    private void awaitInputMessage() {
        System.out.println("--------------------"); // Printing this to help with CLI readability
        System.out.println("Awaiting next command, type \"HELP\" to see valid commands.");
        System.out.println("--------------------"); // Printing this to help with CLI readability
    }

    /**
     * Method to get the core command from the user input
     * @param userInput full user input
     * @return just the command
     */
    private String getCommand(String userInput) {
        String[] parts = userInput.split("\\s+", 2);
        return parts[0].strip();
    }

    /**
     * Core method for when the communication channel is open and ready.
     */
    public void messagingOpen() {
        awaitInputMessage();

        while (true) {
            /*
            Here we get just the first part of the command to match in the switch case.
            Checking if the input contains or does not contain more characters is done within
            the case statements as needed.
             */
            String userInput = readFromUser();

            if (username == null) {
                logIn();
            } else {
                switch (getCommand(userInput)) {
                    case "EXIT":
                        sendToServer("EXIT");
                        return; // Jumping out of this method
                    case "LOGIN": // I believe login can only be done once per client.
                        System.out.println("You are already logged in as: " + username);
                        break;
                    case "COMPOSE":
                        compose(userInput);
                        break;
                    case "READ":
                        read(userInput);
                        break;
                    case "SENT":
                        getSent(userInput);
                        break;
                    case "HELP": // Added to help with user experience.
                        validCommands();
                        break;
                    case "LOGOUT":
                        sendToServer(userInput);
                        username = null;
                        logIn();
                        if (username == null) {
                            return;
                        }
                        break;
                    default: // If invalid input, notify user of the problem and request new input
                        System.out.println("\nINVALID INPUT");
                        validCommands();
                        break;
                }
                if (username != null) {
                    awaitInputMessage();
                }
            }
        }
    }

    /**
     * Method to process a COMPOSE command on the client side
     * @param userInput the full input from the user
     */
    private void compose(String userInput) {

        // If no argument was provided with COMPOSE
        if (userInput.trim().equals("COMPOSE")) {
            System.out.println("Invalid command: COMPOSE must be followed by a space and a recipient.");
            return;
        // If recipient name contains spaces
        } else if (userInput.split("\\s+").length > 2) {
            System.out.println("Invalid command: COMPOSE must be followed by a space and a valid username.");
            return;
        }
        // If valid we send the command
        sendToServer(userInput);

        // Check the server accepted the recipient.
        if (readFromServer().startsWith("Invalid argument")) {
            return;
        }

        // Then get the message and send that
        sendToServer(readFromUser());

        // Display server response
        System.out.println(readFromServer());
    }

    /**
     * Method to process a SENT command on the client side
     * @param userInput String of the full input by the user
     */
    private void getSent(String userInput) {
        // First checking SENT is not given any arguments
        if (checkArgs(userInput)) {
            int numMessages;
            // Sending to server
            sendToServer(userInput);
            response = readFromServer();
            if (response.startsWith("Invalid command")) {
                System.out.println(response);
            } else {
                try {
                    numMessages = Integer.parseInt(response);
                } catch (Exception e) {
                    System.out.println("Server Error, could not find any sent messages");
                    return;
                }
                if (numMessages > 0) {
                    for (int i = 0; i < numMessages; i++) {
                        // If successful response, print sender name, then message
                        System.out.println("Sent Message: " + (i + 1));
                        String recipient = readFromServer();
                        System.out.println("\tRecipient: " + recipient);
                        String contents = readFromServer();
                        System.out.println("\tContents: " + contents);
                        String isRead = readFromServer();
                        System.out.println("\tRead = " + isRead);
                    }
                } else {
                    System.out.println(readFromServer());
                }
            }
        } else {
            // If SENT was given an argument
            System.out.println("INVALID INPUT: SENT does not take any arguments.");
        }
    }

    /**
     * Method to process a READ command on the client side
     * @param userInput String of the full input by the user
     */
    private void read(String userInput) {
        // First checking READ is not given any arguments
        if (checkArgs(userInput)) {
            // Sending to server
            sendToServer(userInput);
            response = readFromServer();
            if (response.startsWith("No unread")) {
                System.out.println(response);
            } else {
                // If successful response, print sender name, then message
                System.out.println("Sender: " + response);
                String contents = readFromServer();
                System.out.println("Message: " + contents);
            }
        } else {
            // If READ was given an argument
            System.out.println("INVALID INPUT: READ does not take any arguments.");
        }
    }

    /**
     * Method to read from the users console.
     * Abstracted out to enhance readability of other methods (less try-catches)
     * @return String of the console input
     */
    private String readFromUser() {
        try {
            return consoleInput.readLine();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method to read a password from the users console.
     * @return the password as a String
     */
    private String readPasswordFromUser() {
        try {
            Console console = System.console();
            return new String(console.readPassword());
        } catch (Exception e) {
            System.out.println("Failed to read password: " + e.getMessage());
        }
        return readFromUser();
    }

    /**
     * Method to read a message from the server
     * @return the string message in plaintext
     */
    private String readFromServer() {
        try {
            int numberOfBlocks = Integer.parseInt(decryptAES(incoming.readLine()));
            StringBuilder message = new StringBuilder();
            for (int i = 0; i < numberOfBlocks; i++) {
                message.append(decryptAES(incoming.readLine()));
            }
            return message.toString();
        } catch (Exception e) {
            System.out.println("Failed to read message from the server: " + e.getMessage());
        }
        return null;
    }

    /**
     * Method to send to the server.
     * Abstracted out to enhance readability of other methods (less try-catches)
     */
    private void sendToServer(String message) {
        try {
            if (debug) { System.out.println("Plaintext: " + message);}
            ArrayList<String> blocks = splitStringIntoBlocks(message);
            outgoing.println(encryptAES(String.valueOf(blocks.size())));
            for (String block : blocks) {
                if (debug) { System.out.println("Sending: " + block);}
                outgoing.println(encryptAES(block));
            }
        } catch (Exception e) {
            System.out.println("Failed to send to the server: " + e.getMessage());
        }
    }

    /**
     * Method to split a string into blocks for encryption
     * @param message the full message to split
     * @return an array list of all blocks to encrypt and send
     */
    private ArrayList<String> splitStringIntoBlocks(String message) {
        ArrayList<String> blocks = new ArrayList<>();
        for (int i = 0; i < message.length(); i += 10) {
            // Math.min allowing us to take the less than 10 characters on the last pass
            blocks.add(message.substring(i, Math.min(i + 10, message.length())));
        }
        return blocks;
    }

    /**
     * Method to check a command has not been given any arguments
     * @param command String command to check
     * @return boolean - true if command has no arguments.
     */
    private boolean checkArgs(String command) {
        String[] parts = command.trim().split("\\s+", 2);
        return parts.length == 1;
    }

    /**
     * Method to print a list of valid commands
     */
    private void validCommands() {
        System.out.println("The following are valid commands:");
        System.out.println("- COMPOSE (followed by a space and a user as recipient).");
        System.out.println("- READ (to read your next unread message).");
        System.out.println("- SENT (to see your sent messages).");
        System.out.println("- LOGOUT (to logout of your account).");
        System.out.println("- EXIT (to close connection with the server).");
    }

    /**
     * Main method
     * @param args arguments to program
     */
    public static void main(String[] args) {
        // Checking the client receives 2 arguments as required.
        if (args.length != 2) {
            System.out.println("Please provide the host and port number.");
            System.exit(1);
        }

        // First arguments is the hostname
        String hostName = args[0];

        int portNumber = -1;

        // Second argument needs to be the port number
        try {
            portNumber = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.out.println("Could not parse argument 2 into an integer: " + e.getMessage());
            System.exit(1);
        }

        // Instantiating the Client
        new Client(hostName, portNumber);
    }
}