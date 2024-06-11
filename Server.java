import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.*;

/*
REFERENCES FOR ENCRYPTION METHODS
AES Encryption methods are based off the following:
https://www.baeldung.com/java-aes-encryption-decryption
RSA Encryption methods are based off the following:
https://www.baeldung.com/java-rsa
SHA-256 hashing is based off the following:
https://www.geeksforgeeks.org/sha-256-hash-in-java/
 */
/**
 * Server Class
 * Opens a server socket for a client to connect to.
 * Communication protocol as per assignment instructions
 */
public class Server {
    private ServerSocket serverSocket;
    private Socket clientSocket;
    private PrintWriter outgoing;
    private BufferedReader incoming;
    private String currentUser;
    private ArrayList<Object[]> storedMessages; // List of all messages on server
    private ArrayList<String[]> users; // List of all users
    private SecretKey SymmetricKey;
    private PublicKey clientPublicKey; // Will receive from the client
    boolean debug = false; // Purely for debugging

    /**
     * Constructor for the Server class
     * @param port port number the server will be available on
     */
    public Server(int port) {

        // Assigning a new blank arraylist to the storedMessages
        storedMessages = new ArrayList<>();

        // Initiating to null for log in purposes
        currentUser = null;

        // Symmetric key for communication
        SymmetricKey = getSymmetricKey();

        // Used to send the symmetric key to the client
        clientPublicKey = null;

        // Instantiating the users list
        users = new ArrayList<>();

        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            outgoing = new PrintWriter(clientSocket.getOutputStream(), true);
            incoming = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // Once communication is open it is processed here
            clientCommunication();

            // Closing the sockets
            terminateConnection();
        } catch (IOException e) {
            System.out.println("Error: could not establish socket " + e.getMessage());
        }
    }

    /**
     * Method to get a symmetric AES key
     * @return an AES key of 256 bits
     */
    private SecretKey getSymmetricKey() {
        SecretKey key = null;
        try {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        key = keyGenerator.generateKey();
        } catch (Exception e) {
            System.out.println("Failed to generate an AES key: " + e.getMessage());
        }
        return key;
    }

    /**
     * To encrypt a message with the clients public key
     * Only used for sending the symmetric key
     * @param data an array of data as bytes to encrypt
     * @param publicKey the public key to do the encrypted
     * @return encrypted data
     */
    public String encryptRSA(byte[] data, PublicKey publicKey) {
        String encryptedMessage = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedMessage = Base64.getEncoder().encodeToString(cipher.doFinal(data));
        } catch (Exception e) {
            System.out.println("Failed to encrypt with RSA: " + e.getMessage());
        }
        return encryptedMessage;
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
            cipher.init(Cipher.ENCRYPT_MODE, this.SymmetricKey);
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
            cipher.init(Cipher.DECRYPT_MODE, this.SymmetricKey);
            byte[] plainBytes = cipher.doFinal(cipherBytes);
            plaintext = new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Failed to decrypt with AES: " + e.getMessage());
        }
        return plaintext;
    }

    /**
     * Method to generate some random salt for passwords
     * @return String for salting a password
     */
    private String makeSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return new String(salt);
    }

    /**
     * Method to salt and hash a password with SHA-256
     * @param passwordToHash user password to hash
     * @param salt String for the salt
     * @return Hashed password as String
     */
    private static String hashPassword(String passwordToHash, String salt) {
        String hashedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] hashedBytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            hashedPassword = toHexString(hashedBytes);
        } catch (Exception e) {
            System.out.println("Failed to hash password: " + e.getMessage());
        }
        return hashedPassword;
    }

    /**
     * Method to convert a byte array to string
     */
    private static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));

        while (hexString.length() > 64) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }

    /**
     * Method to add a message to arraylist
     * @param recipient String username of the recipient
     * @param sender String of the current user leaving the message
     * @param message String of the actual message
     */
    private void addMessage(String recipient, String sender, String message) {
        Object[] thisMessage = {recipient, sender, message, false};
        storedMessages.add(thisMessage);
    }

    /**
     * Method to get the oldest message from the arraylist
     * @return a string array with the sender and message
     */
    private Object[] getMessage() {
        // Go through each message
        for (Object[] message : storedMessages) {
            // Check if recipient equals current client user
            if (message[0].equals(currentUser) && message[3].equals(false)) {
                message[3] = true;
                return message;
            }
        }
        // If no messages for the client user
        return null;
    }

    /**
     * @return all sent messages by current user in an arraylist
     */
    private ArrayList<Object[]> checkSentMessages() {
        ArrayList<Object[]> sentMessages = new ArrayList<>();
        // Go through each message
        for (Object[] message : storedMessages) {
            // Check if sender equals current client user
            if (message[1].equals(currentUser)) {
                sentMessages.add(message);
            }
        }
        if (!sentMessages.isEmpty()) {
            return sentMessages;
        } else {
            return null;
        }
    }

    /**
     * Method to get the number of messages for a certain user
     * @return int of the total number of messages waiting.
     */
    private int getNumMessages() {
        int numMessages = 0;
        for (Object[] message : storedMessages) {
            if (message[0].equals(currentUser) && message[3].equals(false)) {
                numMessages++;
            }
        }
        return numMessages;
    }

    /**
     * Attempting to close the client and server sockets.
     */
    private void terminateConnection() {
        try {
            if (clientSocket != null) {
                clientSocket.close();
            }
        } catch (IOException e) {
            System.out.println("Error closing client socket: " + e.getMessage());
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            System.out.println("Error closing server socket: " + e.getMessage());
        }
    }

    /**
     * Method to log in a user.
     */
    private void userLogin() {
        send("username: ");
        String username = readFromClient();
        send("password: ");
        String password = readFromClient();

        if (authenticateUser(username, password)) {
            currentUser = username;
            send("LOGGED IN AS: ");
            send(String.valueOf(getNumMessages()));
        } else {
            send("Invalid password or username");
        }
    }

    /**
     * method to authenticate if a users username and password matches
     * @param username the entered username
     * @param password the entered password
     * @return true if they match a valid user
     */
    private boolean authenticateUser(String username, String password) {
        for (String[] user : users) {
            if (user[0].equals(username) && (user[1].equals(hashPassword(password, user[2])))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Method to create a new account
     */
    private void createAccount() {
        // Request username and password
        send("username: ");
        String username = readFromClient();
        send("password: ");
        String password = readFromClient();

        // Make salt for user and create user array
        String userSalt = makeSalt();
        String[] thisUser = {username, hashPassword(password, userSalt), userSalt};

        // DEBUGGING ONLY - Would remove for production, left in here for marker if wanted
        if (debug) { System.out.println("User salt: " + userSalt + "\nUser plaintext password: " +
                password + "\nUser stored password: " + hashPassword(password, userSalt)); }

        // If username is invalid, return
        if (!checkUsername(username)) {
            return;
        }

        // Check if password is valid
        if (!validatePassword(password, username)) {
            send("Invalid password: ");
        } else {
            // Create the new user
            currentUser = username;
            users.add(thisUser);
            send("LOGGED IN AS: ");
            int numMessages = getNumMessages();
            send(String.valueOf(numMessages));
        }
    }

    /**
     * Method which checks if a chosen username is valid
     * @param username the chosen username
     * @return boolean of whether its valid
     */
    private boolean checkUsername(String username) {
        if (username != null && username.contains(" ")) {
            send("Invalid: username cannot contain spaces.");
            return false;
        } else if (searchUsernames(username)) {
            send("Invalid: username is already taken.");
            return false;
        }
        return true;
    }

    /**
     * Method to check whether a given username exists in users already
     * @param username the name to check
     * @return boolean of whether it exists
     */
    private boolean searchUsernames(String username){
        for (String[] user: users) {
            if (user[0].equals(username)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Method to check if a password is a valid choice
     * @param password chosen password
     * @param username username associated with the password
     * @return boolean of whether the password is valid
     */
    private boolean validatePassword(String password, String username) {

        if (password == null || password.equals(username) || password.contains(username)) {
            return false;
        }

        String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,64}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

    /**
     * Method to receive and set the clients public key.
     */
    private void setClientRSAkey() {
        try {
            String publicKeyString = incoming.readLine();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            clientPublicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            System.out.println("Failed to get and set client public key: " + e.getMessage());
        }
    }

    /**
     * Method to read a message from the client and
     * separate them into command and argument.
     * @return String array of the command and argument.
     */
    private String[] getCommand() {
        try {
            String[] parts = readFromClient().split("\\s+", 2);
            String command = parts[0].strip();
            String arg = parts.length > 1 ? parts[1] : "";
            return new String[]{command, arg};
        } catch (Exception e) {
            System.out.println("Could not receive command: " + e.getMessage());
        }
        return new String[]{"", ""};
    }

    /**
     * Method to establish the required encryption keys and log in a user.
     */
    private void setUpCommunication() {
        // Receive and set the clients public key
        setClientRSAkey();

        // Send the symmetric key encrypted by clients public key
        outgoing.println(encryptRSA(SymmetricKey.getEncoded(), clientPublicKey));

        // First get the user logged in
        if (currentUser == null) {
            requestLogIn();
        }
    }

    /**
     * Method to accept a new message from the client
     * @param recipient the recipient of the message
     */
    private void compose(String recipient) {
        // If no recipient with COMPOSE we reject the request.
        if (Objects.equals(recipient, "")) {
            send("Invalid argument, COMPOSE requires a recipient.");
            return;
        } else {
            send("Recipient acknowledged.");
        }
        // Wait for the following line for the message
        String message = readFromClient();
        // If we have both a recipient and message we store it
        if (recipient != null && message != null) {
            addMessage(recipient, currentUser, message);
            send("MESSAGE SENT");
        } else {
            send("MESSAGE FAILED");
        }
    }

    /**
     * Method to send the most recent unread message for the current user.
     */
    private void read() {
        Object[] toSend = getMessage();
        if (toSend != null) {
            send((String) toSend[1]); // Sender
            send((String) toSend[2]); // Content
        } else {
            send("No unread messages were found.");
        }
    }

    /**
     * Method to retrieve all sent messages by the current user
     * and pass them to the client.
     */
    private void sent() {
        ArrayList<Object[]> sentMessages = checkSentMessages();
        if (sentMessages != null) {
            // Sending the amount of messages to expect
            send(String.valueOf(sentMessages.size()));
            // Break each message into the three parts and send
            for (Object[] sent : sentMessages) {
                String isRead = sent[3].equals(true) ? "true" : "false";
                send((String) sent[0]); // Recipient
                send((String) sent[2]); // Message contents
                send(isRead);
            }
        } else {
            send("No Sent messages found");
        }
    }

    /**
     * Method for processing the client communication
     */
    private void clientCommunication() {
        setUpCommunication();

        // If they exited the login without logging in, we need to exit this as well
        if (currentUser == null) { return; }

        try {
            while (true) {
                /*
                We start by splitting the incoming message to get the command to match to.
                We keep the argument separate for later use.
                */
                String[] parts = getCommand();
                String command = parts[0], arg = parts[1];

                switch (command) {
                    case "COMPOSE":
                        compose(arg);
                        break;
                    case "READ":
                        // If READ came with an argument, it's an invalid command
                        if (!Objects.equals(arg, "")) {
                            send("Invalid command, READ does not take any arguments.");
                            return;
                        } else {
                            read();
                        }
                        break;
                    case "SENT":
                        sent();
                        break;
                    case "LOGOUT":
                        requestLogIn();
                        if (currentUser == null) { return; } // If they selected "EXIT"
                        break;
                    case "EXIT":
                        return;
                    default: // Any other message from the client
                        send("Invalid command, something went wrong with the server.");
                        return;
                }
            }
        } catch (Exception e) {
            System.out.println("Error processing command: " + e.getMessage());
        }
    }

    /**
     * Method to request a user to log in
     * It will continue asking until they successfully log in or select exit
     */
    private void requestLogIn() {
        currentUser = null;
        try {
            while (true) {
                /*
                We start by splitting the incoming message to get the command to match to.
                We keep the argument separate for later use.
                 */
                String command = getCommand()[0];

                switch (command) {
                    case "LOGIN":
                        userLogin();
                        break;
                    case "CREATE":
                        createAccount();
                        break;
                    case "EXIT":
                        return;
                    default: // Any other message from the client
                        send("Invalid command.");
                        return;
                }
                // If they successfully logged in, return.
                if (currentUser != null) {
                    return;
                }
            }
        } catch (Exception e) {
            System.out.println("Error handling command: " + e.getMessage());
        }
    }

    /**
     * Method to read a message from the client,
     * It first gets the number of blocks to expect and then reads and decrypts
     * each block forming a single string message
     * @return String of the full message
     */
    private String readFromClient() {
        try {
            int messageBlocks = Integer.parseInt(decryptAES(incoming.readLine()));
            StringBuilder message = new StringBuilder();
            for (int i = 0; i < messageBlocks; i++) {
                message.append(decryptAES(incoming.readLine()));
            }
            return message.toString();
        } catch (Exception e) {
            System.out.println("Failed to read message from client: " + e.getMessage());
        }
        return null;
    }

    /**
     * A method to send a message to the client
     * It first breaks it into small blocks to be encrypted,
     * then sends the number of blocks to expect and then sends the blocks.
     * @param message the message to send
     */
    private void send(String message) {
        try {
            ArrayList<String> blocks = splitStringIntoBlocks(message);
            outgoing.println(encryptAES(String.valueOf(blocks.size())));
            for (String block : blocks) {
                if (debug) { System.out.println("Sending: \"" + block + "\" As: " + encryptAES(block));}
                outgoing.println(encryptAES(block));
            }
        } catch (Exception e) {
            System.out.println("Failed to send message: " + e.getMessage());
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
     * Main method
     * @param args we require a port number
     */
    public static void main(String[] args) {
        int portNumber = -1; // Initialising to -1 to minimise risk of runtime errors

        // Attempt to set port number
        try {
            portNumber = Integer.parseInt(args[0]);
        } catch (Exception e) {
            System.out.println("Invalid arguments, please provide one string for host and one available port number.");
            System.exit(1);
        }

        // If port number was set by args, create server object
        if (portNumber != -1) {
            new Server(portNumber);
        }
    }
}