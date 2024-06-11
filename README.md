# <p style="text-align:center"> COSC340 A4 </p>

### <p style="text-align:center"> By Andrew McKenzie (#220263507) </p>

### Outline:
This is a basic terminal based network messaging system where users can leave messages for other users 
and read messages intended for themselves. The client and server are written in Java with corresponding shell 
script for each.
***
### Permissions:
Permissions for all files have been set to allow all users to read, write, and execute. However, when transferring the files
to Turing with FileZilla I lost those permissions. So if permission is denied, please copy and paste these into your CLI.

- chmod +x startClient.sh
- chmod +x startServer.sh
- chmod +x Client.java
- chmod +x Server.java

***
### Running the program:
First start the server by opening a new terminal in the current directory of these source files.
Then run `./startServer.sh port` replacing `port` with an available port number.

Second start the client by opening a terminal in the current directory of these source files.
Then run `./startClient.sh hostname port` replacing `hostname` with a host name and `port` with the port of the server.

For example in terminal 1:
```shell
./startServer.sh 4444
```
And in terminal 2:
```shell
./startClient.sh localhost 4444
```

***
### Communication Protocol:
*Note:* all commands are case-sensitive.

All users must create an account with a unique username and password meeting the criteria stated in the UI.

The initial interface involves the following commands:
- `LOGIN` - To log into an existing account.
- `CREATE` - To create a new account.
- `EXIT` - To terminate the connection.

Once logged in you will then see a number representing the number of unread messages waiting for you.

At any time in the client terminal, to see a list of valid commands you can enter 'HELP'.

During communication you have the option of the following commands:
- `COMPOSE <username>` - To write a message to another user, after sending this, the server will wait to 
receive the message as well.
- `SENT` - To return all messages you have sent with the recipient and whether they have read it.
- `READ` - To return the oldest message with senders name first or READ ERROR if no messages were found.
- `LOGOUT` - To logout the current user.
- `EXIT` - To terminate the connection.
***
### Message Storage:

The server stores messages in a resizeable array list with a theoretical capacity so high it is basically infinite.
The array list contains string arrays where the first index is the recipient, the second the sender, the third is the message, and the fourth is whether it has been read.
```java
private ArrayList<String[]> storedMessages = new ArrayList<>();

private void addMessage(String recipient, String sender, String message) {
    Object[] thisMessage = {recipient, sender, message, false};
    storedMessages.add(thisMessage);
}
```

### Security:

There are two key security measures:
1. All passwords salted and hashed with SHA-256.
2. All messages a sent between client and server with an AES encryption algorithm (the key is initially passed to the client with the clients public RSA key).

