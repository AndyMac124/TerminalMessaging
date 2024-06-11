#!/usr/bin/env bash

# Checking if arguments were supplied for both the host name and port number
if [ $# -ne 2 ]
then
  echo "Please supply both the host name and port number"
  exit 1
fi

# Assigning the host and port for clarity
host="$1"
port="$2"

# Compiling the file
javac Client.java

echo "Starting the client..."

# Starting the client
java Client "$host" "$port"