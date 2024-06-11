#!/usr/bin/env bash

# Checking if an argument was supplied for the port number
if [ $# -ne 1 ]
then
  echo "Please only supply the port number"
  exit 1
fi

# Assigning the port for clarity
port="$1"

# Compiling the file
javac Server.java

echo "Starting the server..."

# Starting Server
java Server "$port"
