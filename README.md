# Ubuntu Server

A lightweight C++ multi-threaded discussion board server application that allows users to create accounts, authenticate, post messages, and retrieve content.

## Features

- User account creation and authentication
- Post creation and retrieval (with optional author filtering)
- Thread-safe concurrent client handling
- Persistent storage of posts and user accounts
- Simple pipe-delimited protocol for client-server communication

## Protocol

The server communicates using a pipe (`|`) separated protocol:

### Client Commands
- `CREATE|username|password` - Create a new user account
- `LOGIN|username|password` - Log in with existing credentials
- `GET` - Retrieve all posts
- `GET|username` - Retrieve posts from a specific author
- `RECEIVED` - Acknowledge receipt of a post and request the next one
- `POST|topic|body` - Create a new post
- `EXIT` - Disconnect from the server
- `CLOSE SERVER` - Shut down the server

### Server Responses
- `OK|author|message` - Command succeeded
- `FAILED|author|reason` - Command failed
- `MESSAGE|author|topic|body` - Post content
- `DONE|author|message` - No more posts to send

## Building

Requirements:
- CMake 3.30 or newer
- C++20 compatible compiler

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

Run the server:
```bash
./UbuntuServer
```

The server will start listening on port 27000.

## Storage

The server uses two text files for persistent storage:
- `posts.txt` - Stores all posts in the format: `author|topic|body`
- `users.txt` - Stores user credentials in the format: `username|password`

## Notes

- Usernames are converted to lowercase and limited to 20 characters
- Passwords must be at least 8 characters
- Posts are protected by mutex locks for thread safety
- The server can handle multiple clients simultaneously
