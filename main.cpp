#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <fstream>
#include <algorithm>

using namespace std;

/*
   This server application listens for incoming client connections on a specified port.
   Clients can:
   - Create new user accounts
   - Log in with existing accounts
   - Retrieve posts (optionally filtered by a particular author)
   - Submit new posts
   - Exit the connection or request the server to shut down

   Authentication ensures that if a user is logged in, any post made will include the logged-in username as the author.
   If a user is not logged in, the author field defaults to "anonymous".

   The protocol uses pipe ('|') separated commands and responses:
   - Commands from clients are generally in the format:
     COMMAND|param1|param2|...
   - Responses from the server generally start with:
     OK|... or FAILED|... or MESSAGE|... or DONE|...

   The server runs on a single port, handling multiple clients using threads.
   Each client connection is managed by a dedicated thread.
   Shared data (posts and user accounts) is protected by mutex locks.
   A thread-local structure maintains per-client session state (e.g., current user, logged-in status).
*/


// Files used for persistent storage of posts and users
static const string POSTS_FILENAME = "posts.txt";
static const string USERS_FILENAME = "users.txt";


// Represents a single post on the discussion board.
class POST {
public:
    string author; // The author of the post
    string topic;  // The topic or title of the post
    string body;   // The main text content of the post

    POST() : author(""), topic(""), body("") {}
    POST(const string &auth, const string &tp, const string &bd) : author(auth), topic(tp), body(bd) {}
};


// Manages an array of posts and provides file I/O for loading and appending posts.
class POSTS {
    POST posts[128]; // Fixed-size array to store posts
    int length;      // Current number of posts stored
public:
    POSTS() : length(0) {}

    // Adds a new post to the array if space is available.
    void push(const POST &post) {
        if (length < 128) {
            posts[length] = post;
            length++;
        } else {
            cerr << "ERROR: Post array is full. Cannot add more posts." << endl;
        }
    }

    // Retrieves a post by its index. Returns an empty post if out of range.
    POST getPost(int index) const {
        if (index >= 0 && index < length) {
            return posts[index];
        } else {
            return POST();
        }
    }

    // Returns the current count of posts.
    int getLength() const {
        return length;
    }

    // Loads posts from a file. The file format is one post per line:
    // author|topic|body
    void loadFromFile(const string &filename) {
        ifstream infile(filename);
        if (!infile) {
            return;
        }

        string line;
        while (getline(infile, line)) {
            if (line.empty()) continue;
            size_t firstPipe = line.find('|');
            size_t secondPipe = line.find('|', firstPipe + 1);
            if (firstPipe == string::npos || secondPipe == string::npos) {
                // Invalid line format, skip
                continue;
            }

            string author = line.substr(0, firstPipe);
            string topic = line.substr(firstPipe + 1, secondPipe - firstPipe - 1);
            string body = line.substr(secondPipe + 1);

            POST p(author, topic, body);
            push(p);
        }
    }

    // Appends a single post to the specified file.
    void appendToFile(const string &filename, const POST &post) {
        ofstream outfile(filename, ios::app);
        if (!outfile) {
            cerr << "WARNING: Could not open " << filename << " for writing posts." << endl;
            return;
        }
        outfile << post.author << "|" << post.topic << "|" << post.body << "\n";
    }
};


// Represents a user with a lowercase username and a password.
struct User {
    string username;
    string password;
};


// Manages a collection of users and provides file I/O for loading and appending users.
class USERS {
    vector<User> userList; // Dynamic list of registered users
public:
    // Loads users from a file. Format:
    // username|password
    void loadFromFile(const string &filename) {
        ifstream infile(filename);
        if (!infile) return;

        string line;
        while (getline(infile, line)) {
            if (line.empty()) continue;
            size_t pipePos = line.find('|');
            if (pipePos == string::npos) continue;
            string username = line.substr(0, pipePos);
            string password = line.substr(pipePos + 1);
            userList.push_back({username, password});
        }
    }

    // Appends a new user to the users file.
    void appendToFile(const string &filename, const User &user) {
        ofstream outfile(filename, ios::app);
        if (!outfile) {
            cerr << "WARNING: Could not open " << filename << " to write user." << endl;
            return;
        }
        outfile << user.username << "|" << user.password << "\n";
    }

    // Checks if a user with the given username already exists.
    bool userExists(const string &username) {
        for (auto &u : userList) {
            if (u.username == username) return true;
        }
        return false;
    }

    // Creates a new user and stores it if conditions are met:
    // - Username length: 1-20 characters
    // - Password length: >= 8 characters
    // - Username must not already exist
    // - Username will be stored in lowercase
    bool createUser(const string &filename, string username, const string &password) {
        transform(username.begin(), username.end(), username.begin(), ::tolower);

        if (username.empty() || username.size() > 20) {
            return false;
        }
        if (password.size() < 8) {
            return false;
        }
        if (userExists(username)) {
            return false;
        }

        User u{username, password};
        userList.push_back(u);
        appendToFile(filename, u);
        return true;
    }

    // Attempts to log in a user by checking if the given username and password match any stored user.
    bool loginUser(string username, const string &password) {
        transform(username.begin(), username.end(), username.begin(), ::tolower);

        for (auto &u : userList) {
            if (u.username == username && u.password == password) {
                return true;
            }
        }
        return false;
    }
};


// Controls whether the server continues accepting clients.
static atomic<bool> serverRunning(true);

// Global instance that holds posts.
static POSTS posts;

// Global instance that holds users.
static USERS users;

// Mutexes for thread-safe access to global resources.
static std::mutex postsMutex;
static std::mutex userMutex;

/*
   Each client session (thread) maintains its own state:
   - filteredIndices: indices of posts currently filtered by a GET command
   - lastCommandWasGet: indicates if the last command was a GET, so RECEIVED can continue retrieving
   - sendIndex: index into filteredIndices for sending MESSAGE responses
   - loggedIn: whether the client is logged in
   - currentUser: the username of the currently logged-in user, or "anonymous" if not logged in
*/
struct ClientSessionState {
    vector<int> filteredIndices;
    bool lastCommandWasGet = false;
    int sendIndex = 0;
    bool loggedIn = false;
    string currentUser = "anonymous";
};

// thread_local ensures each client thread has its own session state.
static thread_local ClientSessionState sessionState;


// Splits an input string by '|' and stores the fields in a vector.
static void splitByPipe(const string &str, vector<string> &fields) {
    size_t start = 0;
    size_t pos;
    while ((pos = str.find('|', start)) != string::npos) {
        fields.push_back(str.substr(start, pos - start));
        start = pos + 1;
    }
    if (start < str.size()) {
        fields.push_back(str.substr(start));
    } else if (!str.empty() && str.back() == '|') {
        fields.push_back("");
    }
}


// Handles a single connected client in a dedicated thread.
// Processes client commands and sends responses according to the defined protocol.
void handleClientThread(int clientSocket) {
    bool connected = true;

    // Initialize per-client state for this thread.
    sessionState.filteredIndices.clear();
    sessionState.lastCommandWasGet = false;
    sessionState.sendIndex = 0;
    sessionState.loggedIn = false;
    sessionState.currentUser = "anonymous";

    // Helper lambda to send a message to the client.
    auto sendMessage = [&](const string &msg) {
        if (send(clientSocket, msg.c_str(), msg.size(), 0) == -1) {
            cerr << "ERROR: Failed to send message to client." << endl;
            connected = false;
        }
    };

    // Helper lambda to get the appropriate prefix for responses. If user is logged in, use their username, otherwise "anonymous".
    auto responsePrefix = [&]() -> string {
        return sessionState.currentUser;
    };

    // Continuously read commands from the client until disconnected or instructed to EXIT.
    while (connected) {
        char buffer[128] = {0};
        ssize_t recvSize = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (recvSize <= 0) {
            // Client either disconnected or there's a receive error.
            cerr << "Client disconnected or failed to receive." << endl;
            connected = false;
            break;
        }

        string input(buffer);
        vector<string> fields;
        splitByPipe(input, fields);

        if (fields.empty()) {
            sendMessage("FAILED|" + responsePrefix() + "|Invalid command");
            continue;
        }

        string cmd = fields[0];

        // Process the command from the client.
        if (cmd == "EXIT") {
            // The client wants to close its connection to the server.
            sendMessage("OK|" + responsePrefix() + "|Understood");
            connected = false;
        }
        else if (cmd == "CLOSE SERVER") {
            // The client requests the server shutdown entirely.
            sendMessage("OK|" + responsePrefix() + "|Understood");
            connected = false;
            serverRunning = false;
        }
        else if (cmd == "CREATE") {
            // CREATE|username|password
            // Attempts to create a new user.
            if (fields.size() != 3) {
                sendMessage("FAILED|" + responsePrefix() + "|Missing username or password");
                continue;
            }
            string username = fields[1];
            string password = fields[2];

            {
                std::lock_guard<std::mutex> lock(userMutex);
                if (!users.createUser(USERS_FILENAME, username, password)) {
                    sendMessage("FAILED|" + responsePrefix() + "|User creation failed. Check uniqueness, username length <= 20, password length >= 8.");
                } else {
                    sendMessage("OK|" + responsePrefix() + "|User created");
                }
            }
        }
        else if (cmd == "LOGIN") {
            // LOGIN|username|password
            // Authenticates an existing user.
            if (fields.size() != 3) {
                sendMessage("FAILED|" + responsePrefix() + "|Missing username or password");
                continue;
            }
            string username = fields[1];
            string password = fields[2];

            transform(username.begin(), username.end(), username.begin(), ::tolower);

            {
                std::lock_guard<std::mutex> lock(userMutex);
                if (users.loginUser(username, password)) {
                    sessionState.loggedIn = true;
                    sessionState.currentUser = username;
                    sendMessage("OK|" + responsePrefix() + "|Logged in as " + username);
                } else {
                    sendMessage("FAILED|" + responsePrefix() + "|Invalid credentials");
                }
            }
        }
        else if (cmd == "GET") {
            // GET or GET|username
            // Retrieves posts filtered by an optional username.
            string userFilter;
            if (fields.size() == 2) {
                userFilter = fields[1];
                transform(userFilter.begin(), userFilter.end(), userFilter.begin(), ::tolower);
            } else if (fields.size() > 2) {
                sendMessage("FAILED|" + responsePrefix() + "|Too many parameters");
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(postsMutex);
                sessionState.filteredIndices.clear();
                sessionState.sendIndex = 0;
                int length = posts.getLength();
                for (int i = 0; i < length; i++) {
                    POST p = posts.getPost(i);
                    // If no filter given, include all. If a filter is given, include only matching author posts.
                    if (userFilter.empty() || p.author == userFilter) {
                        sessionState.filteredIndices.push_back(i);
                    }
                }
                sessionState.lastCommandWasGet = true;

                if (sessionState.filteredIndices.empty()) {
                    sendMessage("OK|" + responsePrefix() + "|No posts found");
                } else {
                    // Send the first post immediately.
                    POST currentPost = posts.getPost(sessionState.filteredIndices[0]);
                    string msg = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendMessage(msg);
                    sessionState.sendIndex = 1;
                }
            }
        }
        else if (cmd == "RECEIVED") {
            // Client acknowledges receiving the last MESSAGE.
            // Server responds with the next post if available, or DONE if none remain.
            if (fields.size() != 1) {
                sendMessage("FAILED|" + responsePrefix() + "|Invalid RECEIVED command");
                continue;
            }
            if (!sessionState.lastCommandWasGet) {
                sendMessage("FAILED|" + responsePrefix() + "|No GET command active");
            } else {
                std::lock_guard<std::mutex> lock(postsMutex);
                if (sessionState.sendIndex >= (int)sessionState.filteredIndices.size()) {
                    // No more posts to send.
                    sendMessage("DONE|" + responsePrefix() + "|All posts have been sent");
                    sessionState.lastCommandWasGet = false;
                } else {
                    // Send the next post in the filtered list.
                    int idx = sessionState.filteredIndices[sessionState.sendIndex];
                    POST currentPost = posts.getPost(idx);
                    string msg = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendMessage(msg);
                    sessionState.sendIndex++;
                }
            }
        }
        else if (cmd == "POST") {
            // POST|topic|body
            // Adds a new post by the current user (or "anonymous" if not logged in).
            if (fields.size() != 3) {
                sendMessage("FAILED|" + responsePrefix() + "|Missing topic or body");
                continue;
            }
            string topic = fields[1];
            string body = fields[2];
            if (topic.empty() || body.empty()) {
                sendMessage("FAILED|" + responsePrefix() + "|Missing topic or body");
            } else {
                POST newPost(sessionState.currentUser, topic, body);
                {
                    std::lock_guard<std::mutex> lock(postsMutex);
                    posts.push(newPost);
                    posts.appendToFile(POSTS_FILENAME, newPost);
                }
                sendMessage("OK|" + responsePrefix() + "|Added post");
            }
        }
        else {
            // Unknown command
            sendMessage("FAILED|" + responsePrefix() + "|Unknown command");
        }
    }

    close(clientSocket);
    cout << "Client thread terminating." << endl;
}


// The main function:
// 1. Loads posts and users from files.
// 2. Sets up a listening socket on port 27000.
// 3. Accepts incoming client connections and spawns a thread for each.
// 4. Continues until a CLOSE SERVER command is received or terminated otherwise.
int main() {
    {
        std::lock_guard<std::mutex> lock(postsMutex);
        posts.loadFromFile(POSTS_FILENAME);
    }
    {
        std::lock_guard<std::mutex> lock(userMutex);
        users.loadFromFile(USERS_FILENAME);
    }

    int ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ServerSocket == -1) {
        cerr << "ERROR: Failed to create server socket." << endl;
        return 1;
    }

    int opt = 1;
    setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in SvrAddr{};
    SvrAddr.sin_family = AF_INET;
    SvrAddr.sin_addr.s_addr = INADDR_ANY;
    SvrAddr.sin_port = htons(27000);

    if (bind(ServerSocket, (struct sockaddr *)&SvrAddr, sizeof(SvrAddr)) == -1) {
        close(ServerSocket);
        cerr << "ERROR: Failed to bind server socket to port." << endl;
        return 1;
    }

    if (listen(ServerSocket, 10) == -1) {
        close(ServerSocket);
        cerr << "ERROR: Failed to listen on server socket." << endl;
        return 1;
    }

    cout << "Server is running and listening on port 27000..." << endl;

    while (serverRunning) {
        sockaddr_in clientAddr{};
        socklen_t clientAddrSize = sizeof(clientAddr);
        int ConnectionSocket = accept(ServerSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (ConnectionSocket == -1) {
            // If serverRunning is false, we are shutting down, otherwise just continue.
            if (!serverRunning) break;
            cerr << "ERROR: Failed to accept a client connection. Will continue..." << endl;
            continue;
        }

        cout << "Client connected. Spawning handler thread." << endl;
        thread clientThread(handleClientThread, ConnectionSocket);
        clientThread.detach();
    }

    close(ServerSocket);
    cout << "Server shutting down gracefully." << endl;
    return 0;
}
