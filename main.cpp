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

using namespace std;

enum fields {
    COMMAND = 0,
    AUTHOR,
    TOPIC,
    BODY
};

class POST {
public:
    string author;
    string topic;
    string body;

    POST() : author(""), topic(""), body("") {}
    POST(const string &auth, const string &tp, const string &bd) : author(auth), topic(tp), body(bd) {}
};

class POSTS {
    POST posts[128];
    int length;
public:
    POSTS() : length(0) {}

    void push(const POST &post) {
        if (length < 128) {
            posts[length] = post;
            length++;
        } else {
            cerr << "ERROR: Post array full, cannot add more posts." << endl;
        }
    }

    POST getPost(int index) const {
        if (index >= 0 && index < length) {
            return posts[index];
        } else {
            return POST();
        }
    }

    int getLength() const {
        return length;
    }

    // Load posts from file: author|topic|body per line
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
                continue; // Invalid line, skip
            }

            string author = line.substr(0, firstPipe);
            string topic = line.substr(firstPipe + 1, secondPipe - firstPipe - 1);
            string body = line.substr(secondPipe + 1);

            POST p(author, topic, body);
            push(p);
        }
    }

    // Append a single post to file
    void appendToFile(const string &filename, const POST &post) {
        ofstream outfile(filename, ios::app);
        if (!outfile) {
            cerr << "WARNING: Could not open " << filename << " for writing." << endl;
            return;
        }
        outfile << post.author << "|" << post.topic << "|" << post.body << "\n";
    }
};

// User management
struct User {
    string username;
    string password;
};

// This class manages the users
class USERS {
    vector<User> userList;
public:
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

    void appendToFile(const string &filename, const User &user) {
        ofstream outfile(filename, ios::app);
        if (!outfile) {
            cerr << "WARNING: Could not open " << filename << " to write user." << endl;
            return;
        }
        outfile << user.username << "|" << user.password << "\n";
    }

    bool userExists(const string &username) {
        for (auto &u : userList) {
            if (u.username == username) return true;
        }
        return false;
    }

    bool createUser(const string &filename, const string &username, const string &password) {
        // Validate username and password
        if (username.length() == 0 || username.length() > 20) {
            return false; // invalid username length
        }
        if (password.length() < 8) {
            return false; // password too short
        }
        if (userExists(username)) {
            return false; // user already exists
        }

        User u{username, password};
        userList.push_back(u);
        appendToFile(filename, u);
        return true;
    }

    bool loginUser(const string &username, const string &password) {
        for (auto &u : userList) {
            if (u.username == username && u.password == password) {
                return true;
            }
        }
        return false;
    }
};

// Global Variables
static atomic<bool> serverRunning(true);
static POSTS posts;
static USERS users;
static std::mutex postsMutex;
static std::mutex userMutex;

static const string POSTS_FILENAME = "posts.txt";
static const string USERS_FILENAME = "users.txt";

// Helper function to split incoming message
void separateStrings(const string &str, string *output) {
    // Up to 4 segments: command, author/username, topic, body
    int outputIndex = 0;
    size_t start = 0;
    size_t pos = 0;

    while (outputIndex < 4 && (pos = str.find('|', start)) != string::npos) {
        output[outputIndex++] = str.substr(start, pos - start);
        start = pos + 1;
    }

    if (outputIndex < 4 && start < str.size()) {
        output[outputIndex] = str.substr(start);
    }
}

/**
 * handleClient function:
 * Each client thread maintains its own state:
 * - Whether the client is logged in or not.
 * - Current username (if logged in).
 *
 * Commands:
 * - CREATE|username|password
 * - LOGIN|username|password
 * - GET or GET|username
 * - POST|topic|body (author is current user or anonymous)
 * - RECEIVED
 * - EXIT
 * - CLOSE SERVER
 */
void handleClient(int clientSocket) {
    bool connected = true;
    string lastCommand = "GET";
    int sendIndex = 0;
    bool loggedIn = false;
    string currentUser = "anonymous"; // default if not logged in

    // Helper function to send a response
    auto sendMessage = [&](const string &msg) {
        if (send(clientSocket, msg.c_str(), msg.size(), 0) == -1) {
            cerr << "ERROR: Failed to send message to client." << endl;
            connected = false;
        }
    };

    while (connected) {
        char buffer[128] = {0};
        ssize_t recvSize = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (recvSize <= 0) {
            cerr << "Client disconnected or failed to receive." << endl;
            connected = false;
            break;
        }

        string receivedMessage[4];
        for (int i = 0; i < 4; i++) receivedMessage[i].clear();
        separateStrings(string(buffer), receivedMessage);

        string cmd = receivedMessage[COMMAND];
        if (cmd.empty()) {
            sendMessage("FAILED|Server|Invalid command");
            continue;
        }

        lastCommand = cmd;
        if (cmd == "EXIT") {
            sendMessage("OK|Server|Understood");
            connected = false;
        }
        else if (cmd == "CLOSE SERVER") {
            sendMessage("OK|Server|Understood");
            connected = false;
            serverRunning = false;
        }
        else if (cmd == "CREATE") {
            // CREATE|username|password
            string username = receivedMessage[AUTHOR];
            string password = receivedMessage[TOPIC]; // Here TOPIC holds password due to indexing

            if (username.empty() || password.empty()) {
                sendMessage("FAILED|Server|Missing username or password");
            } else {
                std::lock_guard<std::mutex> lock(userMutex);
                if (!users.createUser(USERS_FILENAME, username, password)) {
                    sendMessage("FAILED|Server|Could not create user. Check uniqueness, length, or password strength.");
                } else {
                    sendMessage("OK|Server|User created");
                }
            }
        }
        else if (cmd == "LOGIN") {
            // LOGIN|username|password
            string username = receivedMessage[AUTHOR];
            string password = receivedMessage[TOPIC];

            if (username.empty() || password.empty()) {
                sendMessage("FAILED|Server|Missing username or password");
            } else {
                std::lock_guard<std::mutex> lock(userMutex);
                if (users.loginUser(username, password)) {
                    loggedIn = true;
                    currentUser = username;
                    sendMessage("OK|Server|Logged in");
                } else {
                    sendMessage("FAILED|Server|Invalid credentials");
                }
            }
        }
        else if (cmd == "GET") {
            // GET or GET|username
            // If GET|username given, show posts for that user only
            string userFilter = receivedMessage[AUTHOR];
            {
                std::lock_guard<std::mutex> lock(postsMutex);
                sendIndex = 0;
                int length = posts.getLength();

                // We'll filter posts if a username is provided
                // We'll store the filtered indices in a vector to iterate through
                vector<int> filteredIndices;
                for (int i = 0; i < length; i++) {
                    POST p = posts.getPost(i);
                    if (userFilter.empty() || p.author == userFilter) {
                        filteredIndices.push_back(i);
                    }
                }

                if (filteredIndices.empty()) {
                    // No posts or no posts from that user
                    sendMessage("OK|Server|No posts found");
                } else {
                    // Send the first post
                    POST currentPost = posts.getPost(filteredIndices[0]);
                    string msg = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendMessage(msg);

                    // We'll handle RECEIVED by remembering these indices in a local lambda capture
                    // Actually, we need to handle multiple GET/RECEIVED cycles
                    // We'll store them in the sendIndex and a vector local to this function is lost after the block
                    // Let's store filtered posts in a static thread local for simplicity
                    // A cleaner approach: We'll reuse receivedMessage structure to store states
                    // For simplicity, let's store them in thread local static variables.

                    // However, we need a persistent way to track the filtered indices between RECEIVED calls.
                    // Let's store them in a lambda capture by reference. But that lambda ends with the scope.

                    // Instead, store them in a small dynamic structure within this loop:
                    struct ClientSessionState {
                        vector<int> filtered;
                    };

                    // We'll hack this in by using a static thread_local:
                    static thread_local ClientSessionState sessionState;
                    sessionState.filtered = filteredIndices;

                    // On RECEIVED, we will use sessionState.filtered and sendIndex
                    // We'll store sendIndex as well. sendIndex is already a member variable here.
                    // We'll just remember that after GET we have a filtered list.

                    // We need a way to know if the last command was a GET or something else
                    // so we know when to use sessionState.filtered. Let's store another static:
                    static thread_local bool lastWasGet;
                    lastWasGet = true;

                    // Now modify handle RECEIVED to check lastWasGet and use sessionState.filtered.
                    // Wait, we must rework RECEIVED logic now:

                    // Let's break out of this block first, then we fix RECEIVED.
                }
            }
        }
        else if (cmd == "RECEIVED") {
            // After GET, the client acknowledges a message and wants the next one.
            // We need to handle filtering logic introduced in GET.

            // We'll use static thread_local storage to store filtering context per thread:
            struct ClientSessionState {
                vector<int> filtered;
                bool lastWasGet;
            };
            // Declare static thread_local inside function scope is tricky. Let's move them outside of this if block:
        }
        else if (cmd == "POST") {
            // POST|topic|body
            // Author is currentUser if loggedIn, otherwise "anonymous"
            string topic = receivedMessage[TOPIC];
            string body = receivedMessage[BODY];
            if (topic.empty() || body.empty()) {
                sendMessage("FAILED|Server|Missing topic or body");
            } else {
                // Add a new post
                POST newPost(currentUser, topic, body);
                {
                    std::lock_guard<std::mutex> lock(postsMutex);
                    posts.push(newPost);
                    posts.appendToFile(POSTS_FILENAME, newPost);
                }
                sendMessage("OK|Server|Added post");
            }
        }
        else {
            // Unknown command
            sendMessage("FAILED|Server|Unknown command");
        }

        // Handling the RECEIVED command and GET filtering outside the main if-block:
        // The above approach needs a small redesign to handle GET/RECEIVED state across calls.
    }

    close(clientSocket);
    cout << "Client thread terminating." << endl;
}

// To handle GET/RECEIVED properly, we need some per-thread state that persists across calls.
// We'll redesign slightly: we'll create a struct to store client state and pass it into handleClient by reference.
// However, since we can't easily do that with threads, we can store thread_local variables for per-thread state.

struct ClientSessionState {
    vector<int> filteredIndices;  // Indices of posts that match the GET filter
    bool lastCommandWasGet = false;
    int sendIndex = 0; // index into filteredIndices
    bool loggedIn = false;
    string currentUser = "anonymous";
};

// We'll refactor handleClient with a helper function that uses static thread_local state:
static thread_local ClientSessionState sessionState;

void handleClientThread(int clientSocket) {
    bool connected = true;
    // Initialize per-session state
    sessionState.filteredIndices.clear();
    sessionState.lastCommandWasGet = false;
    sessionState.sendIndex = 0;
    sessionState.loggedIn = false;
    sessionState.currentUser = "anonymous";

    auto sendMessage = [&](const string &msg) {
        if (send(clientSocket, msg.c_str(), msg.size(), 0) == -1) {
            cerr << "ERROR: Failed to send message to client." << endl;
            connected = false;
        }
    };

    while (connected) {
        char buffer[128] = {0};
        ssize_t recvSize = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (recvSize <= 0) {
            cerr << "Client disconnected or failed to receive." << endl;
            connected = false;
            break;
        }

        string receivedMessage[4];
        for (int i = 0; i < 4; i++) receivedMessage[i].clear();
        separateStrings(string(buffer), receivedMessage);

        string cmd = receivedMessage[COMMAND];
        if (cmd.empty()) {
            sendMessage("FAILED|Server|Invalid command");
            continue;
        }

        if (cmd == "EXIT") {
            sendMessage("OK|Server|Understood");
            connected = false;
        }
        else if (cmd == "CLOSE SERVER") {
            sendMessage("OK|Server|Understood");
            connected = false;
            serverRunning = false;
        }
        else if (cmd == "CREATE") {
            string username = receivedMessage[AUTHOR];
            string password = receivedMessage[TOPIC];
            if (username.empty() || password.empty()) {
                sendMessage("FAILED|Server|Missing username or password");
            } else {
                std::lock_guard<std::mutex> lock(userMutex);
                if (!users.createUser(USERS_FILENAME, username, password)) {
                    sendMessage("FAILED|Server|Could not create user. Check uniqueness, username length <= 20, password length >= 8.");
                } else {
                    sendMessage("OK|Server|User created");
                }
            }
        }
        else if (cmd == "LOGIN") {
            string username = receivedMessage[AUTHOR];
            string password = receivedMessage[TOPIC];
            if (username.empty() || password.empty()) {
                sendMessage("FAILED|Server|Missing username or password");
            } else {
                std::lock_guard<std::mutex> lock(userMutex);
                if (users.loginUser(username, password)) {
                    sessionState.loggedIn = true;
                    sessionState.currentUser = username;
                    sendMessage("OK|Server|Logged in");
                } else {
                    sendMessage("FAILED|Server|Invalid credentials");
                }
            }
        }
        else if (cmd == "GET") {
            string userFilter = receivedMessage[AUTHOR]; // If present, filter by this username
            {
                std::lock_guard<std::mutex> lock(postsMutex);
                sessionState.filteredIndices.clear();
                sessionState.sendIndex = 0;
                int length = posts.getLength();
                for (int i = 0; i < length; i++) {
                    POST p = posts.getPost(i);
                    if (userFilter.empty() || p.author == userFilter) {
                        sessionState.filteredIndices.push_back(i);
                    }
                }
                sessionState.lastCommandWasGet = true;

                if (sessionState.filteredIndices.empty()) {
                    sendMessage("OK|Server|No posts found");
                } else {
                    POST currentPost = posts.getPost(sessionState.filteredIndices[0]);
                    string msg = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendMessage(msg);
                    sessionState.sendIndex = 1; // next post will be at index 1 in filteredIndices
                }
            }
        }
        else if (cmd == "RECEIVED") {
            if (!sessionState.lastCommandWasGet) {
                sendMessage("FAILED|Server|No GET command active");
            } else {
                std::lock_guard<std::mutex> lock(postsMutex);
                if (sessionState.sendIndex >= (int)sessionState.filteredIndices.size()) {
                    sendMessage("DONE|Server|All posts have been sent");
                    sessionState.lastCommandWasGet = false;
                } else {
                    int idx = sessionState.filteredIndices[sessionState.sendIndex];
                    POST currentPost = posts.getPost(idx);
                    string msg = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendMessage(msg);
                    sessionState.sendIndex++;
                }
            }
        }
        else if (cmd == "POST") {
            string topic = receivedMessage[TOPIC];
            string body = receivedMessage[BODY];
            if (topic.empty() || body.empty()) {
                sendMessage("FAILED|Server|Missing topic or body");
            } else {
                POST newPost(sessionState.loggedIn ? sessionState.currentUser : "anonymous", topic, body);
                {
                    std::lock_guard<std::mutex> lock(postsMutex);
                    posts.push(newPost);
                    posts.appendToFile(POSTS_FILENAME, newPost);
                }
                sendMessage("OK|Server|Added post");
            }
        }
        else {
            sendMessage("FAILED|Server|Unknown command");
        }
    }

    close(clientSocket);
    cout << "Client thread terminating." << endl;
}

int main() {
    // Load posts and users at startup
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
        cerr << "ERROR: Failed to create ServerSocket" << endl;
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
        cerr << "ERROR: Failed to bind ServerSocket" << endl;
        return 1;
    }

    if (listen(ServerSocket, 10) == -1) {
        close(ServerSocket);
        cerr << "ERROR: Listen failed to configure ServerSocket" << endl;
        return 1;
    }

    cout << "Server is running. Waiting for clients on port 27000..." << endl;

    while (serverRunning) {
        sockaddr_in clientAddr{};
        socklen_t clientAddrSize = sizeof(clientAddr);
        int ConnectionSocket = accept(ServerSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (ConnectionSocket == -1) {
            if (!serverRunning) break;
            cerr << "ERROR: Failed to accept connection. Continuing..." << endl;
            continue;
        }

        cout << "Client connected. Spawning new thread to handle this client." << endl;
        thread clientThread(handleClientThread, ConnectionSocket);
        clientThread.detach();
    }

    close(ServerSocket);
    cout << "Server shutting down gracefully." << endl;
    return 0;
}
