#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <fstream>

using namespace std;

enum messages
{
    COMMAND,
    AUTHOR,
    TOPIC,
    BODY
};

class POST
{
public:
    string author;
    string topic;
    string body;

    POST()
    {
        author = "";
        topic = "";
        body = "";
    }
};

class POSTS
{
    POST posts[128];
    int length;

public:
    POSTS()
    {
        length = 0;
    }

    void push(const POST &post)
    {
        if (length < 128)
        {
            posts[length] = post;
            length++;
        }
        else
        {
            cerr << "ERROR: Post array full" << endl;
        }
    }

    POST getPost(int index) const
    {
        if (index >= 0 && index < length)
        {
            return posts[index];
        }
        else
        {
            return POST(); // Return an empty POST object if index is invalid
        }
    }

    int getLength() const
    {
        return length;
    }
};

void seperateStrings(const string &str, string *output)
{
    int i = 0;
    int start = 0;
    int outputLength = 0;

    while (i < str.length())
    {
        if (str[i] == '|')
        {
            output[outputLength++] = str.substr(start, i - start);
            start = i + 1;
        }
        i++;
    }

    if (start < str.length())
    {
        output[outputLength] = str.substr(start);
    }
}

POST createPostFromArray(string *arr)
{
    POST newPost;
    newPost.author = arr[AUTHOR];
    newPost.topic = arr[TOPIC];
    newPost.body = arr[BODY];

    return newPost;
}

void loadFromFile(const string &filename, POSTS *posts)
{
    ifstream file(filename);
    if (!file)
        return;

    string line;
    while (getline(file, line))
    {
        if (line.empty())
            continue;

        string filePost[4];
        seperateStrings(line, filePost);
        posts->push(createPostFromArray(filePost));
    }
}

void saveToFile(const string &filename, const POSTS &posts)
{
    ofstream file(filename);
    if (!file)
    {
        cerr << "WARNING: Could not open " << filename << " for writing posts." << endl;
        return;
    }

    for (int i = 0; i < posts.getLength(); i++)
    {
        POST post = posts.getPost(i);
        file << "FILE|" << post.author << "|" << post.topic << "|" << post.body << "\n";
    }
}

int main()
{
    // The rest of the main function is unchanged
    int ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ServerSocket == -1)
    {
        cerr << "ERROR: Failed to create ServerSocket" << endl;
        return 1;
    }

    sockaddr_in SvrAddr{};
    SvrAddr.sin_family = AF_INET;
    SvrAddr.sin_addr.s_addr = INADDR_ANY;
    SvrAddr.sin_port = htons(27000);

    if (bind(ServerSocket, (struct sockaddr *)&SvrAddr, sizeof(SvrAddr)) == -1)
    {
        close(ServerSocket);
        cerr << "ERROR: Failed to bind ServerSocket" << endl;
        return 1;
    }

    POSTS posts;
    bool connected = false;
    string lastCommand = "GET";
    int sendIndex = 0;
    int ConnectionSocket = -1;

    do
    {
        if (!connected)
        {
            cout << "Listening for connections..." << endl;
            if (listen(ServerSocket, 1) == -1)
            {
                close(ServerSocket);
                cerr << "ERROR: Listen failed to configure ServerSocket" << endl;
                return 1;
            }

            ConnectionSocket = accept(ServerSocket, NULL, NULL);
            if (ConnectionSocket == -1)
            {
                cerr << "ERROR: Failed to accept connection" << endl;
                continue;
            }
            connected = true;
        }

        char buffer[128] = {0};
        if (recv(ConnectionSocket, buffer, sizeof(buffer) - 1, 0) == -1)
        {
            cerr << "ERROR: Failed to receive message" << endl;
            close(ConnectionSocket);
            connected = false;
            continue;
        }

        string receivedMessage[4];
        seperateStrings(buffer, receivedMessage);

        string message;

        if (receivedMessage[COMMAND].empty())
        {
            message = "FAILED|Server|Invalid command";
        }
        else
        {
            lastCommand = receivedMessage[COMMAND];

            if (receivedMessage[COMMAND] == "EXIT")
            {
                message = "OK|Server|Understood";
                connected = false;
            }
            else if (receivedMessage[COMMAND] == "CLOSE SERVER")
            {
                message = "OK|Server|Understood";
                connected = false;
            }
            else if (receivedMessage[COMMAND] == "GET")
            {
                sendIndex = 0;
                if (posts.getLength() == 0)
                {
                    message = "OK|Server|There are no posts";
                }
                else
                {
                    POST currentPost = posts.getPost(sendIndex);
                    message = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendIndex++;
                }
            }
            else if (receivedMessage[COMMAND] == "RECEIVED")
            {
                if (sendIndex >= posts.getLength())
                {
                    message = "DONE|Server|All posts have been sent";
                }
                else
                {
                    POST currentPost = posts.getPost(sendIndex);
                    message = "MESSAGE|" + currentPost.author + "|" + currentPost.topic + "|" + currentPost.body;
                    sendIndex++;
                }
            }
            else if (receivedMessage[COMMAND] == "POST")
            {
                if (receivedMessage[AUTHOR].empty() || receivedMessage[TOPIC].empty() || receivedMessage[BODY].empty())
                {
                    message = "FAILED|Server|Missing Author, Topic, or Body";
                }
                else
                {
                    POST newPost;
                    newPost.author = receivedMessage[AUTHOR];
                    newPost.topic = receivedMessage[TOPIC];
                    newPost.body = receivedMessage[BODY];

                    posts.push(newPost);
                    message = "OK|Server|Added post";
                }
            }
            else
            {
                message = "FAILED|Server|Couldn't find command";
            }
        }

        if (send(ConnectionSocket, message.c_str(), message.length(), 0) == -1)
        {
            cerr << "ERROR: Failed to send message" << endl;
            close(ConnectionSocket);
            connected = false;
        }
    } while (lastCommand != "CLOSE SERVER");

    close(ConnectionSocket);
    close(ServerSocket);

    return 0;
}
