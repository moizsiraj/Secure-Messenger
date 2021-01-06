#include <iostream>
#include <unistd.h>
#include <regex>
#include <cstdio>
#include <cstring>
#include <wait.h>
#include <algorithm>
#include <fcntl.h>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cmath>
#include <iomanip>
#include "DES.cpp"

using namespace std;

string str2hex(const string &s);

int findCID(char *username);

string hex2str(string hex);

int setOperation(char *operationText);

void signal_handler_CONH(int signo);

void signal_handler_CONHEXIT(int signo);

std::string getTime();

std::string elapsedTime(std::string startTime, std::string endTime);

int removeColon(std::string s);

void createSock();

long diffieHellman(long G, long P, long A, long B);

int registerUser(char *username, char *publicKey, char *privateKey);

int bindUserIP(char *username);

int setOperationServer(char *operationText);

int setOperationInput(char *operationText);

void updateClientList(int pid);

void *clientReader(void *ptr);

[[noreturn]] void *serverReader(void *ptr);

void *ServerInput2Client(void *ptr);

void *clientHandler(void *clientID);

int bindIP(char *username, string IP);

struct data {
    string A;
    string B;
};


data connectUser(char *username, string currentUser);

struct clients {
    int clientID = -1;
    int readingEnd = -1;
    int writingEnd = -1;
    int pid;
    int msgsock;
    std::string ip;
    std::string status;
    int serverWritingEnd = -1;
    int serverReadingEnd = -1;
};


string KDC[50][3];
string UIP[50][2];
string connections[25][2];
int noOfUsers = 0;//KDC
int noOfConUsers = 0;//UIP
int noOfConnections = 0;//connections
int write2CH[2];
int write2CON[2];
int write2SR[2];
int readSR[2];
int currentClientIndex = -1;
int activeClients = 0;
int sock;
int msgsock;
long DFHLG = 3;
long DFHLP = 17;
std::string ip;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

struct clients clientsList[50];

int main() {
    if (signal(SIGCHLD, signal_handler_CONH) == SIG_ERR) {
        write(STDOUT_FILENO, "sig error", 9);
    }
    if (signal(SIGINT | SIGHUP, signal_handler_CONHEXIT) == SIG_ERR) {
        write(STDOUT_FILENO, "sig error", 9);
    }
    pthread_t inputThread;
    pthread_t clientInputThread[10];
    int inputID;

    createSock();
    listen(sock, 5);
    write(STDOUT_FILENO, "Accepting Connections Now\n", 26);
//    inputID = pthread_create(&inputThread, nullptr, serverReader, (void *) nullptr);
    struct sockaddr_in addr;
    socklen_t client_addr_size = sizeof(struct sockaddr_in);
    int clientHandlerPID;
    while (true) {
        msgsock = accept(sock, (struct sockaddr *) &addr, &client_addr_size);
        if (msgsock != -1) {
            write(STDOUT_FILENO, "Client Connected\n", 17);
            currentClientIndex++;
            activeClients++;
            int checkPipe = pipe(write2CH);
            int checkPipe2 = pipe(write2CON);
            pipe(write2SR);
            pipe(readSR);
            clientsList[currentClientIndex].clientID = currentClientIndex;
            clientsList[currentClientIndex].readingEnd = write2CON[0];
            clientsList[currentClientIndex].writingEnd = write2CH[1];
            clientsList[currentClientIndex].ip = inet_ntoa(addr.sin_addr);
            clientsList[currentClientIndex].msgsock = msgsock;
            clientsList[currentClientIndex].status = "Connected";
            clientsList[currentClientIndex].serverReadingEnd = readSR[0];
            clientsList[currentClientIndex].serverWritingEnd = write2SR[1];
            ip = inet_ntoa(addr.sin_addr);

            int *arg = static_cast<int *>(malloc(sizeof(*arg)));
            if (arg == NULL) {
                fprintf(stderr, "Couldn't allocate memory for thread arg.\n");
                exit(EXIT_FAILURE);
            }

            *arg = currentClientIndex;
            pthread_create(&clientInputThread[currentClientIndex], nullptr, clientHandler, arg);

            clientHandlerPID = fork();
            if (clientHandlerPID == 0) {
                pthread_t CRThread;
                pthread_t SRThread;
                pthread_create(&CRThread, nullptr, clientReader, (void *) nullptr);
                pthread_create(&SRThread, nullptr, serverReader, (void *) nullptr);
                pthread_join(SRThread, nullptr);
                pthread_join(CRThread, nullptr);
            }
        } else {
            write(STDOUT_FILENO, "Connection fail\n", 16);
        }
        clientsList[currentClientIndex].pid = clientHandlerPID;
    }
//    pthread_join(inputThread, nullptr);
    for (int i = 0; i < currentClientIndex; ++i) {
        pthread_join(clientInputThread[i], nullptr);
    }
    return 0;
}

#pragma clang diagnostic pop

//creating socket
void createSock() {
    char output[500];
    struct sockaddr_in server{};//struct to store socket info
    int length;
    sock = socket(AF_INET, SOCK_STREAM, 0);//socket created
    if (sock < 0) {
        perror("opening stream socket");
        exit(1);
    } else {//setting values in the structure
        server.sin_family = AF_INET;//for communication over the internet
        server.sin_addr.s_addr = INADDR_ANY;//can connect to any address
        server.sin_port = 0;//passing 0 so system can assign any port number
    }
    if (bind(sock, (struct sockaddr *) &server, sizeof(server))) {//binding socket with the port
        perror("binding stream socket");
        exit(1);
    }
    length = sizeof(server);
    if (getsockname(sock, (struct sockaddr *) &server, (socklen_t *) &length)) {// getting the assigned port
        perror("getting socket name");
        exit(1);
    }
    int portNo = ntohs(server.sin_port);
    int noOfChars = sprintf(output, "%s", "Socket has port #\n");
    int portChars = sprintf(&output[noOfChars - 1], "%d\n", portNo);
    int count = noOfChars + portChars;
    write(STDOUT_FILENO, output, count);
    fflush(stdout);
}

//method to get current time
std::string getTime() {
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", timeinfo);
    std::string str(buffer);
    return str;
}

//helper method for time calculations
int removeColon(std::string s) {
    char buffer[8];
    int count = sprintf(buffer, "%s", s.c_str());
    std::replace(s.begin(), s.end(), ':', '0');
    count = sprintf(buffer, "%s", s.c_str());
    return std::stoi(s);
}

//calculating elapsed time
std::string elapsedTime(std::string startTime, std::string endTime) {
    int time1 = removeColon(startTime);
    int time2 = removeColon(endTime);

    int hourDiff = time2 / 1000000 - time1 / 1000000 - 1;
    time1 = time1 % 1000000;
    time2 = time2 % 1000000;

    int minDiff = time2 / 1000 + (60 - time1 / 1000);
    if (minDiff >= 60) {
        hourDiff++;
        minDiff = minDiff - 60;
    }

    time1 = time1 % 100;
    time2 = time2 % 100;

    int secDiff = (time2) + (60 - time1);
    if (secDiff >= 60) {
        secDiff = secDiff - 60;
    }
    std::string res = std::to_string(hourDiff) + ':' + std::to_string(minDiff) + ':' + std::to_string(secDiff);
    return res;
}


//operation setter for clientReader handler
int setOperation(char *operationText) {
    int operation;
    if (strcmp(operationText, "exit") == 0) {
        operation = 0;
    } else if (strcmp(operationText, "register") == 0) {
        operation = 1;
    } else if (strcmp(operationText, "messaging") == 0) {
        operation = 2;
    } else if (strcmp(operationText, "connect") == 0) {
        operation = 3;
    } else if (strcmp(operationText, "message") == 0) {
        operation = 4;
    } else if (strcmp(operationText, "disconnect") == 0) {
        operation = 5;
    } else if (strcmp(operationText, "exit") == 0) {
        operation = 6;
    } else {
        operation = -1;
    }
    return operation;
}

//operation setter for ServerInput2Client
int setOperationInput(char *operationText) {
    int operation;
    if (strcmp(operationText, "register") == 0) {
        operation = 1;
    } else if (strcmp(operationText, "messaging") == 0) {
        operation = 2;
    } else if (strcmp(operationText, "connect") == 0) {
        operation = 3;
    } else if (strcmp(operationText, "message") == 0) {
        operation = 4;
    } else if (strcmp(operationText, "disconnect") == 0) {
        operation = 5;
    } else if (strcmp(operationText, "exit") == 0) {
        operation = 6;
    } else {
        operation = -1;
    }
    return operation;
}

int setOperationServer(char *operationText) {
    int operation;
    if (strcmp(operationText, "request") == 0) {
        operation = 1;
    } else if (strcmp(operationText, "message") == 0) {
        operation = 2;
    } else {
        operation = -1;
    }
    return operation;
}

//for handling clientReader handler exits
void signal_handler_CONH(int signo) {
    if (signo == SIGCHLD) {
        int status;
        for (int activeClient = 0; activeClient <= activeClients; ++activeClient) {
            int pid = waitpid(0, &status, WNOHANG);
            if (pid != 0) {
                updateClientList(pid);
            }
        }
    }
}

void signal_handler_CONHEXIT(int signo) {
    if (signo == SIGINT || signo == SIGHUP) {
        if (activeClients == 0) {
            close(msgsock);
            exit(getpid());
        } else {
            for (int i = 0; i <= currentClientIndex; ++i) {
                if (strcmp(clientsList[i].status.c_str(), "Connected") == 0) {
                    int checkWrite = write(clientsList[i].writingEnd, "exit ", 5);
                }
            }
            close(msgsock);
            exit(getpid());
        }
    }
}

int registerUser(char *username, char *publicKey, char *privateKey) {
    std::string user(username);
    char out[10];
    for (int i = 0; i < noOfUsers; i++) {
        if (strcmp(user.c_str(), KDC[i][0].c_str()) == 0 || strcmp(publicKey, KDC[i][1].c_str()) == 0 ||
            strcmp(publicKey, KDC[i][2].c_str()) == 0) {
            return -1;
        }
    }
    std::string key(publicKey);
    std::string privKey(privateKey);
    KDC[noOfUsers][0] = user;
    KDC[noOfUsers][1] = key;
    KDC[noOfUsers][2] = privKey;
    noOfUsers++;
    return 0;
}

//clientReader handler thread
void *clientReader(void *ptr) {
    char inputText[500];
    char outputText[500];
    bool continueInput = true;
    char saveOperator[10];
    int operation = -1;
    char *token;

    write(msgsock, "Commands: kill <pid>, list, run <process> <path(optional)>, "
                   "add/div/sub/mul <list of numbers separated by spaces>\nInput exit to terminate:\n"
                   "Please input your command:\n", 166);

    while (continueInput) {
        int readCount = 0;
        while (true) {
            read(msgsock, &inputText[readCount], 1);
            if (inputText[readCount] == ':') {
                break;
            }
            readCount++;
        }
        inputText[readCount] = '\0';//adding null at the end

        if (readCount == 0) {//empty input
            write(msgsock, "Input next command\n", 19);
            continue;
        }
        //getting the first token to set operation
        token = strtok(inputText, " ");
        sscanf(token, "%s", saveOperator);
        operation = setOperation(saveOperator);
        //exit
        if (operation == 0) {
            continueInput = false;
            int *status = nullptr;
            write(msgsock, "exit\0", 5);
            close(sock);
            close(msgsock);
            wait(status);
            kill(getpid(), SIGTERM);
        }
            //invalid input
        else if (operation == -1) {
            write(msgsock, "Invalid command.\nInput next command\n", 36);
        }
            //register
        else if (operation == 1) {
            char *username;
            char *publicKey;
            char *privateKey;
            username = strtok(nullptr, " ");
            publicKey = strtok(nullptr, " ");
            privateKey = strtok(nullptr, " ");
            if (username == nullptr || publicKey == nullptr || privateKey == nullptr) {
                write(msgsock, "Invalid Command. Input next command\n", 36);
            } else {
                string registerCommand = "register ";
                registerCommand.append(username).append(" ").append(publicKey).append(" ").append(privateKey);
                int count = sprintf(outputText, "%s", registerCommand.c_str());
                write(write2CON[1], outputText, count);
                count = read(write2CH[0], outputText, 1000);
                write(msgsock, outputText, count);
            }
        }
            //messaging
        else if (operation == 2) {
            char *username;
            username = strtok(nullptr, " ");
            if (username == nullptr) {
                write(msgsock, "Invalid Command. Input next command\n", 36);
            } else {
                string registerCommand = "messaging ";
                registerCommand.append(username);
                int count = sprintf(outputText, "%s", registerCommand.c_str());
                write(write2CON[1], outputText, count);
                count = read(write2CH[0], outputText, 1000);
                write(msgsock, outputText, count);
            }
        }
            //connect
        else if (operation == 3) {
            char *username;
            username = strtok(nullptr, " ");
            if (username == nullptr) {
                write(msgsock, "Invalid Command. Input next command\n", 36);
            } else {
                string registerCommand = "connect ";
                registerCommand.append(username);
                int count = sprintf(outputText, "%s", registerCommand.c_str());
                write(write2CON[1], outputText, count);
                count = read(write2CH[0], outputText, 1000);
                write(msgsock, outputText, count);
            }
        }
    }
    return nullptr;
}

//server reader thread on the child process to take instructions from server
void *serverReader(void *ptr) {
    char input[1000];
    char saveOperator[10];
    int operation = -1;
    char *token;
    int checkRead;

    while (true) {
        checkRead = read(write2SR[0], input, 1000);//B1
        input[checkRead] = '\0';//adding null at the end
        //getting the first token to set operation
        token = strtok(input, " ");
        sscanf(token, "%s", saveOperator);
        operation = setOperationServer(saveOperator);
        //Request for connection
        if (operation == 1) {
            write(readSR[1], "done", 4);
        }
            //Message from user
        else if (operation == 2) {

        }
    }

}

//update clientReader list on disconnects
void updateClientList(int pid) {
    int index = -1;
    for (int client = 0; client <= currentClientIndex; ++client) {
        if (clientsList[client].pid == pid) {
            index = client;
            break;
        }
    }
    if (index != -1) {
        close(clientsList[index].writingEnd);
        close(clientsList[index].readingEnd);
        close(clientsList[index].msgsock);
        clientsList[index].status = "Disconnected";
        activeClients--;
    }
}


void *clientHandler(void *clientID) {
    char input[1000];
    char output[1000];
    char saveOperator[10];
    int operation = -1;
    char *token;
    string currentUser;
    string privKey;
    string pubKey;
    string sessionKey;
    int checkRead;


    while (true) {
        int CID = *((int *) clientID);
        checkRead = read(clientsList[CID].readingEnd, input, 1000);//B2//B4
        input[checkRead] = '\0';//adding null at the end
        token = strtok(input, " ");
        sscanf(token, "%s", saveOperator);
        operation = setOperationInput(saveOperator);
        //register
        if (operation == 1) {
            char *username;
            char *publicKey;
            char *privateKey;
            username = strtok(nullptr, " ");
            publicKey = strtok(nullptr, " ");
            privateKey = strtok(nullptr, " ");
            int registerCheck = registerUser(username, publicKey, privateKey);
            if (registerCheck == -1) {
                write(clientsList[CID].writingEnd, "User already exists. Registration failed. Please try again.", 59);
            } else if (registerCheck == 0) {
                write(clientsList[CID].writingEnd, "Registration Successful\n", 24);
            }
            //messaging
        } else if (operation == 2) {
            char out[1000];
            char *username;
            username = strtok(nullptr, " ");
            int bindCheck = bindIP(username, clientsList[CID].ip);
            if (bindCheck == 1) {
                int index = -1;
                for (int i = 0; i < noOfUsers; ++i) {
                    if (strcmp(username, KDC[i][0].c_str()) == 0) {
                        index = i;
                    }
                }
                std::string user(username);
                currentUser = user;
                std::string puK(KDC[index][1]);
                pubKey = puK;
                std::string prK(KDC[index][2]);
                privKey = prK;
                write(clientsList[CID].writingEnd, "Connection Successful.\nInput next command\n", 42);
            } else if (bindCheck == 0) {
                write(clientsList[CID].writingEnd, "User Doesn't Exist.\nInput next command\n", 39);
            }
            //connect user
        } else if (operation == 3) {
            char *token;
            char o[1000];
            char *username;
            username = strtok(nullptr, " ");
            data get;
            get = connectUser(username, currentUser);
            if (strcmp(get.A.c_str(), "x") != 0) {
                int count;
                DES decrypt;
                char check[1000];
                string keyPartE = get.A;
                string keyPartD = decrypt.runDES(keyPartE, privKey, true);
                string keyPartT = hex2str(keyPartD);
                string toSend = get.B;
                int cid = findCID(username);
                char out[1000];
                string msg;
                msg.append("request ").append(toSend);
                count = sprintf(out, "%s", msg.c_str());
                write(clientsList[cid].serverWritingEnd, out, count);//sending B's part
                count = read(clientsList[cid].serverReadingEnd, out, 1000);
                out[count] = '\0';
                if (strcmp(out, "done") == 0) {
                    write(clientsList[CID].writingEnd, "Connection Successful.\nInput next command\n", 42);
                } else {
                    write(clientsList[CID].writingEnd, "Connection Unsuccessful.\nInput next command\n", 44);
                }
            } else {
                write(clientsList[CID].writingEnd, "User Doesn't Exist.\nInput next command\n", 39);
            }
        } else if (operation == 7) {


        }//closing the clientReader handler on server exit
        else if (operation == 6) {
            int *status = nullptr;
            write(msgsock, "exit\0", 5);
            close(sock);
            close(msgsock);
            wait(status);
            exit(getpid());
        }
    }
}

int findCID(char *username) {
    string getIP;
    for (int i = 0; i < noOfConUsers; ++i) {
        if (strcmp(username, UIP[i][0].c_str()) == 0) {
            getIP = UIP[i][1];
        }
    }
    for (int i = 0; i <= currentClientIndex; ++i) {
        if (strcmp(getIP.c_str(), clientsList[i].ip.c_str()) == 0) {
            return clientsList[i].clientID;
        }
    }
    return -1;
}

data connectUser(char *username, string currentUser) {
    std::string user(username);
    int indexB;
    int indexA = 0;
    bool exist = false;
    for (int i = 0; i < noOfUsers; i++) {
        if (strcmp(user.c_str(), KDC[i][0].c_str()) == 0) {
            indexB = i;
            exist = true;
            break;
        }
    }
    if (exist) {
        for (int i = 0; i < noOfUsers; i++) {
            if (strcmp(currentUser.c_str(), KDC[i][0].c_str()) == 0) {
                indexA = i;
                break;
            }
        }

        long sessionKey = diffieHellman(DFHLG, DFHLP, strtol(KDC[indexA][1].c_str(), nullptr, 10),
                                        strtol(KDC[indexB][1].c_str(), nullptr, 10));
        string messageA = to_string(sessionKey).append(":").append(KDC[indexB][0]);
        string messageB = to_string(sessionKey).append(":").append(KDC[indexA][0]);
        string hexB = str2hex(messageB);
        string hexA = str2hex(messageA);
        DES encrypt;
        string packetB = encrypt.runDES(hexB, KDC[indexB][2], false);//done
        string packetA = encrypt.runDES(hexA, KDC[indexA][2], false);

        data send;
        send.A = packetA;
        send.B = packetB;
        return send;
    } else {
        data send;
        send.A = "x";
        send.B = "x";
        return send;
    }
}

int bindIP(char *username, string IP) {
    std::string user(username);
    bool exist = false;
    for (int i = 0; i < noOfUsers; i++) {
        if (strcmp(user.c_str(), KDC[i][0].c_str()) == 0) {
            exist = true;
            break;
        }
    }
    if (exist) {
        UIP[noOfConUsers][0] = user;
        UIP[noOfConUsers][1] = IP;
        noOfConUsers++;
        return 1;
    } else {
        return 0;
    }
}

long diffieHellman(long G, long P, long A, long B) {
    long BS = (long) pow(G, B) % P;
    long X = (long) pow(BS, A);
    long K = X % P;
    return K;
}

string str2hex(const string &s) {
    ostringstream ret;
    for (string::size_type i = 0; i < s.length(); ++i) {
        ret << std::hex << std::setfill('0') << std::setw(2) << (int) s[i];
    }
    return ret.str();
}

string hex2str(string hex) {
    int len = hex.length();
    std::string newString;
    for (int i = 0; i < len; i += 2) {
        string byte = hex.substr(i, 2);
        char chr = (char) (int) strtol(byte.c_str(), nullptr, 16);
        newString.push_back(chr);
    }
    return newString;
}

////string printing
//char out[100];
//int count = sprintf(out, "%s", key.c_str());
//write(STDOUT_FILENO, out, count);

//parsing
//std::stringstream test(finalMessageA);
//std::string segment;
//std::vector<std::string> seglist;
//while (std::getline(test, segment, ':')) {
//seglist.push_back(segment);
//}
//string decryptPA = encrypt.runDES(seglist.at(1), KDC[indexB][2], true);