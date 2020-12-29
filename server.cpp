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

using namespace std;

int setOperation(char *operationText);

void signal_handler_CONH(int signo);

void signal_handler_CONHEXIT(int signo);

std::string getTime();

std::string elapsedTime(std::string startTime, std::string endTime);

int removeColon(std::string s);

void createSock();

long diffieHellman(long G, long P, long A, long B);

int registerUser(char *username, char *publicKey);

int bindUserIP(char *username);

int setOperationInput(char *operationText);

void updateClientList(int pid);

void *clientCommandProcessor(void *ptr);

void *userInput2Server(void *ptr);

void *ServerInput2Client(void *ptr);

void *clientInput2Server(void *clientID);

int bindIP(char *username, string IP);

int connectUser(char *username, string currentUser);

struct clients {
    int clientID = -1;
    int readingEnd = -1;
    int writingEnd = -1;
    int pid;
    int msgsock;
    std::string ip;
    std::string status;
};

string KDC[50][2];
string UIP[50][2];
string connections[25][2];
int noOfUsers = 0;
int noOfConUsers = 0;
int write2CH[2];
int write2CON[2];
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
    inputID = pthread_create(&inputThread, nullptr, userInput2Server, (void *) nullptr);
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
            clientsList[currentClientIndex].clientID = currentClientIndex + 1;
            clientsList[currentClientIndex].readingEnd = write2CON[0];
            clientsList[currentClientIndex].writingEnd = write2CH[1];
            clientsList[currentClientIndex].ip = inet_ntoa(addr.sin_addr);
            clientsList[currentClientIndex].msgsock = msgsock;
            clientsList[currentClientIndex].status = "Connected";
            ip = inet_ntoa(addr.sin_addr);

            int *arg = static_cast<int *>(malloc(sizeof(*arg)));
            if (arg == NULL) {
                fprintf(stderr, "Couldn't allocate memory for thread arg.\n");
                exit(EXIT_FAILURE);
            }

            *arg = currentClientIndex;
            pthread_create(&clientInputThread[currentClientIndex], nullptr, clientInput2Server, arg);

            clientHandlerPID = fork();
            if (clientHandlerPID == 0) {
                pthread_t clientHThread;
                pthread_create(&clientHThread, nullptr, clientCommandProcessor, (void *) nullptr);
                pthread_join(clientHThread, nullptr);
            }
        } else {
            write(STDOUT_FILENO, "Connection fail\n", 16);
        }
        clientsList[currentClientIndex].pid = clientHandlerPID;
    }
    pthread_join(inputThread, nullptr);
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


//operation setter for clientCommandProcessor handler
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

//for handling clientCommandProcessor handler exits
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

int registerUser(char *username, char *publicKey) {
    std::string user(username);
    write(STDOUT_FILENO, "RU1 \n", 5);
    char out[10];
    for (int i = 0; i < noOfUsers; i++) {
        int count = sprintf(out, "%s", user.c_str());
        write(STDOUT_FILENO, out, count);
        count = sprintf(out, "%s", KDC[i][0].c_str());
        write(STDOUT_FILENO, out, count);
        write(STDOUT_FILENO, "RU3 \n", 5);
        if (strcmp(user.c_str(), KDC[i][0].c_str()) == 0 || strcmp(publicKey, KDC[i][1].c_str()) == 0) {
            return -1;
        }
    }
    write(STDOUT_FILENO, "RU2 \n", 5);

    char o[10];
    int count = sprintf(o, "%s\n", to_string(noOfUsers).c_str());
    write(STDOUT_FILENO, o, count);
    std::string key(publicKey);

    KDC[noOfUsers][0] = user;
    KDC[noOfUsers][1] = key;
    noOfUsers++;
    return 0;
}

//clientCommandProcessor handler thread
void *clientCommandProcessor(void *ptr) {
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
            username = strtok(nullptr, " ");
            publicKey = strtok(nullptr, " ");
            if (username == nullptr || publicKey == nullptr) {
                write(msgsock, "Invalid Command. Input next command\n", 36);
            } else {
                string registerCommand = "register ";
                registerCommand.append(username).append(" ").append(publicKey);
                int count = sprintf(outputText, "%s", registerCommand.c_str());

                write(STDOUT_FILENO, outputText, count);
                write(STDOUT_FILENO, "CCP 1\n", 6);
                write(write2CON[1], outputText, count);
                write(STDOUT_FILENO, "CCP 2\n", 6);
                count = read(write2CH[0], outputText, 1000);
                write(STDOUT_FILENO, "CCP 3\n", 6);
                write(msgsock, outputText, count);
                write(STDOUT_FILENO, "CCP 4\n", 6);
            }
        }

            //bindIP
        else if (operation == 2) {
            char *username;
            username = strtok(nullptr, " ");
            if (username == nullptr) {
                write(msgsock, "Invalid Command. Input next command\n", 36);
            } else {
                string registerCommand = "messaging ";
                registerCommand.append(username);
                int count = sprintf(outputText, "%s", registerCommand.c_str());
                write(STDOUT_FILENO, outputText, count);
                write(STDOUT_FILENO, "CCP 1\n", 6);
                write(write2CON[1], outputText, count);
                write(STDOUT_FILENO, "CCP 2\n", 6);
                count = read(write2CH[0], outputText, 1000);
                write(STDOUT_FILENO, "CCP 3\n", 6);
                write(msgsock, outputText, count);
                write(STDOUT_FILENO, "CCP 4\n", 6);
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
                write(STDOUT_FILENO, outputText, count);
                write(STDOUT_FILENO, "CCP 1\n", 6);
                write(write2CON[1], outputText, count);
                write(STDOUT_FILENO, "CCP 2\n", 6);
                count = read(write2CH[0], outputText, 1000);
                write(STDOUT_FILENO, "CCP 3\n", 6);
                write(msgsock, outputText, count);
                write(STDOUT_FILENO, "CCP 4\n", 6);
            }
        }
    }
    return nullptr;
}

//Input Thread
void *userInput2Server(void *ptr) {
    char input[1000];
    char saveOperator[10];
    int operation = -1;
    char *token;
    int checkRead;

    while (true) {
        write(STDIN_FILENO, "Input next command\n", 19);
        checkRead = read(STDIN_FILENO, input, 1000);//B1
        input[checkRead - 1] = '\0';//adding null at the end

        if (checkRead == 1) {//empty input
            write(STDIN_FILENO, "No command input\n", 17);
        } else {
            //getting the first token to set operation
            token = strtok(input, " ");
            sscanf(token, "%s", saveOperator);
            operation = setOperationInput(saveOperator);

            //Invalid Command
            if (operation == -1) {
                write(STDOUT_FILENO, "Invalid Command\n", 16);
            }

                //print to single clientCommandProcessor
            else if (operation == 3) {
                if (activeClients == 0) {
                    write(STDOUT_FILENO, "No Client Connected\n", 20);
                } else {
                    char output[500];
                    char saveIP[100];
                    std::string print;
                    char buf[sizeof(struct in6_addr)];
                    int clientIndex;
                    int ipCheck = -1;
                    token = strtok(nullptr, " ");
                    if (token == nullptr) {
                        write(STDOUT_FILENO, "No IP Provided\n", 15);
                    } else {
                        ipCheck = inet_pton(AF_INET, token, buf);
                        if (ipCheck <= 0) {
                            write(STDOUT_FILENO, "Invalid IP\n", 20);
                        } else {
                            for (int i = 0; i <= currentClientIndex; ++i) {
                                sscanf(clientsList[i].ip.c_str(), "%s", saveIP);
                                if (strcmp(saveIP, token) == 0) {
                                    clientIndex = i;
                                }
                            }
                            if (ipCheck != -1) {
                                print.append("print Message from server: ");
                                token = strtok(nullptr, " ");
                                while (token != nullptr) {
                                    print.append(token).append(" ");
                                    token = strtok(nullptr, " ");
                                }
                                print.append("\n").append("Input next command\n");
                                int count = sprintf(output, "%s", print.c_str());
                                if (strcmp(clientsList[clientIndex].status.c_str(), "Connected") == 0) {
                                    int checkWrite = write(clientsList[clientIndex].writingEnd, output, count);
                                } else {
                                    write(STDOUT_FILENO, "Client not connected\n", 21);
                                }
                            } else {
                                write(STDOUT_FILENO, "IP does not exist\n", 18);
                            }
                        }
                    }
                }
            }

                //print clientCommandProcessor list
            else if (operation == 4) {
                char output[1000];
                if (currentClientIndex == -1) {
                    write(STDOUT_FILENO, "No Client Connected\n", 20);
                } else {
                    std::string print;
                    print.append("Client ID\tPID\t\tIP\t\tStatus\n");
                    for (int i = 0; i <= currentClientIndex; ++i) {
                        print.append(to_string(clientsList[i].clientID)).append("\t\t");
                        print.append(to_string(clientsList[i].pid)).append("\t\t");
                        print.append(clientsList[i].ip).append("\t");
                        print.append(clientsList[i].status).append("\n");
                    }
                    int checkPrint = sprintf(output, "%s", print.c_str());
                    write(STDOUT_FILENO, output, checkPrint);
                }
            }

                //exit
            else if (operation == 5) {
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
    }
}

//update clientCommandProcessor list on disconnects
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


void *clientInput2Server(void *clientID) {
    char input[1000];
    char output[1000];
    char saveOperator[10];
    int operation = -1;
    char *token;
    string currentUser;
    int checkRead;

    while (true) {
        int CID = *((int *) clientID);
        write(STDOUT_FILENO, "CIS 1\n", 6);
        checkRead = read(clientsList[CID].readingEnd, input, 1000);//B2//B4
        write(STDOUT_FILENO, input, checkRead);
        write(STDOUT_FILENO, "CIS 2\n", 6);
        input[checkRead] = '\0';//adding null at the end
        write(STDOUT_FILENO, "CIS 3\n", 6);
        token = strtok(input, " ");
        sscanf(token, "%s", saveOperator);
        operation = setOperationInput(saveOperator);
        write(STDOUT_FILENO, "CIS 4\n", 6);
        //register
        if (operation == 1) {
            char *username;
            char *publicKey;
            username = strtok(nullptr, " ");
            publicKey = strtok(nullptr, " ");
            write(STDOUT_FILENO, "CIS 5\n", 6);
            int registerCheck = registerUser(username, publicKey);
            write(STDOUT_FILENO, "CIS 6\n", 6);
            if (registerCheck == -1) {
                write(STDOUT_FILENO, "CIS 7\n", 6);
                write(clientsList[CID].writingEnd, "User already exists. Registration failed. Please try again.", 59);
                write(STDOUT_FILENO, "CIS 8\n", 6);
            } else if (registerCheck == 0) {
                write(STDOUT_FILENO, "CIS 9\n", 6);
                write(clientsList[CID].writingEnd, "Registration Successful\n", 24);
                write(STDOUT_FILENO, "CIS 10\n", 6);
            }
        } else if (operation == 2) {
            char *username;
            username = strtok(nullptr, " ");
            write(STDOUT_FILENO, "CIS 5\n", 6);
            int bindCheck = bindIP(username, clientsList[CID].ip);
            write(STDOUT_FILENO, "CIS 6\n", 6);
            if (bindCheck == 1) {
                std::string user(username);
                currentUser = user;
                write(STDOUT_FILENO, "CIS 7\n", 6);
                write(clientsList[CID].writingEnd, "Connection Successful.\nInput next command\n", 42);
                write(STDOUT_FILENO, "CIS 8\n", 6);
            } else if (bindCheck == 0) {
                write(STDOUT_FILENO, "CIS 9\n", 6);
                write(clientsList[CID].writingEnd, "User Doesn't Exist.\nInput next command\n", 39);
                write(STDOUT_FILENO, "CIS 10\n", 6);
            }
        } else if (operation == 3) {
            char *username;
            username = strtok(nullptr, " ");
            write(STDOUT_FILENO, "CIS 5\n", 6);
            int connectCheck = connectUser(username, currentUser);
            write(STDOUT_FILENO, "CIS 6\n", 6);
            if (connectCheck == 1) {
                write(STDOUT_FILENO, "CIS 7\n", 6);
                write(clientsList[CID].writingEnd, "Connection Successful.\nInput next command\n", 42);
                write(STDOUT_FILENO, "CIS 8\n", 6);
            } else if (connectCheck == 0) {
                write(STDOUT_FILENO, "CIS 9\n", 6);
                write(clientsList[CID].writingEnd, "User Doesn't Exist.\nInput next command\n", 39);
                write(STDOUT_FILENO, "CIS 10\n", 6);
            }
        }//closing the clientCommandProcessor handler on server exit
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

int connectUser(char *username, string currentUser) {
    std::string user(username);
    char out[10];
    int indexB;
    int indexA = 0;
    write(STDOUT_FILENO, "RU1 \n", 5);
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
        char o[10];
        long sessionKey = diffieHellman(DFHLG, DFHLP, atoi(KDC[indexA][1].c_str()), atoi(KDC[indexB][1].c_str()));

        return 1;
    } else {
        return 0;
    }
}

int bindIP(char *username, string IP) {
    std::string user(username);
    char out[10];
    write(STDOUT_FILENO, "RU1 \n", 5);

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
    int count = sprintf(o, "\n%ld G\n", G);
    write(STDOUT_FILENO, o, count);
    count = sprintf(o, "\n%ld P\n", P);
    write(STDOUT_FILENO, o, count);
    count = sprintf(o, "\n%ld A\n", A);
    write(STDOUT_FILENO, o, count);
    count = sprintf(o, "\n%ld B\n", B);
    write(STDOUT_FILENO, o, count);
    long AS = (long) pow(G, A) % P;
    count = sprintf(o, "\n%ld AS\n", AS);
    write(STDOUT_FILENO, o, count);
    long BS = (long) pow(G, B) % P;
    count = sprintf(o, "\n%ld BS\n", BS);
    write(STDOUT_FILENO, o, count);
    long X = (long) pow(BS, A);
    count = sprintf(o, "\n%ld X\n", X);
    write(STDOUT_FILENO, o, count);
    long K = X % P;
    count = sprintf(o, "\n%ld K\n", K);
    write(STDOUT_FILENO, o, count);
    long K;
}
