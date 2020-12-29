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

using namespace std;

int setOperation(char *operationText);

void signal_handler_CH(int signo);

void signal_handler_CONH(int signo);

void signal_handler_CONHEXIT(int signo);

std::string getTime();

std::string elapsedTime(std::string startTime, std::string endTime);

int removeColon(std::string s);

void createSock();

int registerUser(char *username, char *publicKey);

int killAllProcess();

int bindUserIP(char *username);

int setOperationInput(char *operationText);

void updateClientList(int pid);

void *client(void *ptr);

void *connection(void *ptr);

void *inputHandler(void *ptr);

struct clients {
    int clientID = -1;
    int readingEnd = -1;
    int writingEnd = -1;
    int pid;
    int msgsock;
    std::string ip;
    std::string status;
};

std::string processList[50][6];
std::string KDC[50][2];
int noOfUsers = -1;
int currentListIndex = 0;
int activeProcesses = 0;
int write2CH[2];
int write2CON[2];
int currentClientIndex = -1;
int activeClients = 0;
int sock;
int msgsock;
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
    int inputID;

    createSock();
    listen(sock, 5);
    write(STDOUT_FILENO, "Accepting Connections Now\n", 26);
    inputID = pthread_create(&inputThread, nullptr, connection, (void *) nullptr);
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

            clientHandlerPID = fork();

            if (clientHandlerPID == 0) {
                pthread_t clientHThread;
                pthread_t inputHThread;
                int clientHID;
                int inputHID;

                clientHID = pthread_create(&clientHThread, nullptr, client, (void *) nullptr);
                inputHID = pthread_create(&inputHThread, nullptr, inputHandler, (void *) nullptr);

                pthread_join(clientHThread, nullptr);
                pthread_join(inputHThread, nullptr);
            }
        } else {
            write(STDOUT_FILENO, "Connection fail\n", 16);
        }
        clientsList[currentClientIndex].pid = clientHandlerPID;
    }
    pthread_join(inputThread, nullptr);
    return 0;
}

#pragma clang diagnostic pop

//creating socket
void createSock() {
    char output[500];
    struct sockaddr_in server;//struct to store socket info
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

//run processes on client's command
int bindUserIP(char *username) {

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


//operation setter for client handler
int setOperation(char *operationText) {
    int operation;
    if (strcmp(operationText, "print") == 0) {
        operation = 8;
    } else if (strcmp(operationText, "exit") == 0) {
        operation = 0;
    } else {
        operation = -1;
    }
    return operation;
}

//operation setter for input handler and input thread
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
    } else {
        operation = -1;
    }
    return operation;
}

//for handling client handler exits
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
    for (int i = 0; i < noOfUsers; ++i) {
        if (strcmp(username, KDC[i][0].c_str()) != 0 || strcmp(publicKey, KDC[i][1].c_str()) != 0) {
            return -1;
        }
    }
    noOfUsers++;
    KDC[noOfUsers][0] = username;
    KDC[noOfUsers][1] = publicKey;
    return 0;
}

//client handler thread
void *client(void *ptr) {
    char inputText[500];
    char outputText[500];
    bool continueInput = true;
    char saveOperator[10];
    int operation = -1;
    char *token;


    if (signal(SIGCHLD, signal_handler_CH) == SIG_ERR) {
        write(STDOUT_FILENO, "sig error", 9);
    }

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
            killAllProcess();
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
                int registerCheck = registerUser(username, publicKey);
                if (registerCheck == -1) {
                    write(msgsock, "User already exists. Registration failed. Please try again.", 59);
                } else if (registerCheck == 0) {
                    write(msgsock, "Registration Successful\n", 24);
                }
            }
        }

            //run
        else if (operation == 2) {
            char *username;
            username = strtok(nullptr, " ");
            if (username != nullptr) {
                int checkBinding = bindUserIP(username);
            } else {
                write(msgsock, "Input next command\n", 19);
            }
        }

            //list
        else if (operation == 7) {
            char output[500];
            std::string print;
            if (currentListIndex == 0) {
                write(msgsock, "No processes\nInput next command\n", 32);
            } else {
                print.append("Process PID\tProcess Name\tStatus\t\tStart Time\t\tEnd Time\t\tElapsed Time\n");
                for (int i = 0; i < currentListIndex; ++i) {
                    for (int j = 0; j < 6; ++j) {
                        print.append(processList[i][j]).append("\t\t");
                    }
                    print.append("\n");
                }
                int read = sprintf(output, "%s", print.c_str());
                sprintf(&output[read - 1], "%s", "\nInput next command\n");
                int count = read + 20;
                write(msgsock, output, count);
            }
        }

            //print
        else if (operation == 8) {
            token = strtok(nullptr, " ");
            char messageBuffer[500];
            std::string print;
            print.append("Message from ").append(ip).append(": ");
            while (token != nullptr) {
                print.append(token).append(" ");
                token = strtok(nullptr, " ");
            }
            print.append("\n").append("Input next command\n");
            int read = sprintf(messageBuffer, "%s", print.c_str());
            write(STDOUT_FILENO, messageBuffer, read);
            write(msgsock, "Input next command\n", 19);
        }
    }
}

//Input Thread
void *connection(void *ptr) {
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

                //print to single client
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

                //print client list
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

//update client list on disconnects
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

//Input handler thread
void *inputHandler(void *ptr) {
    char input[1000];
    char output[1000];
    char saveOperator[10];
    int operation = -1;
    char *token;
    int checkRead;

    while (true) {
        checkRead = read(write2CH[0], input, 1000);//B2//B4
        input[checkRead - 1] = '\0';//adding null at the end

        token = strtok(input, " ");
        sscanf(token, "%s", saveOperator);
        operation = setOperationInput(saveOperator);


        //printing to client
        if (operation == 1 || operation == 3) {
            std::string print;
            token = strtok(nullptr, " ");
            while (token != nullptr) {
                print.append(token).append(" ");
                token = strtok(nullptr, " ");
            }
            print.append("\n");
            int count = sprintf(output, "%s", print.c_str());
            write(msgsock, output, count);
        }

            //sending list to input handler
        else if (operation == 2) {
            std::string print;
            if (currentListIndex == 0) {
                write(write2CON[1], "No processes\n", 13);
            } else {
                print.append("Process PID\tProcess Name\tStatus\t\tStart Time\t\tEnd Time\t\tElapsed Time\n");
                for (int i = 0; i < currentListIndex; ++i) {
                    for (int j = 0; j < 6; ++j) {
                        print.append(processList[i][j]).append("\t\t");
                    }
                    print.append("\n");
                }
                int count = sprintf(output, "%s", print.c_str());
                write(write2CON[1], output, count);
            }
        }

            //closing the client handler on server exit
        else if (operation == 5) {
            int *status = nullptr;
            write(msgsock, "exit\0", 5);
            close(sock);
            close(msgsock);
            killAllProcess();
            wait(status);
            exit(getpid());
        }
    }
}