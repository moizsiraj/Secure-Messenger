#include <iostream>
#include <regex>
#include <algorithm>
#include <bitset>
#include <unistd.h>

using namespace std;

class DES {

    int pc_1[56] = {57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4};


    int pc_2[48] = {14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32};

    int ip[64] = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    int selection[48] = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };


    int S1[4][16] = {
            {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7},
            {0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8},
            {4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0},
            {15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13}
    };

    int S2[4][16] = {
            {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10},
            {3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5},
            {0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15},
            {13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9}

    };
    int S3[4][16] = {
            {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8},
            {13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1},
            {13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7},
            {1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12}
    };
    int S4[4][16] = {
            {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15},
            {13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9},
            {10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4},
            {3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14}
    };
    int S5[4][16] = {
            {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9},
            {14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6},
            {4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14},
            {11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3}
    };
    int S6[4][16] = {
            {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11},
            {10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8},
            {9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6},
            {4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},
    };
    int S7[4][16] = {
            {4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1},
            {13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6},
            {1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2},
            {6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12}
    };
    int S8[4][16] = {
            {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7},
            {1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2},
            {7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8},
            {2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11},
    };

    int p[32] = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    int ip_inv[64] = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };


    int left_shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    string auxKeys[17][2];
    string keys[17];
    string auxMessage[17][2];

    //input 16 character hex key
    string permuteKey(string key) {
        string p_key;
        string bin = hexToBinary(key);
        for (int i = 0; i < 56; i++) {
            char binChar = bin.at(pc_1[i] - 1);
            p_key.push_back(binChar);
        }
        return p_key;
    }

    string hexToBinary(string hex) {
        string binary;
        long int i = 0;
        while (hex[i]) {
            switch (hex[i]) {
                case '0':
                    binary.append("0000");
                    break;
                case '1':
                    binary.append("0001");
                    break;
                case '2':
                    binary.append("0010");
                    break;
                case '3':
                    binary.append("0011");
                    break;
                case '4':
                    binary.append("0100");
                    break;
                case '5':
                    binary.append("0101");
                    break;
                case '6':
                    binary.append("0110");
                    break;
                case '7':
                    binary.append("0111");
                    break;
                case '8':
                    binary.append("1000");
                    break;
                case '9':
                    binary.append("1001");
                    break;
                case 'A':
                case 'a':
                    binary.append("1010");
                    break;
                case 'B':
                case 'b':
                    binary.append("1011");
                    break;
                case 'C':
                case 'c':
                    binary.append("1100");
                    break;
                case 'D':
                case 'd':
                    binary.append("1101");
                    break;
                case 'E':
                case 'e':
                    binary.append("1110");
                    break;
                case 'F':
                case 'f':
                    binary.append("1111");
                    break;

            }
            i++;
        }
        return binary;
    }

    string *splitKey(string key) {
        auto *str = new string[3];
        string C = key.substr(0, 28);
        string D = key.substr(28, 28);
        str[0] = C;
        str[1] = D;
        return str;
    }

    string leftShift(string key, int shift) {
        return key.substr(shift, (key.length() - shift)) + key.substr(0, shift);
    }

    void getAuxKeys(string key) {
        string *keySplit = splitKey(key);
        auxKeys[0][0] = keySplit[0];
        auxKeys[0][1] = keySplit[1];
        for (int i = 1; i <= 16; i++) {
            auxKeys[i][0] = leftShift(auxKeys[i - 1][0], left_shift[i - 1]);
            auxKeys[i][1] = leftShift(auxKeys[i - 1][1], left_shift[i - 1]);
        }
    }

    void getFinalKeys() {
        for (int i = 1; i < 17; i++) {//till auxkeys length
            string auxKey = auxKeys[i][0] + auxKeys[i][1];
            string key;
            for (int j = 0; j < 48; j++) {//pc2 size
                char binChar = auxKey.at(pc_2[j] - 1);
                key.push_back((binChar));
            }
            keys[i] = key;
        }
    }

    string initialPermute(string message) {
        string permutedMessage;
        string binary = hexToBinary(message);
        if (binary.length() < 64) {
            int padding = 64 - binary.length();
            string binMessage;
            for (int i = 0; i < padding; i++) {
                binMessage.append("0");
            }
            binMessage.append(binary);
            permutedMessage = binMessage;
        } else {
            permutedMessage = binary.substr(0, 64);
        }
        string initialMessage;
        for (int i = 0; i < 64; i++) {//size of  ip
            char binChar = permutedMessage.at(ip[i] - 1);
            initialMessage.push_back((binChar));
        }
        return initialMessage;
    }

    string *splitMessage(string message) {
        auto *msg = new string[3];
        string C = message.substr(0, 32);
        string D = message.substr(32, 32);
        msg[0] = C;
        msg[1] = D;
        return msg;
    }

    void getAuxMessages(string message) {
        string *messageSplit = splitMessage(message);
        auxMessage[0][0] = messageSplit[0];
        auxMessage[0][1] = messageSplit[1];
        for (int i = 1; i <= 16; i++) {
            auxMessage[i][0] = auxMessage[i - 1][1];
            getRight(i);//buggy
        }
    }

    void getAuxMessagesDecrypt(string message) {
        string *messageSplit = splitMessage(message);
        auxMessage[0][0] = messageSplit[0];
        auxMessage[0][1] = messageSplit[1];
        for (int i = 1, j = 16; i <= 16 && j >= 1; i++, j--) {
            auxMessage[i][0] = auxMessage[i - 1][1];
            getRightDecrypt(i, j);
        }
    }

    void getRightDecrypt(int index, int indexKey) {
        long Ln_1 = stol(auxMessage[index - 1][0], nullptr, 2);
        string function = funcDecrypt(index, indexKey);
        long functionToBin = stol(function, nullptr, 2);
        long valueBin = Ln_1 ^functionToBin;
        std::string valueStr = std::bitset<32>(valueBin).to_string();
        auxMessage[index][1] = valueStr;
    }

    string funcDecrypt(int index, int indexKey) {
        string returnstring;
        string e_Rn_1;
        for (int i = 0; i < 48; i++) {
            char binChar = auxMessage[index - 1][1].at(selection[i] - 1);
            e_Rn_1.push_back((binChar));
        }
        long dec_e_Rn_1 = stol(e_Rn_1, nullptr, 2);
        long dec_key = stol(keys[indexKey], nullptr, 2);
        long Xor = dec_e_Rn_1 ^dec_key;
        std::string binary = std::bitset<48>(Xor).to_string();
        string binStore[8];
        int start = 0;
        int end = 6;
        for (int i = 0; i < 8; i++) {
            binStore[i] = binary.substr(start, end);
            start = start + 6;
        }
        for (int i = 0; i < 8; i++) {
            string rowStr;
            string tempStr = binStore[i];
            rowStr.push_back((tempStr.at(0)));
            rowStr.push_back(tempStr.at(5));
            int row = stoi(rowStr, nullptr, 2);
            string columnStr = tempStr.substr(1, 4);
            int column = stoi(columnStr, nullptr, 2);
            int value;
            string binValue;
            switch (i) {
                case 0:
                    value = S1[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 1:
                    value = S2[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 2:
                    value = S3[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 3:
                    value = S4[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 4:
                    value = S5[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 5:
                    value = S6[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 6:
                    value = S7[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 7:
                    value = S8[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
            }
        }
        string pTableInput = returnstring;
        string pTableOutput;
        for (int i = 0; i < 32; i++) {
            pTableOutput.push_back((pTableInput.at(p[i] - 1)));
        }
        return pTableOutput;
    }

    string getEncodedMessage() {
        string RL;
        RL.append(auxMessage[16][1]).append(auxMessage[16][0]);
        string finalStr;
        for (int j = 0; j < 64; j++) {
            char binChar = RL.at(ip_inv[j] - 1);
            finalStr.push_back((binChar));
        }
        stringstream hexStr;
        bitset<64> set(finalStr);
        hexStr << hex << set.to_ulong() << endl;
        return hexStr.str();
    }

    void getRight(int index) {
        long Ln_1 = stol(auxMessage[index - 1][0], nullptr, 2);
        string function = func(index);
        long functionToBin = stol(function, nullptr, 2);
        long valueBin = Ln_1 ^functionToBin;
        std::string valueStr = std::bitset<32>(valueBin).to_string();
        auxMessage[index][1] = valueStr;
    }

    string func(int index) {
        string returnstring;
        string e_Rn_1;
        for (int i = 0; i < 48; i++) {
            char binChar = auxMessage[index - 1][1].at(selection[i] - 1);
            e_Rn_1.push_back((binChar));
        }
        long dec_e_Rn_1 = stol(e_Rn_1, nullptr, 2);
        long dec_key = stol(keys[index], nullptr, 2);
        long Xor = dec_e_Rn_1 ^dec_key;
        std::string binary = std::bitset<48>(Xor).to_string();
        string binStore[8];
        int start = 0;
        int end = 6;
        for (int i = 0; i < 8; i++) {
            binStore[i] = binary.substr(start, end);
            start = start + 6;
        }
        for (int i = 0; i < 8; i++) {
            string rowStr;
            string tempStr = binStore[i];
            rowStr.push_back((tempStr.at(0)));
            rowStr.push_back(tempStr.at(5));
            int row = stoi(rowStr, nullptr, 2);
            string columnStr = tempStr.substr(1, 4);
            int column = stoi(columnStr, nullptr, 2);
            int value;
            string binValue;
            switch (i) {
                case 0:
                    value = S1[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 1:
                    value = S2[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 2:
                    value = S3[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 3:
                    value = S4[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 4:
                    value = S5[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 5:
                    value = S6[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 6:
                    value = S7[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
                case 7:
                    value = S8[row][column];
                    binValue = std::bitset<4>(value).to_string();
                    returnstring.append(binValue);
                    break;
            }
        }
        string pTableInput = returnstring;
        string pTableOutput;
        for (int i = 0; i < 32; i++) {
            pTableOutput.push_back((pTableInput.at(p[i] - 1)));
        }
        return pTableOutput;
    }

public:
    string runDES(string message, string key, bool decrypt) {
        string permutedKey = permuteKey(key);
        getAuxKeys(permutedKey);
        getFinalKeys();
        string permutedMessage = initialPermute(message);
        if (decrypt) {
            getAuxMessagesDecrypt(permutedMessage);
        } else {
            getAuxMessages(permutedMessage);
        }
        string encodedMessage = getEncodedMessage();
        return encodedMessage;

    }
};

int main() {
    DES d;
    string encrypt = d.runDES("0123456789ABCDEF", "133457799BBCDFF1", false);
    string decrypt = d.runDES(encrypt, "133457799BBCDFF1", true);
    printf("%s", encrypt.c_str());
    printf("%s", decrypt.c_str());
}
