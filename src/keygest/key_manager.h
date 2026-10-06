// keygest/key_manager.h - 0.1 alpha
// Lógica pura del gestor de claves. SIN menús, SIN cout, SIN KeySecureInput.
// Los menús viven en ui/key_manager_ui.h

#ifndef KEYGEST_KEY_MANAGER_H
#define KEYGEST_KEY_MANAGER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <memory>
#include <functional>
#include <sys/stat.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>
#include <thread>
#include <fcntl.h>

#include <botan/pwdhash.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <botan/hash.h>

using namespace std;

// ***********************************************
// CLASE  MLOCK PROTECION DE MEMORIA //

class MemoryLC {
private:
    void* ptr;
    size_t size;
    bool locked;

public:
    MemoryLC() : ptr(nullptr), size(0), locked(false) {}
    
    explicit MemoryLC(void* memory_ptr, size_t memory_size) 
        : ptr(memory_ptr), size(memory_size), locked(false) {
        if (ptr && size > 0) {
            if (mlock(ptr, size) == 0) {
                locked = true;
            }
        }
    }
    
    MemoryLC(const MemoryLC&) = delete;
    MemoryLC& operator=(const MemoryLC&) = delete;
    
    MemoryLC(MemoryLC&& other) noexcept 
        : ptr(other.ptr), size(other.size), locked(other.locked) {
        other.ptr = nullptr;
        other.size = 0;
        other.locked = false;
    }
    
    MemoryLC& operator=(MemoryLC&& other) noexcept {
        if (this != &other) {
            unlock();
            ptr = other.ptr;
            size = other.size;
            locked = other.locked;
            other.ptr = nullptr;
            other.size = 0;
            other.locked = false;
        }
        return *this;
    }
    
    void unlock() {
        if (locked && ptr && size > 0) {
            munlock(ptr, size);
            locked = false;
        }
    }
    
    ~MemoryLC() {
        unlock();
    }
    
    bool isLocked() const { return locked; }
};

// ************************************
// COMPARACION //
inline bool secure_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

// *************************************************
// CRYPTO ARGON2ID //

class KeyCryptoUtils {
public:
    static constexpr int ARGON2_MEMORY_KB = 65536;
    static constexpr int ARGON2_ITERATIONS = 3;
    static constexpr int ARGON2_PARALLELISM = 1;
    static constexpr int SALT_SIZE = 32;
    static constexpr int KEY_SIZE = 32;
    static constexpr int IV_SIZE = 12;

    static Botan::secure_vector<uint8_t> generateSalt() {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> salt(SALT_SIZE);
            rng.randomize(salt.data(), salt.size());
            return salt;
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    static Botan::secure_vector<uint8_t> generateRandomBytes(int bytes = 32) {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> key(bytes);
            rng.randomize(key.data(), key.size());
            return key;
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    static string generateRandomHex(int bytes = 32) {
        try {
            Botan::AutoSeeded_RNG rng;
            vector<uint8_t> key(bytes);
            rng.randomize(key.data(), key.size());
            return Botan::hex_encode(key);
        } catch(...) {
            return "";
        }
    }

    static Botan::secure_vector<uint8_t> deriveKey(
        const Botan::secure_vector<uint8_t>& password,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_len = KEY_SIZE) {
        
        try {
            auto argon2_family = Botan::PasswordHashFamily::create("Argon2id");
            if (!argon2_family) {
                return Botan::secure_vector<uint8_t>();
            }
            
            auto argon2 = argon2_family->from_params(
                ARGON2_MEMORY_KB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM
            );
            
            if (!argon2) {
                return Botan::secure_vector<uint8_t>();
            }
            
            Botan::secure_vector<uint8_t> key(key_len);
            argon2->derive_key(key.data(), key.size(),
                              reinterpret_cast<const char*>(password.data()), password.size(),
                              salt.data(), salt.size());
            
            return key;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    static Botan::secure_vector<uint8_t> encryptData(
        const Botan::secure_vector<uint8_t>& plaintext,
        const Botan::secure_vector<uint8_t>& password) {
        
        try {
            Botan::AutoSeeded_RNG rng;
            
            Botan::secure_vector<uint8_t> salt = generateSalt();
            if (salt.empty()) return Botan::secure_vector<uint8_t>();
            
            Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
            if (key.empty()) return Botan::secure_vector<uint8_t>();
            
            Botan::secure_vector<uint8_t> iv(IV_SIZE);
            rng.randomize(iv.data(), iv.size());
            
            unique_ptr<Botan::Cipher_Mode> cipher = 
                Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
            
            if (!cipher) return Botan::secure_vector<uint8_t>();
            
            cipher->set_key(key);
            cipher->start(iv.data(), iv.size());
            
            Botan::secure_vector<uint8_t> ct = plaintext;
            cipher->finish(ct);
            
            Botan::secure_vector<uint8_t> result;
            result.reserve(salt.size() + iv.size() + ct.size());
            result.insert(result.end(), salt.begin(), salt.end());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), ct.begin(), ct.end());
            
            return result;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static Botan::secure_vector<uint8_t> decryptData(
        const Botan::secure_vector<uint8_t>& encrypted,
        const Botan::secure_vector<uint8_t>& password) {
        
        try {
            if (encrypted.size() < SALT_SIZE + IV_SIZE) {
                return Botan::secure_vector<uint8_t>();
            }
            
            Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
            Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, 
                                             encrypted.begin() + SALT_SIZE + IV_SIZE);
            Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());
            
            Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
            if (key.empty()) return Botan::secure_vector<uint8_t>();
            
            unique_ptr<Botan::Cipher_Mode> cipher = 
                Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
            
            if (!cipher) return Botan::secure_vector<uint8_t>();
            
            cipher->set_key(key);
            cipher->start(iv.data(), iv.size());
            
            Botan::secure_vector<uint8_t> pt = ct;
            cipher->finish(pt);
            
            return pt;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static bool isArgon2Available() {
        try {
            auto family = Botan::PasswordHashFamily::create("Argon2id");
            return family != nullptr;
        } catch(...) {
            return false;
        }
    }
};

// *****************************************************
// Estructura para almacenar información de claves //

struct KeyInfo {
    string key_name;
    Botan::secure_vector<uint8_t> key_value;  
    string key_type;
    string key_usage;
    time_t created_at;
    time_t last_used;
    bool is_active;
    int strength;
    Botan::secure_vector<uint8_t> access_code;
    bool requires_access;
    
    mutable unique_ptr<MemoryLC> memory_locker;
    
    KeyInfo() : created_at(0), last_used(0), is_active(false), strength(256), requires_access(true) {
        key_type = "AES-256";
    }
    
    KeyInfo(const KeyInfo& other) 
        : key_name(other.key_name), 
          key_value(other.key_value), 
          key_type(other.key_type), 
          key_usage(other.key_usage),
          created_at(other.created_at), 
          last_used(other.last_used), 
          is_active(other.is_active), 
          strength(other.strength),
          access_code(other.access_code), 
          requires_access(other.requires_access),
          memory_locker(nullptr) {}
    
    KeyInfo(KeyInfo&& other) noexcept
        : key_name(std::move(other.key_name)),
          key_value(std::move(other.key_value)),
          key_type(std::move(other.key_type)),
          key_usage(std::move(other.key_usage)),
          created_at(other.created_at),
          last_used(other.last_used),
          is_active(other.is_active),
          strength(other.strength),
          access_code(std::move(other.access_code)),
          requires_access(other.requires_access),
          memory_locker(std::move(other.memory_locker)) {
        other.created_at = 0;
        other.last_used = 0;
        other.is_active = false;
        other.strength = 256;
        other.requires_access = true;
    }
    
    KeyInfo& operator=(const KeyInfo& other) {
        if (this != &other) {
            key_name = other.key_name;
            key_value = other.key_value;
            key_type = other.key_type;
            key_usage = other.key_usage;
            created_at = other.created_at;
            last_used = other.last_used;
            is_active = other.is_active;
            strength = other.strength;
            access_code = other.access_code;
            requires_access = other.requires_access;
            memory_locker.reset();
        }
        return *this;
    }
    
    KeyInfo& operator=(KeyInfo&& other) noexcept {
        if (this != &other) {
            key_name = std::move(other.key_name);
            key_value = std::move(other.key_value);
            key_type = std::move(other.key_type);
            key_usage = std::move(other.key_usage);
            created_at = other.created_at;
            last_used = other.last_used;
            is_active = other.is_active;
            strength = other.strength;
            access_code = std::move(other.access_code);
            requires_access = other.requires_access;
            memory_locker = std::move(other.memory_locker);
            
            other.created_at = 0;
            other.last_used = 0;
            other.is_active = false;
            other.strength = 256;
            other.requires_access = true;
        }
        return *this;
    }
    
    void lockMemory() const {
        if (!access_code.empty() && !memory_locker) {
            void* ptr = const_cast<uint8_t*>(access_code.data());
            memory_locker = make_unique<MemoryLC>(ptr, access_code.size());
        }
    }
    
    void unlockMemory() const {
        memory_locker.reset();
    }
    
    ~KeyInfo() {
        access_code.clear();
        key_value.clear();
    }
    
    string serialize() const {
        stringstream ss;
        ss << key_name << "\n";
        ss << Botan::hex_encode(key_value) << "\n"; 
        ss << key_type << "\n";
        ss << key_usage << "\n";
        ss << created_at << "\n";
        ss << last_used << "\n";
        ss << (is_active ? "1" : "0") << "\n";
        ss << strength << "\n";
        
        string accessB64 = Botan::base64_encode(access_code);
        ss << accessB64 << "\n";
        
        ss << (requires_access ? "1" : "0");
        return ss.str();
    }
    
    bool deserialize(const string& data) {
        try {
            stringstream ss(data);
            string line;
            
            if (!getline(ss, key_name)) return false;
            if (!getline(ss, line)) return false;
            
            auto decoded_key = Botan::hex_decode(line);
            key_value.assign(decoded_key.begin(), decoded_key.end());
            
            if (!getline(ss, key_type)) return false;
            if (!getline(ss, key_usage)) return false;
            
            if (!getline(ss, line)) return false;
            created_at = stol(line);
            
            if (!getline(ss, line)) return false;
            last_used = stol(line);
            
            if (!getline(ss, line)) return false;
            is_active = (line == "1");
            
            if (!getline(ss, line)) return false;
            strength = stoi(line);
            
            if (!getline(ss, line)) return false;
            access_code = Botan::base64_decode(line);
            
            if (!getline(ss, line)) return false;
            requires_access = (line == "1");
            
            return true;
        } catch(...) {
            return false;
        }
    }
};

// *************************************************************
// CLASE PRINCIPAL DEL GESTOR DE CLAVES (sin UI) //

class KeyManager {
public:
    using LogCallback = std::function<void(const std::string& msg)>;
    
private:
    string username;
    Botan::secure_vector<uint8_t> userPasswordSecure;
    map<string, KeyInfo> keys;
    bool passwordVerified;
    
    unique_ptr<MemoryLC> password_locker;
    LogCallback log_cb_;
    
    void log(const string& msg) { if (log_cb_) log_cb_(msg); }
    
    string getKeysFilePath() const {
        string data_dir_users;
        const char* xdg_data = getenv("XDG_DATA_HOME");
        if (xdg_data && xdg_data[0] != '\0') {
            data_dir_users = string(xdg_data) + "/RUBIC-A/users";
        } else {
            const char* home = getenv("HOME");
            if (home) {
                data_dir_users = string(home) + "/.local/share/RUBIC-A/users";
            } else {
                data_dir_users = "/tmp/RUBIC-A/users";
            }
        }
        
        struct stat st;
        if (stat(data_dir_users.c_str(), &st) != 0) {
            string current_path;
            stringstream ss(data_dir_users);
            string segment;
            while (getline(ss, segment, '/')) {
                if (segment.empty()) {
                    current_path = "/";
                    continue;
                }
                if (current_path == "/") {
                    current_path += segment;
                } else {
                    current_path += "/" + segment;
                }
                if (stat(current_path.c_str(), &st) != 0) {
                    mkdir(current_path.c_str(), 0700);
                }
            }
        }
        
        return data_dir_users + "/" + username + "_keys.dat";
    }
    
    bool ensureUsersDirectory() const {
        string usersDir;
        const char* xdg_data = getenv("XDG_DATA_HOME");
        if (xdg_data && xdg_data[0] != '\0') {
            usersDir = string(xdg_data) + "/RUBIC-A/users";
        } else {
            const char* home = getenv("HOME");
            if (home) {
                usersDir = string(home) + "/.local/share/RUBIC-A/users";
            } else {
                usersDir = "/tmp/RUBIC-A/users";
            }
        }
        
        struct stat buffer;
        if (stat(usersDir.c_str(), &buffer) == 0) {
            if ((buffer.st_mode & 0777) != 0700) {
                chmod(usersDir.c_str(), 0700);
            }
            return true;
        }
        return mkdir(usersDir.c_str(), 0700) == 0;
    }
    
    bool setSecureFilePermissions(const string& filepath) const {
        return chmod(filepath.c_str(), 0600) == 0;
    }
    
    Botan::secure_vector<uint8_t> encryptDataWithUserPass(const Botan::secure_vector<uint8_t>& plaintext) {
        return KeyCryptoUtils::encryptData(plaintext, userPasswordSecure);
    }
    
    Botan::secure_vector<uint8_t> decryptDataWithUserPass(const Botan::secure_vector<uint8_t>& encrypted) {
        return KeyCryptoUtils::decryptData(encrypted, userPasswordSecure);
    }
    
    bool saveKeysToFile() {
        try {
            if (!ensureUsersDirectory()) {
                log("✗ No se puede crear directorio de usuarios");
                return false;
            }
            
            if (userPasswordSecure.empty()) {
                log("✗ Contraseña de usuario no establecida");
                return false;
            }
            
            stringstream allKeysData;
            for (const auto& pair : keys) {
                const KeyInfo& key = pair.second;
                allKeysData << "=== KEY START ===\n";
                allKeysData << key.serialize();
                allKeysData << "\n=== KEY END ===\n\n";
            }
            
            string keysData = allKeysData.str();
            
            Botan::secure_vector<uint8_t> pt_secure(keysData.begin(), keysData.end());
            
            Botan::secure_vector<uint8_t> encrypted = encryptDataWithUserPass(pt_secure);
            if (encrypted.empty()) {
                log("✗ Error cifrando claves");
                return false;
            }
            
            string encryptedB64 = Botan::base64_encode(encrypted);
            
            string keysFile = getKeysFilePath();
            ofstream file(keysFile, ios::binary);
            if (!file) {
                log("✗ No se puede crear archivo de claves");
                return false;
            }
            
            file << encryptedB64;
            file.close();
            
            setSecureFilePermissions(keysFile);
            
            return true;
            
        } catch(...) {
            return false;
        }
    }
    
    bool loadKeysFromFile() {
        try {
            string keysFile = getKeysFilePath();
            
            struct stat buffer;
            if (stat(keysFile.c_str(), &buffer) != 0) {
                return true;
            }
            
            if ((buffer.st_mode & 0777) != 0600) {
                chmod(keysFile.c_str(), 0600);
            }
            
            ifstream file(keysFile, ios::binary);
            if (!file) {
                log("✗ No se puede abrir archivo de claves");
                return false;
            }
            
            stringstream bufferStream;
            bufferStream << file.rdbuf();
            file.close();
            
            string encryptedB64 = bufferStream.str();
            if (encryptedB64.empty()) {
                return true;
            }
            
            Botan::secure_vector<uint8_t> encrypted = Botan::base64_decode(encryptedB64);
            
            Botan::secure_vector<uint8_t> decrypted = decryptDataWithUserPass(encrypted);
            if (decrypted.empty()) {
                log("✗ Error descifrando claves. Contraseña incorrecta o archivo corrupto.");
                return false;
            }
            
            string decryptedStr(decrypted.begin(), decrypted.end());
            
            keys.clear();
            stringstream ss(decryptedStr);
            string line;
            string currentKeyData;
            bool readingKey = false;
            
            while (getline(ss, line)) {
                if (line == "=== KEY START ===") {
                    readingKey = true;
                    currentKeyData.clear();
                } else if (line == "=== KEY END ===") {
                    readingKey = false;
                    
                    KeyInfo key;
                    if (key.deserialize(currentKeyData)) {
                        keys[key.key_name] = std::move(key);
                    }
                    
                    currentKeyData.clear();
                } else if (readingKey) {
                    if (!currentKeyData.empty()) {
                        currentKeyData += "\n";
                    }
                    currentKeyData += line;
                }
            }
            
            return true;
            
        } catch(...) {
            return false;
        }
    }
    
public:
    KeyManager() : passwordVerified(false) {}
    
    ~KeyManager() {
        userPasswordSecure.clear();
        password_locker.reset();
    }
    
    void setLogCallback(LogCallback cb) { log_cb_ = std::move(cb); }
    
    void setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password) {
        userPasswordSecure = password;
        
        if (!userPasswordSecure.empty()) {
            password_locker = make_unique<MemoryLC>(
                const_cast<uint8_t*>(userPasswordSecure.data()), 
                userPasswordSecure.size()
            );
        }
    }
    
    void setUsername(const string& name) {
        username = name;
        if (!userPasswordSecure.empty()) {
            loadKeysFromFile();
            
            for (auto& pair : keys) {
                if (!pair.second.access_code.empty() && !pair.second.memory_locker) {
                    pair.second.lockMemory();
                }
            }
        }
    }
    
    void saveKeys() {
        if (!username.empty() && !userPasswordSecure.empty() && !keys.empty()) {
            saveKeysToFile();
        }
    }
    
    const map<string, KeyInfo>& getKeys() const {
        return keys;
    }
    
    bool hasKey(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end();
    }
    
    bool isKeyActive(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end() && it->second.is_active;
    }

    Botan::secure_vector<uint8_t> getKeyValue(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it != keys.end() && it->second.is_active) {
            return it->second.key_value;
        }
        return Botan::secure_vector<uint8_t>();
    }
    
    bool activateKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode) {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            return false;
        }
        
        KeyInfo& key = it->second;
        
        if (key.is_active) {
            return true;
        }
        
        if (!key.requires_access) {
            key.is_active = true;
            key.last_used = time(nullptr);
            saveKeysToFile();
            return true;
        }
        
        bool match = (accessCode.size() == key.access_code.size() && 
                     secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
        
        if (!match) {
            return false;
        }
        
        key.is_active = true;
        key.last_used = time(nullptr);
        
        if (saveKeysToFile()) {
            return true;
        } else {
            key.is_active = false;
            return false;
        }
    }
    
    bool activateKey(const string& keyName, const string& accessCode) {
        Botan::secure_vector<uint8_t> codeSecure(accessCode.begin(), accessCode.end());
        return activateKey(keyName, codeSecure);
    }
    
    bool keyRequiresActivation(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            return false;
        }
        return it->second.requires_access;
    }
    
    bool hasKeys() const {
        return !keys.empty();
    }
    
    vector<string> getActiveKeys() const {
        vector<string> activeKeys;
        for (const auto& pair : keys) {
            if (pair.second.is_active) {
                activeKeys.push_back(pair.first);
            }
        }
        return activeKeys;
    }
    
    void resetVerification() {
        passwordVerified = false;
    }
    
    static bool isArgon2Available() {
        return KeyCryptoUtils::isArgon2Available();
    }
    
    // ============================================================
    // MÉTODOS PÚBLICOS PARA LA UI
    // ============================================================
    
    bool verifyPassword(const Botan::secure_vector<uint8_t>& inputPass) {
        if (passwordVerified) return true;
        
        bool match = (inputPass.size() == userPasswordSecure.size() && 
                     secure_memcmp(inputPass.data(), userPasswordSecure.data(), inputPass.size()));
        
        if (match) {
            passwordVerified = true;
            return true;
        }
        return false;
    }
    
    bool isPasswordVerified() const { return passwordVerified; }
    
    string createKey(const string& keyName, const string& usage,
                     const Botan::secure_vector<uint8_t>& accessCode,
                     string& error_out) {
        if (keyName.empty()) {
            error_out = "El nombre de la clave no puede estar vacío";
            return "";
        }
        
        if (keys.find(keyName) != keys.end()) {
            error_out = "Ya existe una clave con ese nombre";
            return "";
        }
        
        if (accessCode.empty()) {
            error_out = "La clave de acceso no puede estar vacía";
            return "";
        }
        
        Botan::secure_vector<uint8_t> keyValue = KeyCryptoUtils::generateRandomBytes(32);
        if (keyValue.empty()) {
            error_out = "Error generando la clave criptográfica";
            return "";
        }
        
        KeyInfo newKey;
        newKey.key_name = keyName;
        newKey.key_value = std::move(keyValue);
        newKey.key_type = "AES-256";
        newKey.key_usage = usage;
        newKey.created_at = time(nullptr);
        newKey.last_used = 0;
        newKey.is_active = false;
        newKey.strength = 256;
        newKey.access_code = accessCode;
        newKey.requires_access = true;
        
        newKey.lockMemory();
        
        keys[keyName] = std::move(newKey);
        
        if (!saveKeysToFile()) {
            keys.erase(keyName);
            error_out = "Error guardando la clave";
            return "";
        }
        
        return keyName;
    }
    
    bool deleteKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode,
                   string& error_out) {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            error_out = "Clave no encontrada";
            return false;
        }
        
        KeyInfo& key = it->second;
        
        if (key.requires_access && !key.access_code.empty()) {
            bool match = (accessCode.size() == key.access_code.size() && 
                         secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
            
            if (!match) {
                error_out = "Clave de acceso incorrecta. Eliminación cancelada.";
                return false;
            }
        }
        
        keys.erase(keyName);
        
        if (!saveKeysToFile()) {
            error_out = "Error guardando cambios";
            return false;
        }
        
        return true;
    }
    
    bool toggleKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode,
                   string& error_out) {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            error_out = "Clave no encontrada";
            return false;
        }
        
        KeyInfo& key = it->second;
        
        if (key.is_active) {
            key.is_active = false;
            key.last_used = time(nullptr);
            
            if (!saveKeysToFile()) {
                error_out = "Error guardando cambios";
                key.is_active = true;
                return false;
            }
            return true;
        }
        
        if (key.requires_access && !key.access_code.empty()) {
            bool match = (accessCode.size() == key.access_code.size() && 
                         secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
            
            if (!match) {
                error_out = "Clave de acceso incorrecta";
                return false;
            }
        }
        
        key.is_active = true;
        key.last_used = time(nullptr);
        
        if (!saveKeysToFile()) {
            error_out = "Error guardando cambios";
            key.is_active = false;
            return false;
        }
        
        return true;
    }
    
    string getKeysFilePathPublic() const { return getKeysFilePath(); }
    string getUsername() const { return username; }
    
    size_t keyCount() const { return keys.size(); }
    int activeCount() const {
        int c = 0;
        for (const auto& p : keys) if (p.second.is_active) c++;
        return c;
    }
    
    const KeyInfo* getKeyInfo(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end()) return nullptr;
        return &it->second;
    }
};

#endif // KEYGEST_KEY_MANAGER_H
