// cipher/unit_encryptor.cpp - 0.1 alpha
// Implementación de la lógica pura de UnitEncryptor.

#include "unit_encryptor.h"
#include "../keygest/key_manager.h"
#include "../rubic_core.h" // Para XDG

#include <limits.h>
#include <sys/wait.h>
#include <fstream>
#include <filesystem>
#include <fcntl.h>
#include <span> // Necesario para la API de Botan 3

// ============================================
// EJECUCIÓN SEGURA DE COMANDOS (Anti-RCE)
// ============================================

static int safe_exec(const std::vector<std::string>& args) {
    if (args.empty()) return -1;
    pid_t pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static std::string exec_cmd_output(const std::vector<std::string>& args) {
    if (args.empty()) return "";
    int pipefd[2];
    if (pipe(pipefd) == -1) return "";
    
    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); return ""; }
    
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    
    close(pipefd[1]);
    std::string result;
    char buffer[256];
    ssize_t bytes_read;
    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        result += buffer;
    }
    close(pipefd[0]);
    
    int status;
    waitpid(pid, &status, 0);
    
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

// ============================================
// KeyDeriv
// ============================================

Botan::secure_vector<uint8_t> KeyDeriv::deriveSubKey(
    const Botan::secure_vector<uint8_t>& master_key,
    const Botan::secure_vector<uint8_t>& salt,
    size_t key_length) {
    try {
        auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
        Botan::secure_vector<uint8_t> derived_key(key_length);
        
        std::string info_str = KEY_DERIVATION_INFO;
        
        kdf->derive_key(
            std::span<uint8_t>(derived_key.data(), derived_key.size()),
            std::span<const uint8_t>(master_key.data(), master_key.size()),
            std::span<const uint8_t>(salt.data(), salt.size()),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size())
        );
        
        return derived_key;
    } catch (const std::exception& e) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyDeriv::generateSalt(size_t size) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(size);
        rng.randomize(salt.data(), salt.size());
        return salt;
    } catch (const std::exception& e) {
        return Botan::secure_vector<uint8_t>();
    }
}

// ============================================
// CustCfg
// ============================================

CustCfg::CustCfg() 
    : buffer_size_mb(64), io_threads(2), crypto_threads(4), 
      use_direct_io(true), custom_mode(false) {}

void CustCfg::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream iss(line);
            std::string key, value;
            if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                if (key == "buffer_size_mb") buffer_size_mb = std::stoul(value);
                else if (key == "io_threads") io_threads = std::stoi(value);
                else if (key == "crypto_threads") crypto_threads = std::stoi(value);
                else if (key == "use_direct_io") use_direct_io = (value == "true");
                else if (key == "custom_mode") custom_mode = (value == "true");
            }
        }
        file.close();
    }
}

void CustCfg::saveToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "# Configuración personalizada de RUBI-C\n";
        file << "# Valores por defecto: buffer_size_mb=64, io_threads=2, crypto_threads=4\n\n";
        file << "buffer_size_mb=" << buffer_size_mb << "\n";
        file << "io_threads=" << io_threads << "\n";
        file << "crypto_threads=" << crypto_threads << "\n";
        file << "use_direct_io=" << (use_direct_io ? "true" : "false") << "\n";
        file << "custom_mode=" << (custom_mode ? "true" : "false") << "\n";
        file.close();
    }
}

// ============================================
// AlignBuf
// ============================================

AlignBuf::AlignBuf(size_t size) : data_ptr(nullptr), size_bytes(size) {
    if (posix_memalign(&data_ptr, ALIGNMENT, size) != 0) throw std::bad_alloc();
    memset(data_ptr, 0, size);
}

AlignBuf::~AlignBuf() { if (data_ptr) free(data_ptr); }

AlignBuf::AlignBuf(AlignBuf&& other) noexcept : data_ptr(other.data_ptr), size_bytes(other.size_bytes) {
    other.data_ptr = nullptr;
    other.size_bytes = 0;
}

AlignBuf& AlignBuf::operator=(AlignBuf&& other) noexcept {
    if (this != &other) {
        if (data_ptr) free(data_ptr);
        data_ptr = other.data_ptr;
        size_bytes = other.size_bytes;
        other.data_ptr = nullptr;
        other.size_bytes = 0;
    }
    return *this;
}

uint8_t* AlignBuf::data() { return static_cast<uint8_t*>(data_ptr); }
const uint8_t* AlignBuf::data() const { return static_cast<const uint8_t*>(data_ptr); }
size_t AlignBuf::size() const { return size_bytes; }

// ============================================
// DevDetect
// ============================================

std::string DevDetect::getSysPath(const std::string& device) {
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    while (!devname.empty() && isdigit(devname.back())) devname.pop_back();
    return "/sys/block/" + devname;
}

bool DevDetect::checkUSB(const std::string& syspath) {
    std::string uevent = syspath + "/device/uevent";
    FILE* f = fopen(uevent.c_str(), "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "USB") || strstr(line, "usb")) { fclose(f); return true; }
        }
        fclose(f);
    }
    char buf[256];
    ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf)-1);
    if (len != -1) { buf[len] = '\0'; if (std::string(buf).find("usb") != std::string::npos) return true; }
    return false;
}

std::string DevDetect::readSpeed(const std::string& syspath) {
    std::string speed_file = syspath + "/device/speed";
    FILE* f = fopen(speed_file.c_str(), "r");
    if (!f) return "";
    char speed[32];
    if (fgets(speed, sizeof(speed), f)) { speed[strcspn(speed, "\n")] = 0; fclose(f); return speed; }
    fclose(f);
    return "";
}

bool DevDetect::checkNVMe(const std::string& device) { return device.find("nvme") != std::string::npos; }
bool DevDetect::checkSD(const std::string& device) { return device.find("mmcblk") != std::string::npos; }

bool DevDetect::isRemovable(const std::string& syspath) {
    std::string removable_file = syspath + "/removable";
    FILE* f = fopen(removable_file.c_str(), "r");
    if (f) { char rem; if (fscanf(f, "%c", &rem) == 1) { fclose(f); return (rem == '1'); } fclose(f); }
    return false;
}

DevType DevDetect::detect(const std::string& device) {
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    if (checkNVMe(devname)) return DevType::NVME;
    if (checkSD(devname)) return DevType::SD_CARD;
    std::string syspath = getSysPath(device);
    bool usb = checkUSB(syspath);
    bool removable = isRemovable(syspath);
    if (usb || removable) {
        std::string speed = readSpeed(syspath);
        if (!speed.empty()) { int speed_val = atoi(speed.c_str()); return speed_val >= 500 ? DevType::USB3 : DevType::USB2; }
        return DevType::USB2;
    }
    std::string rotational_file = syspath + "/queue/rotational";
    FILE* f = fopen(rotational_file.c_str(), "r");
    if (f) { char rot; if (fscanf(f, "%c", &rot) == 1) { fclose(f); return (rot == '0') ? DevType::SSD_SATA : DevType::HDD; } fclose(f); }
    return DevType::UNKNOWN;
}

// ============================================
// FixedThCfg
// ============================================

FixedThCfg FixedThCfg::getConfigForSystem() {
    FixedThCfg config;
    int system_threads = HardwareDetect::getCoreCount();
    int available_threads = system_threads > 1 ? system_threads - 1 : system_threads;
    if (available_threads <= 2) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
    else if (available_threads <= 4) { config.io_threads = 1; config.crypto_threads = 2; config.reserved_os = 1; }
    else if (available_threads <= 8) { config.io_threads = 2; config.crypto_threads = 5; config.reserved_os = 1; }
    else if (available_threads <= 16) { config.io_threads = 3; config.crypto_threads = 11; config.reserved_os = 2; }
    else if (available_threads <= 32) { config.io_threads = 4; config.crypto_threads = 24; config.reserved_os = 4; }
    else { config.io_threads = 6; config.crypto_threads = available_threads - 8; config.reserved_os = 2; }
    return config;
}

// ============================================
// ThCfg
// ============================================

ThCfg::ThCfg() {
    num_threads = HardwareDetect::getCoreCount();
    chunk_size_mb = 64;
    use_direct_io = true;
}

void ThCfg::applyFixedConfig(const FixedThCfg& fixed_cfg, DevType device_type) {
    num_threads = fixed_cfg.io_threads + fixed_cfg.crypto_threads + fixed_cfg.reserved_os;
    chunk_size_mb = DevDetect::getOptimalChunkMB(device_type);
    use_direct_io = DevDetect::useDirectIO(device_type);
}

void ThCfg::applyCustomConfig(const CustCfg& custom_cfg) {
    num_threads = custom_cfg.io_threads + custom_cfg.crypto_threads;
    chunk_size_mb = custom_cfg.buffer_size_mb;
    use_direct_io = custom_cfg.use_direct_io;
}

void ThCfg::validate() {
    if (num_threads < MIN_THREADS) num_threads = MIN_THREADS;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (chunk_size_mb < 1) chunk_size_mb = 1;
    if (chunk_size_mb > 1024) chunk_size_mb = 1024;
    size_t chunk_bytes = chunk_size_mb * MB;
    if (chunk_bytes % ALIGNMENT != 0) chunk_size_mb = ((chunk_bytes + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT / MB;
}

size_t ThCfg::getChunkSize() const {
    size_t size = chunk_size_mb * MB;
    if (size % ALIGNMENT != 0) size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
    return size;
}

std::string ThCfg::getDesc() const {
    std::stringstream ss;
    ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
    if (use_direct_io) ss << " | I/O DIRECTO";
    return ss.str();
}

// ============================================
// SpeedMtr
// ============================================

SpeedMtr::SpeedMtr() { reset(); }

void SpeedMtr::addBytes(uint64_t bytes) { total_bytes += bytes; }

double SpeedMtr::getCurrentSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();
    if (elapsed >= 200) {
        uint64_t current = total_bytes.load();
        uint64_t diff = current - last_bytes;
        double speed = (diff / 1048576.0) / (elapsed / 1000.0);
        current_speed = speed;
        if (speed > peak_speed) peak_speed = speed;
        last_bytes = current;
        last_time = now;
    }
    return current_speed.load();
}

double SpeedMtr::getAvgSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
    return elapsed > 0 ? (total_bytes / 1048576.0) / (elapsed / 1000.0) : 0;
}

double SpeedMtr::getPeakSpeed() { return peak_speed.load(); }
uint64_t SpeedMtr::getTotalBytes() { return total_bytes.load(); }

void SpeedMtr::reset() {
    start_time = std::chrono::steady_clock::now();
    last_time = start_time;
    total_bytes = 0;
    last_bytes = 0;
    current_speed = 0;
    peak_speed = 0;
}

// ============================================
// HdrBackup
// ============================================

std::string HdrBackup::getBackupPath(const std::string& device_path) {
    std::string devname = device_path;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    std::replace(devname.begin(), devname.end(), '/', '_');
    
    // FIX: Usar SHA-256 en lugar de std::hash para evitar pérdida de backups
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(devname);
    std::string hashed = Botan::hex_encode(hash->final()).substr(0, 16);
    
    const char* xdg_data = getenv("XDG_DATA_HOME");
    std::string base_dir;
    if (xdg_data && xdg_data[0] != '\0') {
        base_dir = std::string(xdg_data) + "/RUBIC-A/backups";
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            base_dir = std::string(home) + "/.local/share/RUBIC-A/backups";
        } else {
            base_dir = "/var/lib/rubic-a/backups"; 
        }
    }
    
    std::filesystem::create_directories(base_dir);
    std::filesystem::permissions(base_dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
    
    return base_dir + "/.rubic_" + hashed + ".dat";
}

Botan::secure_vector<uint8_t> HdrBackup::encryptBackup(const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        if (!cipher) return {};
        Botan::secure_vector<uint8_t> data(sizeof(header));
        memcpy(data.data(), &header, sizeof(header));
        cipher->set_key(key);
        Botan::secure_vector<uint8_t> nonce(12);
        Botan::AutoSeeded_RNG rng;
        rng.randomize(nonce.data(), nonce.size());
        cipher->start(nonce);
        cipher->finish(data);
        Botan::secure_vector<uint8_t> result;
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), data.begin(), data.end());
        return result;
    } catch (...) { return {}; }
}

bool HdrBackup::decryptBackup(const std::string& backup_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
    std::ifstream file(backup_path, std::ios::binary);
    if (!file.is_open()) return false;
    Botan::secure_vector<uint8_t> encrypted_data;
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    encrypted_data.resize(size);
    file.read(reinterpret_cast<char*>(encrypted_data.data()), size);
    file.close();
    if (encrypted_data.size() < 12 + 16) return false;
    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        if (!cipher) return false;
        Botan::secure_vector<uint8_t> nonce(encrypted_data.begin(), encrypted_data.begin() + 12);
        Botan::secure_vector<uint8_t> ciphertext(encrypted_data.begin() + 12, encrypted_data.end());
        cipher->set_key(key);
        cipher->start(nonce);
        cipher->finish(ciphertext);
        if (ciphertext.size() != sizeof(header)) return false;
        memcpy(&header, ciphertext.data(), sizeof(header));
        return true;
    } catch (...) { return false; }
}

Botan::secure_vector<uint8_t> HdrBackup::deriveBackupKey(const std::string& device_path) {
    Botan::secure_vector<uint8_t> key(32);
    auto hash = Botan::HashFunction::create("SHA-512");
    if (!hash) return {};
    hash->update(device_path);
    auto digest = hash->final();
    for (size_t i = 0; i < 32; i++) key[i] = digest[i];
    return key;
}

bool HdrBackup::saveHeader(const std::string& device_path, const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
    auto backup_key = deriveBackupKey(device_path);
    auto encrypted = encryptBackup(header, backup_key);
    if (encrypted.empty()) return false;
    std::string backup_path = getBackupPath(device_path);
    std::ofstream file(backup_path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    file.close();
    chmod(backup_path.c_str(), 0600);
    return true;
}

bool HdrBackup::loadHeader(const std::string& device_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
    auto backup_key = deriveBackupKey(device_path);
    std::string backup_path = getBackupPath(device_path);
    return decryptBackup(backup_path, header, backup_key);
}

bool HdrBackup::backupExists(const std::string& device_path) {
    std::string backup_path = getBackupPath(device_path);
    struct stat st;
    return (stat(backup_path.c_str(), &st) == 0);
}

bool HdrBackup::removeBackup(const std::string& device_path) {
    std::string backup_path = getBackupPath(device_path);
    return (unlink(backup_path.c_str()) == 0);
}

// ============================================
// StorUnit
// ============================================

std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* sizes[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double dbl = bytes;
    while (dbl >= 1024.0 && i < 4) { dbl /= 1024.0; i++; }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << dbl << " " << sizes[i];
    return ss.str();
}

std::string StorUnit::getSafeFSType() const {
    if (strlen(fs_info.fstype) > 0) {
        bool valid = true;
        for (size_t i = 0; i < strlen(fs_info.fstype); i++) {
            if (!isprint(fs_info.fstype[i])) { valid = false; break; }
        }
        if (valid) return std::string(fs_info.fstype);
    }
    return "";
}

// ============================================
// KMACProc (KMAC Post-Cuántico)
// ============================================

KMACProc::KMACProc(const Botan::secure_vector<uint8_t>& key_data) {
    key = key_data;
    
    try {
        Kmac = Botan::MessageAuthenticationCode::create("KMAC-256(512)");
    } catch (...) {
        Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(512))");
        if (!Kmac) Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    }
    
    if (!Kmac) throw std::runtime_error("No se pudo crear el MAC criptográfico");
    Kmac->set_key(key);
}

Botan::secure_vector<uint8_t> KMACProc::calculate(const uint8_t* data, size_t size) {
    Kmac->update(data, size);
    return Kmac->final();
}

bool KMACProc::verify(const uint8_t* data, size_t size, const uint8_t* expected_Kmac, size_t Kmac_size) {
    auto calculated = calculate(data, size);
    if (calculated.size() != Kmac_size) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < Kmac_size; i++) diff |= (calculated[i] ^ expected_Kmac[i]);
    return diff == 0;
}

// ============================================
// AESXTSProc
// ============================================

AESXTSProc::AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt) {
    sector_buffer_size = 0;
    if (key_data.size() == 32) {
        key.resize(64);
        memcpy(key.data(), key_data.data(), 32);
        memcpy(key.data() + 32, key_data.data(), 32);
    } else {
        key = key_data;
    }
    cipher = Botan::Cipher_Mode::create("AES-256/XTS", encrypt ? Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption);
    if (!cipher) throw std::runtime_error("No se pudo crear el cifrador");
    cipher->set_key(key);
    sector_buffer.resize(SECTOR_SIZE);
    sector_buffer_size = SECTOR_SIZE;
}

bool AESXTSProc::processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
    try {
        size_t num_sectors = size / SECTOR_SIZE;
        const size_t BATCH_SIZE = 64;
        if (tweak_buffer.size() < BATCH_SIZE * 16) tweak_buffer.resize(BATCH_SIZE * 16);
        for (size_t i = 0; i < num_sectors; i += BATCH_SIZE) {
            size_t batch = std::min(BATCH_SIZE, num_sectors - i);
            SIMDProc::fill_tweak(tweak_buffer.data(), start_sector + i, batch);
            for (size_t j = 0; j < batch; j++) {
                cipher->start(tweak_buffer.data() + j * 16, 16);
                sector_buffer.assign(data + (i + j) * SECTOR_SIZE, data + (i + j + 1) * SECTOR_SIZE);
                cipher->finish(sector_buffer);
                memcpy(data + (i + j) * SECTOR_SIZE, sector_buffer.data(), SECTOR_SIZE);
            }
        }
        return true;
    } catch (const std::exception& e) { return false; }
}

bool AESXTSProc::processSecBuf(SecBuf& buffer, uint64_t start_sector) {
    return processBuffer(buffer.data(), buffer.size(), start_sector);
}

// ============================================
// UnitEncryptor
// ============================================

UnitEncryptor::UnitEncryptor() 
    : keyManager(nullptr), useDirectKey(false), use_custom_config(false), last_refresh(0) {
    fixed_config = FixedThCfg::getConfigForSystem();
    
    // FIX: Usar ruta XDG para la configuración
    std::string cfg_path = XDG::get_rubic_config_dir() + "/rubic_config.cfg";
    custom_config.loadFromFile(cfg_path);
    
    use_custom_config = custom_config.custom_mode;
    refreshUnits();
}

bool UnitEncryptor::hasKey() const {
    if (useDirectKey) return !directKey.empty();
    return keyManager != nullptr && !keyManager->getActiveKeys().empty();
}

void UnitEncryptor::refreshUnits() {
    time_t now = time(nullptr);
    if (now - last_refresh > 2) {
        cached_units = detectUnits();
        last_refresh = now;
    }
}

bool UnitEncryptor::isPhysicalDevice(const std::string& path) {
    if (path.find("/dev/loop") != std::string::npos) return false;
    if (path.find("/dev/ram") != std::string::npos) return false;
    return true;
}

std::string UnitEncryptor::getParentDevice(const std::string& path) {
    std::string dev = path;
    if (dev.find("/dev/") == 0) dev = dev.substr(5);
    
    if (dev.find("nvme") == 0) {
        size_t p_pos = dev.find('p');
        if (p_pos != std::string::npos) {
            return "/dev/" + dev.substr(0, p_pos);
        }
        return "/dev/" + dev;
    }
    
    size_t p = dev.find_first_of("0123456789");
    if (p != std::string::npos) return "/dev/" + dev.substr(0, p);
    
    return "";
}

bool UnitEncryptor::isSystemDisk(const std::string& path) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev, mnt;
            iss >> dev >> mnt;
            if (mnt == "/") {
                return (path == dev);
            }
        }
    }
    return false;
}

FSInfo UnitEncryptor::getFileSystemInfo(const std::string& path) {
    FSInfo info;
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fstype;
        iss >> dev >> mnt >> fstype;
        if (dev == path) {
            strncpy(info.fstype, fstype.c_str(), sizeof(info.fstype) - 1);
            info.fstype[sizeof(info.fstype) - 1] = '\0';
            return info;
        }
    }

    std::string out = exec_cmd_output({"blkid", "-o", "value", "-s", "TYPE", path});
    if (!out.empty()) {
        strncpy(info.fstype, out.c_str(), sizeof(info.fstype) - 1);
        info.fstype[sizeof(info.fstype) - 1] = '\0';
    }
    out = exec_cmd_output({"blkid", "-o", "value", "-s", "LABEL", path});
    if (!out.empty()) {
        strncpy(info.label, out.c_str(), sizeof(info.label) - 1);
        info.label[sizeof(info.label) - 1] = '\0';
    }
    return info;
}

bool UnitEncryptor::isUnitEncrypted(const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    
    EncUnitHdr hdr;
    bool has_valid_header = false;
    
    off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
    ssize_t read_bytes = pread(fd, &hdr, sizeof(hdr), header_offset);
    
    if (read_bytes == sizeof(hdr)) {
        has_valid_header = hdr.isValid();
    }
    
    close(fd);
    return has_valid_header;
}

bool UnitEncryptor::readHeaderFromDevice(int fd, EncUnitHdr& hdr) {
    off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
    ssize_t read_bytes = pread(fd, &hdr, sizeof(hdr), header_offset);
    if (read_bytes != sizeof(hdr)) return false;
    return hdr.isValid();
}

bool UnitEncryptor::writeHeaderToDevice(int fd, const EncUnitHdr& hdr) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) return false;
    bool was_direct = (flags & O_DIRECT);
    if (was_direct) { int new_flags = flags & ~O_DIRECT; fcntl(fd, F_SETFL, new_flags); }
    off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
    ssize_t written = pwrite(fd, &hdr, sizeof(hdr), header_offset);
    if (was_direct) fcntl(fd, F_SETFL, flags);
    return (written == sizeof(hdr));
}

std::vector<StorUnit> UnitEncryptor::detectUnits() {
    std::vector<StorUnit> units;
    std::map<std::string, StorUnit> unique_by_device;
    std::set<std::string> seen_devices;
    
    std::string root_dev;
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev;
            iss >> dev;
            root_dev = dev;
            break;
        }
    }
    
    mounts.clear();
    mounts.seekg(0);
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fstype;
        iss >> dev >> mnt >> fstype;
        
        if (dev.find("/dev/") == 0 && isPhysicalDevice(dev)) {
            StorUnit u;
            u.device_path = dev;
            u.mount_point = mnt;
            u.filesystem = fstype;
            u.is_mounted = true;
            u.is_partition = (dev.find_first_of("0123456789") != std::string::npos);
            u.parent_device = getParentDevice(dev);
            u.is_system_disk = (dev == root_dev);
            
            std::string devname = std::filesystem::path(dev).filename().string();
            std::ifstream size_file("/sys/class/block/" + devname + "/size");
            uint64_t sectors = 0;
            if (size_file >> sectors) {
                u.total_size = sectors * 512ULL;
            } else {
                u.total_size = 0;
            }
            
            int fd = open(dev.c_str(), O_RDONLY);
            if (fd >= 0) {
                u.is_encrypted = isUnitEncrypted(dev);
                u.fs_info = getFileSystemInfo(dev);
                u.label = u.fs_info.label;
                close(fd);
            } else if (errno == EACCES || errno == EPERM) {
                u.requires_elevation = true;
                u.is_encrypted = false; 
            }
            
            u.device_type = DevDetect::detect(dev);
            u.has_header_backup = backup_mgr.backupExists(dev);
            
            unique_by_device[dev] = u;
            seen_devices.insert(dev);
        }
    }
    
    DIR* dir = opendir("/dev");
    if (dir) {
        struct dirent* e;
        while ((e = readdir(dir))) {
            std::string name = e->d_name;
            std::string dev = "/dev/" + name;
            
            if ((name.find("sd") == 0 || name.find("hd") == 0 || name.find("nvme") == 0 || name.find("mmcblk") == 0) &&
                !seen_devices.count(dev) && isPhysicalDevice(dev)) {
                bool is_part = (name.find_first_of("0123456789") != std::string::npos);
                std::string parent = getParentDevice(dev);
                
                if (!is_part) {
                    bool has_parts = false;
                    for (const auto& pair : unique_by_device) {
                        if (pair.second.parent_device == dev) { has_parts = true; break; }
                    }
                    if (has_parts) continue;
                }
                
                StorUnit u;
                u.device_path = dev;
                u.is_mounted = false;
                u.is_partition = is_part;
                u.parent_device = parent;
                u.is_system_disk = (dev == root_dev);
                
                std::string devname = std::filesystem::path(dev).filename().string();
                std::ifstream size_file("/sys/class/block/" + devname + "/size");
                uint64_t sectors = 0;
                if (size_file >> sectors) u.total_size = sectors * 512ULL;
                
                if (u.total_size > 0) {
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        u.is_encrypted = isUnitEncrypted(dev);
                        u.fs_info = getFileSystemInfo(dev);
                        u.label = u.fs_info.label;
                        close(fd);
                    } else if (errno == EACCES || errno == EPERM) {
                        u.requires_elevation = true;
                        u.is_encrypted = false;
                    }
                    
                    u.device_type = DevDetect::detect(dev);
                    u.has_header_backup = backup_mgr.backupExists(dev);
                    unique_by_device[dev] = u;
                }
            }
        }
        closedir(dir);
    }
    
    units.reserve(unique_by_device.size());
    for (auto& pair : unique_by_device) {
        units.push_back(pair.second);
    }
    
    std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
        if (a.is_system_disk != b.is_system_disk) return a.is_system_disk > b.is_system_disk;
        return a.total_size > b.total_size;
    });
    
    return units;
}

bool UnitEncryptor::unmount(StorUnit& u) {
    if (!u.is_mounted) return true;
    log(LogLevel::Info, LogEvent::Unmounting, u.mount_point);
    
    int ret = safe_exec({"umount", "-l", u.mount_point});
    (void)ret;
    
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(u.device_path) != std::string::npos) { return false; }
    }
    u.is_mounted = false;
    u.mount_point.clear();
    log(LogLevel::Success, LogEvent::Unmounted, "");
    return true;
}

bool UnitEncryptor::mount(const StorUnit& u, const std::string& point) {
    log(LogLevel::Info, LogEvent::Mounting, point);
    
    safe_exec({"mkdir", "-p", point});
    
    std::string fs = u.filesystem;
    if (fs.empty() && strlen(u.fs_info.fstype) > 0) {
        std::string safe_fs = u.getSafeFSType();
        if (!safe_fs.empty()) fs = safe_fs;
    }
    
    int ret = -1;
    if (!fs.empty()) {
        ret = safe_exec({"mount", "-t", fs, u.device_path, point});
    } else {
        ret = safe_exec({"mount", u.device_path, point});
    }
    
    if (ret == 0) { log(LogLevel::Success, LogEvent::Mounted, point); return true; }
    log(LogLevel::Error, LogEvent::MountFailed, std::to_string(ret));
    return false;
}

std::vector<StorUnit> UnitEncryptor::getUnits() {
    refreshUnits();
    return cached_units;
}

void UnitEncryptor::refresh() {
    cached_units = detectUnits();
    last_refresh = time(nullptr);
}

void UnitEncryptor::reloadCustomConfig() {
    std::string cfg_path = XDG::get_rubic_config_dir() + "/rubic_config.cfg";
    custom_config.loadFromFile(cfg_path);
    use_custom_config = custom_config.custom_mode;
}

bool UnitEncryptor::tryElevatedProcess(const StorUnit& unit, bool encrypt,
                                        const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("pipe: ") + strerror(errno));
        return false;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("fork: ") + strerror(errno));
        return false;
    }
    
    if (pid == 0) {
        close(pipefd[1]);
        if (pipefd[0] != 3) {
            dup2(pipefd[0], 3);
            close(pipefd[0]);
        }
        int flags = fcntl(3, F_GETFD);
        if (flags >= 0) fcntl(3, F_SETFD, flags & ~FD_CLOEXEC);
        
        char exe_path[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (n <= 0) _exit(127);
        exe_path[n] = '\0';
        
        execlp("sudo", "sudo", "--preserve-fds=1",
               exe_path, "--unit-op",
               unit.device_path.c_str(),
               encrypt ? "encrypt" : "decrypt",
               nullptr);
        _exit(127);
    }
    
    close(pipefd[0]);
    
    uint32_t key_len = static_cast<uint32_t>(master_key.size());
    bool write_ok = (write(pipefd[1], &key_len, sizeof(key_len)) == (ssize_t)sizeof(key_len))
                 && (write(pipefd[1], master_key.data(), key_len) == (ssize_t)key_len);
    close(pipefd[1]);
    
    int status = 0;
    waitpid(pid, &status, 0);
    
    if (!write_ok) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "write pipe failed");
        return false;
    }
    if (!WIFEXITED(status)) {
        log(LogLevel::Error, LogEvent::ProcessingFailed, "worker killed");
        return false;
    }
    int rc = WEXITSTATUS(status);
    if (rc == 127) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, "sudo unavailable");
        return false;
    }
    if (rc != 0) {
        log(LogLevel::Error, LogEvent::ProcessingFailed, "worker rc=" + std::to_string(rc));
        return false;
    }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit, bool encrypt, 
                                 const Botan::secure_vector<uint8_t>& master_key) {
    if (geteuid() != 0) {
        bool ok = tryElevatedProcess(unit, encrypt, master_key);
        if (ok) {
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            refreshUnits();
        }
        return ok;
    }
    
    if (encrypt && unit.is_encrypted) { 
        log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, "");
        return false; 
    }
    if (!encrypt && !unit.is_encrypted) { 
        log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");
        return false; 
    }
    if (unit.is_system_disk) { 
        log(LogLevel::Error, LogEvent::SystemDiskBlocked, "");
        return false; 
    }
    if (unit.is_mounted) {
        log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point);
        return false;
    }
    
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    
    stop_requested = false;
    processing_active = true;
    speed_meter.reset();
    stats = Stats();
    
    auto start = std::chrono::high_resolution_clock::now();
    bool ok = doProcess(unit, master_key, encrypt);
    auto end = std::chrono::high_resolution_clock::now();
    
    processing_active = false;
    
    if (ok) {
        stats.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        stats.total_bytes = speed_meter.getTotalBytes();
        stats.avg_speed_mbps = speed_meter.getAvgSpeed();
        stats.peak_speed_mbps = speed_meter.getPeakSpeed();
        
        unit.is_encrypted = encrypt;
        unit.has_header_backup = encrypt;
        refreshUnits();
    }
    return ok;
}

bool UnitEncryptor::doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
    ThCfg proc_config;
    if (use_custom_config && custom_config.custom_mode) proc_config.applyCustomConfig(custom_config);
    else proc_config.applyFixedConfig(fixed_config, unit.device_type);
    proc_config.validate();
    
    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    if (use_custom_config && custom_config.custom_mode) {
        log(LogLevel::Info, LogEvent::ConfigCustom,
            std::to_string(custom_config.buffer_size_mb) + "MB/" +
            std::to_string(custom_config.io_threads) + "io/" +
            std::to_string(custom_config.crypto_threads) + "crypto");
    } else {
        log(LogLevel::Info, LogEvent::ConfigAuto,
            std::to_string(fixed_config.io_threads) + "io/" +
            std::to_string(fixed_config.crypto_threads) + "crypto");
    }
    log(LogLevel::Info, LogEvent::ChunkSizeInfo, std::to_string(proc_config.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, proc_config.use_direct_io ? "direct" : "normal");
    
    int flags = O_RDWR | O_SYNC;
    if (proc_config.use_direct_io) flags |= O_DIRECT;
    
    int fd = open(unit.device_path.c_str(), flags);
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string(strerror(errno)));
        if (proc_config.use_direct_io && errno == EINVAL) {
            log(LogLevel::Warning, LogEvent::DeviceOpenRetry, "sin O_DIRECT");
            flags &= ~O_DIRECT;
            fd = open(unit.device_path.c_str(), flags);
            if (fd < 0) return false;
            proc_config.use_direct_io = false;
        } else return false;
    }
    
    uint64_t total_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) { 
        log(LogLevel::Error, LogEvent::DeviceSizeFailed, std::string(strerror(errno)));
        close(fd); 
        return false; 
    }
    
    uint64_t total_sectors = total_size / SECTOR_SIZE;
    uint64_t data_start_sector = DATA_OFFSET_SECTORS;
    uint64_t data_sectors = total_sectors - data_start_sector;
    uint64_t data_size = data_sectors * SECTOR_SIZE;
    
    Botan::secure_vector<uint8_t> kdf_salt;
    Botan::secure_vector<uint8_t> xts_key;
    FSInfo fs_info = unit.fs_info;
    
    if (encrypt) {
        log(LogLevel::Info, LogEvent::SaltGenerating, "");
        kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
        if (kdf_salt.empty()) { 
            log(LogLevel::Error, LogEvent::SaltError, "");
            close(fd); 
            return false; 
        }
        
        log(LogLevel::Info, LogEvent::KeyDeriving, "");
        xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
        if (xts_key.empty()) { 
            log(LogLevel::Error, LogEvent::KeyDeriveError, "");
            close(fd); 
            return false; 
        }
        log(LogLevel::Success, LogEvent::KeyDerived, "");
        
        if (strlen(fs_info.fstype) == 0) fs_info = getFileSystemInfo(unit.device_path);
        
        EncUnitHdr hdr{};
        memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
        hdr.version = HEADER_VERSION_CURRENT;
        hdr.data_start_sector = data_start_sector;
        hdr.total_sectors = total_sectors;
        hdr.fs_info = fs_info;
        
        log(LogLevel::Info, LogEvent::KmacCalculating, "");
        try {
            KMACProc Kmac(master_key);
            auto Kmac_result = Kmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac));
            if (Kmac_result.size() == KMAC_SIZE) memcpy(hdr.Kmac, Kmac_result.data(), KMAC_SIZE);
            else { 
                log(LogLevel::Error, LogEvent::KmacError, "size mismatch");
                close(fd); 
                return false; 
            }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd); 
            return false;
        }
        
        if (backup_mgr.saveHeader(unit.device_path, hdr, master_key)) {
            log(LogLevel::Success, LogEvent::BackupSaved, "");
        } else {
            log(LogLevel::Warning, LogEvent::BackupSaveFailed, "");
        }
        
        log(LogLevel::Info, LogEvent::HeaderWriting, "");
        if (!writeHeaderToDevice(fd, hdr)) {
            log(LogLevel::Error, LogEvent::HeaderWriting, std::string(strerror(errno)));
            close(fd); 
            return false;
        }
        fsync(fd);
        log(LogLevel::Success, LogEvent::HeaderWritten, "");
    } else {
        EncUnitHdr hdr;
        log(LogLevel::Info, LogEvent::HeaderVerified, "reading");
        if (!readHeaderFromDevice(fd, hdr)) {
            log(LogLevel::Warning, LogEvent::HeaderReadFailed, "intentando backup");
            if (backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
                log(LogLevel::Success, LogEvent::BackupLoaded, "");
            } else { 
                log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
                close(fd); 
                return false; 
            }
        }
        
        if (hdr.version < 2) {
            log(LogLevel::Warning, LogEvent::KeyDerived, "version<2 sin KDF");
            xts_key.resize(64);
            memcpy(xts_key.data(), master_key.data(), 32);
            memcpy(xts_key.data() + 32, master_key.data(), 32);
        } else {
            log(LogLevel::Info, LogEvent::KeyDeriving, "");
            kdf_salt.resize(KDF_SALT_SIZE);
            memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { 
                log(LogLevel::Error, LogEvent::KeyDeriveError, "");
                close(fd); 
                return false; 
            }
            log(LogLevel::Success, LogEvent::KeyDerived, "");
        }
        
        log(LogLevel::Info, LogEvent::KmacCalculating, "verificando");
        try {
            KMACProc Kmac(master_key);
            if (!Kmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac), hdr.Kmac, KMAC_SIZE)) {
                log(LogLevel::Error, LogEvent::KmacFailed, "");
                close(fd); 
                return false;
            }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd); 
            return false;
        }
        log(LogLevel::Success, LogEvent::KmacVerified, "");
        
        fs_info = hdr.fs_info;
        data_start_sector = hdr.data_start_sector;
        data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
    }
    
    log(LogLevel::Info, LogEvent::DataSizeInfo, std::to_string(data_size));
    
    size_t chunk_size = proc_config.getChunkSize();
    uint64_t total_chunks = (data_size + chunk_size - 1) / chunk_size;
    
    log(LogLevel::Info, LogEvent::ChunkCountInfo, std::to_string(total_chunks));
    
    LimQueue<PipeChunk> read_queue(MAX_QUEUE_SIZE);
    LimQueue<PipeChunk> write_queue(MAX_QUEUE_SIZE);
    
    std::atomic<uint64_t> chunks_done{0};
    std::atomic<uint64_t> bytes_processed{0};
    std::atomic<bool> error{false};
    
    std::thread reader_thread([&]() {
        for (uint64_t c = 0; c < total_chunks && !error && !stop_requested; c++) {
            PipeChunk chunk(chunk_size, proc_config.use_direct_io);
            chunk.index = c;
            chunk.offset = (data_start_sector * SECTOR_SIZE) + (c * chunk_size);
            chunk.size = chunk_size;
            if (chunk.offset + chunk.size > total_size) chunk.size = total_size - chunk.offset;
            chunk.start_sector = chunk.offset / SECTOR_SIZE;
            
            ssize_t bytes_read = pread(fd, chunk.data->data(), chunk.size, chunk.offset);
            if (bytes_read != (ssize_t)chunk.size) {
                log(LogLevel::Error, LogEvent::ChunkReadError,
                    std::to_string(c) + ":" + strerror(errno));
                error = true;
                break;
            }
            read_queue.push(std::move(chunk));
        }
        read_queue.close();
    });
    
    int num_cpu_threads = (use_custom_config && custom_config.custom_mode) ? custom_config.crypto_threads : fixed_config.crypto_threads;
    std::vector<std::thread> cpu_threads;
    cpu_threads.reserve(num_cpu_threads);
    
    for (int t = 0; t < num_cpu_threads; t++) {
        cpu_threads.emplace_back([&, t]() {
            AESXTSProc proc(xts_key, encrypt);
            PipeChunk chunk(chunk_size, proc_config.use_direct_io);
            while (read_queue.pop(chunk) && !error && !stop_requested) {
                if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                    log(LogLevel::Error, LogEvent::ChunkProcessError, std::to_string(chunk.index));
                    error = true;
                    break;
                }
                write_queue.push(std::move(chunk));
                chunk = PipeChunk(chunk_size, proc_config.use_direct_io);
            }
        });
    }
    
    std::thread writer_thread([&]() {
        PipeChunk chunk(chunk_size, proc_config.use_direct_io);
        uint64_t expected_index = 0;
        std::vector<PipeChunk> out_of_order;
        
        while (!error && !stop_requested && expected_index < total_chunks) {
            if (write_queue.pop(chunk)) {
                if (chunk.index == expected_index) {
                    ssize_t bytes_written = pwrite(fd, chunk.data->data(), chunk.size, chunk.offset);
                    if (bytes_written != (ssize_t)chunk.size) {
                        log(LogLevel::Error, LogEvent::ChunkWriteError,
                            std::to_string(chunk.index) + ":" + strerror(errno));
                        error = true;
                        break;
                    }
                    chunks_done++;
                    bytes_processed += chunk.size;
                    speed_meter.addBytes(chunk.size);
                    progress(bytes_processed.load(), data_size, speed_meter.getCurrentSpeed());
                    expected_index++;
                    
                    int flush_interval = (unit.device_type == DevType::HDD || unit.device_type == DevType::USB2) ? 2 : 1;
                    if (chunk.index % flush_interval == 0) fsync(fd);
                    
                    auto it = out_of_order.begin();
                    while (it != out_of_order.end()) {
                        if (it->index == expected_index) {
                            bytes_written = pwrite(fd, it->data->data(), it->size, it->offset);
                            if (bytes_written != (ssize_t)it->size) { error = true; break; }
                            chunks_done++;
                            bytes_processed += it->size;
                            speed_meter.addBytes(it->size);
                            progress(bytes_processed.load(), data_size, speed_meter.getCurrentSpeed());
                            expected_index++;
                            it = out_of_order.erase(it);
                        } else ++it;
                    }
                } else if (chunk.index > expected_index) {
                    out_of_order.push_back(std::move(chunk));
                    chunk = PipeChunk(chunk_size, proc_config.use_direct_io);
                }
            }
        }
        write_queue.close();
    });
    
    while (!error && !stop_requested && chunks_done < total_chunks) {
        std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));
    }
    
    read_queue.close();
    write_queue.close();
    
    if (reader_thread.joinable()) reader_thread.join();
    for (auto& t : cpu_threads) if (t.joinable()) t.join();
    if (writer_thread.joinable()) writer_thread.join();
    
    fsync(fd);
    
    if (!encrypt && !error && !stop_requested) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(header_size, 0);
        if (pwrite(fd, zeros.data(), header_size, header_offset) == (ssize_t)header_size) {
            fsync(fd);
            log(LogLevel::Success, LogEvent::HeaderRemoved, "");
        }
        if (backup_mgr.removeBackup(unit.device_path)) {
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
        }
    }
    
    close(fd);
    stats.total_bytes = bytes_processed.load();
    
    if (error) {
        log(LogLevel::Error, LogEvent::ProcessingFailed, "");
    } else if (stop_requested) {
        log(LogLevel::Warning, LogEvent::ProcessingStopped, "");
    } else {
        log(LogLevel::Success, LogEvent::ProcessingComplete, "");
    }
    
    return !error && (chunks_done == total_chunks) && !stop_requested;
}

bool UnitEncryptor::cleanHeader(const StorUnit& unit) {
    log(LogLevel::Info, LogEvent::CleanupHeader, unit.device_path);
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { 
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
        return false; 
    }
    off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
    size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(header_size, 0);
    ssize_t written = pwrite(fd, zeros.data(), header_size, header_offset);
    fsync(fd);
    close(fd);
    if (written == (ssize_t)header_size) {
        log(LogLevel::Success, LogEvent::HeaderRemoved, "");
        if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
        return true;
    } else {
        log(LogLevel::Error, LogEvent::HeaderCleanFailed, "");
        return false;
    }
}

bool UnitEncryptor::restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, "");
    EncUnitHdr hdr;
    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
        return false;
    }
    if (!writeHeaderToDevice(fd, hdr)) {
        log(LogLevel::Error, LogEvent::HeaderRestoreFailed, "");
        close(fd);
        return false;
    }
    close(fd);
    log(LogLevel::Success, LogEvent::HeaderRestored, "");
    return true;
}

bool UnitEncryptor::formatUnit(const StorUnit& unit, const std::string& fstype) {
    log(LogLevel::Info, LogEvent::FormatStart, unit.device_path + ":" + fstype);
    
    int res = -1;
    if (fstype == "vfat" || fstype == "fat32") {
        res = safe_exec({"mkfs.vfat", "-F", "32", unit.device_path});
    } else if (fstype == "ntfs") {
        res = safe_exec({"mkfs.ntfs", "-f", unit.device_path});
    } else if (fstype == "ext4") {
        res = safe_exec({"mkfs.ext4", "-F", unit.device_path});
    } else {
        res = safe_exec({"mkfs." + fstype, unit.device_path});
    }
    
    if (res == 0) {
        log(LogLevel::Success, LogEvent::FormatOk, "");
        return true;
    }
    log(LogLevel::Error, LogEvent::FormatFailed, std::to_string(res));
    return false;
}
