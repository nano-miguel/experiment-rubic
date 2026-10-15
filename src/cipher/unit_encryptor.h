// cipher/unit_encryptor.h - 0.1 alpha
// Lógica pura. Los menús viven en ui/unit_encryptor_ui.h

#ifndef CIPHER_UNIT_ENCRYPTOR_H
#define CIPHER_UNIT_ENCRYPTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <random>
#include <algorithm>
#include <map>
#include <set>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <mntent.h>
#include <cpuid.h>
#include <errno.h>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <stdlib.h>
#include <x86intrin.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/kdf.h>
#include <botan/hash.h>

class KeyManager;

// ============================================
// COLORES (propios, con guard)
// ============================================
#ifndef CIPHER_UNIT_COLORS_DEFINED
#define CIPHER_UNIT_COLORS_DEFINED
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define BRIGHT_RED     "\033[91m"
#define BRIGHT_GREEN   "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#define BRIGHT_BLUE    "\033[94m"
#define BRIGHT_MAGENTA "\033[95m"
#define BRIGHT_CYAN    "\033[96m"
#define BRIGHT_WHITE   "\033[97m"
#endif

// CONSTANTES DE TAMAÑO
#define SECTOR_SIZE 512ULL
#define HEADER_OFFSET_SECTORS 2048ULL
#define HEADER_SECTORS 8ULL
#define DATA_OFFSET_SECTORS (HEADER_OFFSET_SECTORS + HEADER_SECTORS)
#define MIN_THREADS 1
#define MAX_THREADS 128
#define PROGRESS_UPDATE_MS 200
#define GB (1024ULL*1024ULL*1024ULL)
#define MB (1024ULL*1024ULL)
#define ALIGNMENT 4096ULL
#define HMAC_SIZE 64
#define KDF_SALT_SIZE 64
#define KEY_DERIVATION_INFO "RUBI-C-AES-XTS-KEY-V1-OFFSET-1MB"
#define PIPELINE_DEPTH 3
#define MAX_QUEUE_SIZE 2
#define HEADER_VERSION_CURRENT 3

// VERIFICACIÓN DE PERMISOS 
// NOTA: la version original imprimia. Aquí solo comprueba.
inline bool isRoot() {
    return geteuid() == 0;
}

// DETECCIÓN DE HARDWARE 
class HWDetect {
public:
    static bool hasAESNI() { static bool aesni = check_aesni(); return aesni; }
    static bool hasAVX2() { static bool avx2 = check_avx2(); return avx2; }
    static bool hasAVX512() { static bool avx512 = check_avx512(); return avx512; }
    static int getCoreCount() { static int cores = std::thread::hardware_concurrency(); return cores > 0 ? cores : 4; }
    static std::string getCPUInfo() {
        std::stringstream ss;
        ss << "Núcleos: " << getCoreCount();
        if (hasAESNI()) ss << " | AES-NI: ✓";
        if (hasAVX2()) ss << " | AVX2: ✓";
        if (hasAVX512()) ss << " | AVX-512: ✓";
        return ss.str();
    }
    static size_t getOptimalAlignment() { return ALIGNMENT; }
    static const char* getSIMDLevel() {
        if (hasAVX512()) return "AVX-512";
        if (hasAVX2()) return "AVX2";
        return "SSE";
    }
private:
    static bool check_aesni() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 1) {
            __cpuid_count(1, 0, eax, ebx, ecx, edx);
            return (ecx & (1 << 25)) != 0;
        }
        return false;
    }
    static bool check_avx2() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 7) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            return (ebx & (1 << 5)) != 0;
        }
        return false;
    }
    static bool check_avx512() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 7) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            return (ebx & ((1 << 16) | (1 << 30))) == ((1 << 16) | (1 << 30));
        }
        return false;
    }
};

// DERIVACIÓN DE CLAVES
class KeyDeriv {
public:
    static Botan::secure_vector<uint8_t> deriveSubKey(
        const Botan::secure_vector<uint8_t>& master_key,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_length = 64) {
        try {
            auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
            Botan::secure_vector<uint8_t> derived_key(key_length);
            std::vector<uint8_t> secret(master_key.begin(), master_key.end());
            std::vector<uint8_t> salt_vec(salt.begin(), salt.end());
            std::vector<uint8_t> info(reinterpret_cast<const uint8_t*>(KEY_DERIVATION_INFO),
                                       reinterpret_cast<const uint8_t*>(KEY_DERIVATION_INFO) + strlen(KEY_DERIVATION_INFO));
            kdf->derive_key(derived_key, secret, salt_vec, info);
            return derived_key;
        } catch (const std::exception& e) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static Botan::secure_vector<uint8_t> generateSalt(size_t size = KDF_SALT_SIZE) {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> salt(size);
            rng.randomize(salt.data(), salt.size());
            return salt;
        } catch (const std::exception& e) {
            return Botan::secure_vector<uint8_t>();
        }
    }
};

// CONFIGURACIÓN
struct CustCfg {
    size_t buffer_size_mb;
    int io_threads;
    int crypto_threads;
    bool use_direct_io;
    bool custom_mode;
    
    CustCfg() : buffer_size_mb(64), io_threads(2), crypto_threads(4), 
                use_direct_io(true), custom_mode(false) {}
    
    void loadFromFile(const std::string& filename) {
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
    
    void saveToFile(const std::string& filename) {
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
    
    // NOTA: show() y configure() viven en la UI
};

// BUFFER PARA I/O DIRECTO
class AlignBuf {
private:
    void* data_ptr;
    size_t size_bytes;
public:
    AlignBuf(size_t size);
    ~AlignBuf();
    AlignBuf(AlignBuf&& other) noexcept;
    AlignBuf& operator=(AlignBuf&& other) noexcept;
    AlignBuf(const AlignBuf&) = delete;
    AlignBuf& operator=(const AlignBuf&) = delete;
    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
};

inline AlignBuf::AlignBuf(size_t size) : data_ptr(nullptr), size_bytes(size) {
    if (posix_memalign(&data_ptr, ALIGNMENT, size) != 0) throw std::bad_alloc();
    memset(data_ptr, 0, size);
}

inline AlignBuf::~AlignBuf() { if (data_ptr) free(data_ptr); }

inline AlignBuf::AlignBuf(AlignBuf&& other) noexcept : data_ptr(other.data_ptr), size_bytes(other.size_bytes) {
    other.data_ptr = nullptr;
    other.size_bytes = 0;
}

inline AlignBuf& AlignBuf::operator=(AlignBuf&& other) noexcept {
    if (this != &other) {
        if (data_ptr) free(data_ptr);
        data_ptr = other.data_ptr;
        size_bytes = other.size_bytes;
        other.data_ptr = nullptr;
        other.size_bytes = 0;
    }
    return *this;
}

inline uint8_t* AlignBuf::data() { return static_cast<uint8_t*>(data_ptr); }
inline const uint8_t* AlignBuf::data() const { return static_cast<const uint8_t*>(data_ptr); }
inline size_t AlignBuf::size() const { return size_bytes; }

// PROCESAMIENTO AVX2/AVX-512
class SIMDProc {
public:
    static void xor_blocks(uint8_t* dst, const uint8_t* src, size_t blocks) {
        size_t i = 0;
        size_t total_bytes = blocks * 16;
#ifdef __AVX512F__
        if (HWDetect::hasAVX512()) {
            for (; i + 64 <= total_bytes; i += 64) {
                __m512i vdst = _mm512_loadu_si512((__m512i*)(dst + i));
                __m512i vsrc = _mm512_loadu_si512((__m512i*)(src + i));
                vdst = _mm512_xor_si512(vdst, vsrc);
                _mm512_storeu_si512((__m512i*)(dst + i), vdst);
            }
        } else 
#endif
#ifdef __AVX2__
        if (HWDetect::hasAVX2()) {
            for (; i + 32 <= total_bytes; i += 32) {
                __m256i vdst = _mm256_loadu_si256((__m256i*)(dst + i));
                __m256i vsrc = _mm256_loadu_si256((__m256i*)(src + i));
                vdst = _mm256_xor_si256(vdst, vsrc);
                _mm256_storeu_si256((__m256i*)(dst + i), vdst);
            }
        } else 
#endif
        {
            for (; i + 16 <= total_bytes; i += 16) {
                __m128i vdst = _mm_loadu_si128((__m128i*)(dst + i));
                __m128i vsrc = _mm_loadu_si128((__m128i*)(src + i));
                vdst = _mm_xor_si128(vdst, vsrc);
                _mm_storeu_si128((__m128i*)(dst + i), vdst);
            }
        }
        for (; i < total_bytes; i++) dst[i] ^= src[i];
    }
    
    static void fill_tweak(uint8_t* tweak, uint64_t start_sector, size_t num_blocks) {
        for (size_t i = 0; i < num_blocks; i++) {
            uint64_t sector = start_sector + i;
            memcpy(tweak + i * 16, &sector, 8);
            memset(tweak + i * 16 + 8, 0, 8);
        }
    }
};

// DETECTOR DE TIPO DE DISPOSITIVO
enum class DevType {
    UNKNOWN, USB2, USB3, NVME, SSD_SATA, HDD, SD_CARD
};

class DevDetect {
private:
    static std::string getSysPath(const std::string& device) {
        std::string devname = device;
        if (devname.find("/dev/") == 0) devname = devname.substr(5);
        while (!devname.empty() && isdigit(devname.back())) devname.pop_back();
        return "/sys/block/" + devname;
    }
    
    static bool checkUSB(const std::string& syspath) {
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
    
    static std::string readSpeed(const std::string& syspath) {
        std::string speed_file = syspath + "/device/speed";
        FILE* f = fopen(speed_file.c_str(), "r");
        if (!f) return "";
        char speed[32];
        if (fgets(speed, sizeof(speed), f)) { speed[strcspn(speed, "\n")] = 0; fclose(f); return speed; }
        fclose(f);
        return "";
    }
    
    static bool checkNVMe(const std::string& device) { return device.find("nvme") != std::string::npos; }
    static bool checkSD(const std::string& device) { return device.find("mmcblk") != std::string::npos; }
    
    static bool isRemovable(const std::string& syspath) {
        std::string removable_file = syspath + "/removable";
        FILE* f = fopen(removable_file.c_str(), "r");
        if (f) { char rem; if (fscanf(f, "%c", &rem) == 1) { fclose(f); return (rem == '1'); } fclose(f); }
        return false;
    }
    
public:
    static DevType detect(const std::string& device) {
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
    
    static std::string devTypeToStr(DevType type) {
        switch(type) {
            case DevType::USB2: return "USB 2.0";
            case DevType::USB3: return "USB 3.0";
            case DevType::NVME: return "NVMe SSD";
            case DevType::SSD_SATA: return "SSD SATA";
            case DevType::HDD: return "HDD";
            case DevType::SD_CARD: return "Tarjeta SD";
            default: return "Desconocido";
        }
    }
    
    static const char* devTypeColor(DevType type) {
        switch(type) {
            case DevType::NVME: return BRIGHT_GREEN;
            case DevType::USB3: return BRIGHT_CYAN;
            case DevType::SSD_SATA: return BRIGHT_BLUE;
            case DevType::USB2: return YELLOW;
            case DevType::HDD: return BRIGHT_YELLOW;
            case DevType::SD_CARD: return MAGENTA;
            default: return RESET;
        }
    }
    
    static size_t getOptimalChunkMB(DevType type) {
        switch(type) {
            case DevType::HDD: return 128;
            case DevType::USB2: return 128;
            case DevType::USB3: return 64;
            case DevType::SSD_SATA: return 64;
            case DevType::NVME: return 64;
            case DevType::SD_CARD: return 64;
            default: return 64;
        }
    }
    
    static bool useDirectIO(DevType type) {
        switch(type) {
            case DevType::USB2:
            case DevType::SD_CARD: return false;
            default: return true;
        }
    }
};

// CONFIGURACIÓN DE HILOS
struct FixedThCfg {
    int io_threads;
    int crypto_threads;
    int reserved_os;
    
    FixedThCfg() : io_threads(1), crypto_threads(1), reserved_os(0) {}
    
    static FixedThCfg getConfigForSystem() {
        FixedThCfg config;
        int system_threads = HWDetect::getCoreCount();
        int available_threads = system_threads > 1 ? system_threads - 1 : system_threads;
        if (available_threads <= 1) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
        else if (available_threads <= 2) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
        else if (available_threads <= 4) { config.io_threads = 1; config.crypto_threads = 2; config.reserved_os = 1; }
        else if (available_threads <= 8) { config.io_threads = 2; config.crypto_threads = 5; config.reserved_os = 1; }
        else if (available_threads <= 16) { config.io_threads = 3; config.crypto_threads = 11; config.reserved_os = 2; }
        else if (available_threads <= 32) { config.io_threads = 4; config.crypto_threads = 24; config.reserved_os = 4; }
        else { config.io_threads = 6; config.crypto_threads = available_threads - 8; config.reserved_os = 2; }
        return config;
    }
};

struct ThCfg {
    int num_threads;
    size_t chunk_size_mb;
    bool use_direct_io;
    
    ThCfg() { num_threads = HWDetect::getCoreCount(); chunk_size_mb = 64; use_direct_io = true; }
    
    void applyFixedConfig(const FixedThCfg& fixed_cfg, DevType device_type) {
        num_threads = fixed_cfg.io_threads + fixed_cfg.crypto_threads + fixed_cfg.reserved_os;
        chunk_size_mb = DevDetect::getOptimalChunkMB(device_type);
        use_direct_io = DevDetect::useDirectIO(device_type);
    }
    
    void applyCustomConfig(const CustCfg& custom_cfg) {
        num_threads = custom_cfg.io_threads + custom_cfg.crypto_threads;
        chunk_size_mb = custom_cfg.buffer_size_mb;
        use_direct_io = custom_cfg.use_direct_io;
    }
    
    void validate() {
        if (num_threads < MIN_THREADS) num_threads = MIN_THREADS;
        if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
        if (chunk_size_mb < 1) chunk_size_mb = 1;
        if (chunk_size_mb > 1024) chunk_size_mb = 1024;
        size_t chunk_bytes = chunk_size_mb * MB;
        if (chunk_bytes % ALIGNMENT != 0) chunk_size_mb = ((chunk_bytes + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT / MB;
    }
    
    size_t getChunkSize() const {
        size_t size = chunk_size_mb * MB;
        if (size % ALIGNMENT != 0) size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
        return size;
    }
    
    std::string getDesc() const {
        std::stringstream ss;
        ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
        if (use_direct_io) ss << " | I/O DIRECTO";
        return ss.str();
    }
};

// MEDIDOR DE VELOCIDAD
class SpeedMtr {
private:
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_time;
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> last_bytes{0};
    std::atomic<double> current_speed{0};
    std::atomic<double> peak_speed{0};
    
public:
    SpeedMtr() { reset(); }
    void addBytes(uint64_t bytes) { total_bytes += bytes; }
    double getCurrentSpeed() {
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
    double getAvgSpeed() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        return elapsed > 0 ? (total_bytes / 1048576.0) / (elapsed / 1000.0) : 0;
    }
    double getPeakSpeed() { return peak_speed.load(); }
    uint64_t getTotalBytes() { return total_bytes.load(); }
    void reset() {
        start_time = std::chrono::steady_clock::now();
        last_time = start_time;
        total_bytes = 0;
        last_bytes = 0;
        current_speed = 0;
        peak_speed = 0;
    }
};

// INFORMACIÓN DEL SISTEMA DE ARCHIVOS
struct FSInfo {
    char fstype[32];
    char uuid[64];
    char label[256];
    FSInfo() { memset(fstype, 0, sizeof(fstype)); memset(uuid, 0, sizeof(uuid)); memset(label, 0, sizeof(label)); }
};

// HEADER 
#pragma pack(push, 1)
struct EncUnitHdr {
    uint8_t kdf_salt[KDF_SALT_SIZE];
    uint32_t version;
    uint64_t data_start_sector;
    uint64_t total_sectors;
    FSInfo fs_info;
    uint8_t hmac[HMAC_SIZE];
    
    bool isValid() const {
        if (version < 2 || version > HEADER_VERSION_CURRENT) return false;
        if (data_start_sector < HEADER_OFFSET_SECTORS + HEADER_SECTORS) return false;
        if (data_start_sector > total_sectors) return false;
        bool all_zero = true;
        for (size_t i = 0; i < KDF_SALT_SIZE; i++) {
            if (kdf_salt[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) return false;
        if (strlen(fs_info.fstype) > 31) return false;
        if (strlen(fs_info.label) > 255) return false;
        return true;
    }
};
#pragma pack(pop)

// GESTOR DE BACKUP
class HdrBackup {
private:
    std::string getBackupPath(const std::string& device_path) {
        std::string devname = device_path;
        if (devname.find("/dev/") == 0) devname = devname.substr(5);
        std::replace(devname.begin(), devname.end(), '/', '_');
        std::string hashed = std::to_string(std::hash<std::string>{}(devname));
        return "/var/tmp/.rubic_" + hashed + ".dat";
    }
    
    Botan::secure_vector<uint8_t> encryptBackup(const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
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
    
    bool decryptBackup(const std::string& backup_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
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
    
    Botan::secure_vector<uint8_t> deriveBackupKey(const std::string& device_path) {
        Botan::secure_vector<uint8_t> key(32);
        auto hash = Botan::HashFunction::create("SHA-512");
        if (!hash) return {};
        hash->update(device_path);
        auto digest = hash->final();
        for (size_t i = 0; i < 32; i++) key[i] = digest[i];
        return key;
    }
    
public:
    bool saveHeader(const std::string& device_path, const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
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
    
    bool loadHeader(const std::string& device_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
        auto backup_key = deriveBackupKey(device_path);
        std::string backup_path = getBackupPath(device_path);
        return decryptBackup(backup_path, header, backup_key);
    }
    
    bool backupExists(const std::string& device_path) {
        std::string backup_path = getBackupPath(device_path);
        struct stat st;
        return (stat(backup_path.c_str(), &st) == 0);
    }
    
    bool removeBackup(const std::string& device_path) {
        std::string backup_path = getBackupPath(device_path);
        return (unlink(backup_path.c_str()) == 0);
    }
};

// ESTRUCTURA DE UNIDAD
struct StorUnit {
    std::string device_path;
    std::string mount_point;
    std::string label;
    std::string uuid;
    uint64_t total_size;
    std::string filesystem;
    bool is_mounted;
    bool is_encrypted;
    bool is_partition;
    bool is_system_disk;
    std::string parent_device;
    FSInfo fs_info;
    DevType device_type;
    bool has_header_backup;
    
    StorUnit() : total_size(0), is_mounted(false), is_encrypted(false), 
                 is_partition(false), is_system_disk(false), 
                 device_type(DevType::UNKNOWN), has_header_backup(false) {}
    
    std::string getSizeStr() const { return formatBytes(total_size); }
    std::string getDevTypeStr() const { return DevDetect::devTypeToStr(device_type); }
    const char* getDevTypeColor() const { return DevDetect::devTypeColor(device_type); }
    
    static std::string formatBytes(uint64_t bytes) {
        const char* sizes[] = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double dbl = bytes;
        while (dbl >= 1024.0 && i < 4) { dbl /= 1024.0; i++; }
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << dbl << " " << sizes[i];
        return ss.str();
    }
    
    std::string getSafeFSType() const {
        if (strlen(fs_info.fstype) > 0) {
            bool valid = true;
            for (size_t i = 0; i < strlen(fs_info.fstype); i++) {
                if (!isprint(fs_info.fstype[i])) { valid = false; break; }
            }
            if (valid) return std::string(fs_info.fstype);
        }
        return "";
    }
};

// BUFFER-sec
class SecBuf {
private:
    Botan::secure_vector<uint8_t> buffer_data;
    std::unique_ptr<AlignBuf> aligned_cache;
    bool use_aligned;
    
public:
    SecBuf(size_t size, bool aligned_mode = false) : use_aligned(aligned_mode) {
        if (use_aligned) aligned_cache = std::make_unique<AlignBuf>(size);
        else buffer_data.resize(size);
    }
    uint8_t* data() { return use_aligned ? aligned_cache->data() : buffer_data.data(); }
    const uint8_t* data() const { return use_aligned ? aligned_cache->data() : buffer_data.data(); }
    size_t size() const { return use_aligned ? aligned_cache->size() : buffer_data.size(); }
    uint8_t* secure_data() { return buffer_data.data(); }
    void sync_from_aligned() { if (use_aligned && !buffer_data.empty()) memcpy(buffer_data.data(), aligned_cache->data(), buffer_data.size()); }
    void sync_to_aligned() { if (use_aligned && !buffer_data.empty()) memcpy(aligned_cache->data(), buffer_data.data(), buffer_data.size()); }
};

// PROCESADOR HMAC
class HMACProc {
private:
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
    Botan::secure_vector<uint8_t> key;
    
public:
    HMACProc(const Botan::secure_vector<uint8_t>& key_data) {
        key = key_data;
        hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
        if (!hmac) throw std::runtime_error("No se pudo crear HMAC-SHA512");
        hmac->set_key(key);
    }
    Botan::secure_vector<uint8_t> calculate(const uint8_t* data, size_t size) {
        hmac->update(data, size);
        return hmac->final();
    }
    bool verify(const uint8_t* data, size_t size, const uint8_t* expected_hmac, size_t hmac_size) {
        auto calculated = calculate(data, size);
        if (calculated.size() != hmac_size) return false;
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < hmac_size; i++) diff |= (calculated[i] ^ expected_hmac[i]);
        return diff == 0;
    }
};

// PROCESADOR AES-XTS
class AESXTSProc {
private:
    std::unique_ptr<Botan::Cipher_Mode> cipher;
    Botan::secure_vector<uint8_t> key;
    Botan::secure_vector<uint8_t> tweak_buffer;
    Botan::secure_vector<uint8_t> sector_buffer;
    size_t sector_buffer_size;
    
public:
    AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt) {
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
    
    bool processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
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
    
    bool processSecBuf(SecBuf& buffer, uint64_t start_sector) {
        return processBuffer(buffer.data(), buffer.size(), start_sector);
    }
};

// PIPELINE CHUNK
struct PipeChunk {
    uint64_t index;
    uint64_t offset;
    uint64_t size;
    uint64_t start_sector;
    std::unique_ptr<SecBuf> data;
    
    PipeChunk(size_t chunk_size, bool use_direct_io) : index(0), offset(0), size(0), start_sector(0) {
        data = std::make_unique<SecBuf>(chunk_size, use_direct_io);
    }
    PipeChunk(PipeChunk&& other) noexcept : index(other.index), offset(other.offset), size(other.size), 
        start_sector(other.start_sector), data(std::move(other.data)) {}
    void operator=(PipeChunk&& other) noexcept {
        index = other.index; offset = other.offset; size = other.size;
        start_sector = other.start_sector; data = std::move(other.data);
    }
    PipeChunk(const PipeChunk&) = delete;
    PipeChunk& operator=(const PipeChunk&) = delete;
};

// LIMITED QUEUE
template<typename T>
class LimQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable not_full;
    std::condition_variable not_empty;
    size_t max_size;
    bool closed = false;
    
public:
    LimQueue(size_t max) : max_size(max) {}
    void push(T&& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_full.wait(lock, [this] { return queue.size() < max_size || closed; });
        if (closed) return;
        queue.push(std::move(item));
        not_empty.notify_one();
    }
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_empty.wait(lock, [this] { return !queue.empty() || closed; });
        if (queue.empty()) return false;
        item = std::move(queue.front());
        queue.pop();
        not_full.notify_one();
        return true;
    }
    void close() {
        std::lock_guard<std::mutex> lock(mutex);
        closed = true;
        not_full.notify_all();
        not_empty.notify_all();
    }
    size_t size() { std::lock_guard<std::mutex> lock(mutex); return queue.size(); }
};

// ============================================
// CLASE PRINCIPAL UnitEncryptor (sin UI)
// ============================================

class UnitEncryptor {
public:
    using LogCallback = std::function<void(const std::string& msg)>;
    using ProgressCallback = std::function<void(uint64_t current_bytes, uint64_t total_bytes, double speed_mbps)>;
    
private:
    KeyManager* keyManager = nullptr;
    std::string currentKeyName;
    
    Botan::secure_vector<uint8_t> directKey;
    bool useDirectKey = false;
    
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> processing_active{false};
    SpeedMtr speed_meter;
    FixedThCfg fixed_config;
    CustCfg custom_config;
    bool use_custom_config;
    HdrBackup backup_mgr;
    std::vector<StorUnit> cached_units;
    time_t last_refresh;
    
    LogCallback log_cb_;
    ProgressCallback progress_cb_;
    
    void log(const std::string& msg) { if (log_cb_) log_cb_(msg); }
    void progress(uint64_t cur, uint64_t total, double speed) {
        if (progress_cb_) progress_cb_(cur, total, speed);
    }
    
    struct Stats {
        uint64_t total_bytes = 0;
        uint64_t total_time_ms = 0;
        uint64_t errors = 0;
    } stats;
    
    void refreshUnits() {
        time_t now = time(nullptr);
        if (now - last_refresh > 2) {
            cached_units = detectUnits();
            last_refresh = now;
        }
    }
    
    bool isPhysicalDevice(const std::string& path) {
        if (path.find("/dev/loop") != std::string::npos) return false;
        if (path.find("/dev/ram") != std::string::npos) return false;
        return true;
    }
    
    std::string getParentDevice(const std::string& path) {
        std::string dev = path.substr(5);
        size_t p = dev.find_first_of("0123456789");
        if (p != std::string::npos) return "/dev/" + dev.substr(0, p);
        return "";
    }
    
    bool isSystemDisk(const std::string& path) {
        FILE* fp = popen("df / | tail -1 | awk '{print $1}'", "r");
        if (!fp) return false;
        char buf[256];
        if (!fgets(buf, sizeof(buf), fp)) { pclose(fp); return false; }
        pclose(fp);
        std::string root_dev = buf;
        if (!root_dev.empty() && root_dev.back() == '\n') root_dev.pop_back();
        return (path == root_dev);
    }
    
    FSInfo getFileSystemInfo(const std::string& path) {
        FSInfo info;
        FILE* fp = popen(("blkid -o value -s TYPE " + path + " 2>/dev/null").c_str(), "r");
        if (fp) {
            if (fgets(info.fstype, sizeof(info.fstype), fp)) {
                info.fstype[strcspn(info.fstype, "\n")] = 0;
            }
            pclose(fp);
        }
        fp = popen(("blkid -o value -s LABEL " + path + " 2>/dev/null").c_str(), "r");
        if (fp) {
            if (fgets(info.label, sizeof(info.label), fp)) {
                info.label[strcspn(info.label, "\n")] = 0;
            }
            pclose(fp);
        }
        return info;
    }
    
    bool isUnitEncrypted(const std::string& device_path) {
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
    
    bool readHeaderFromDevice(int fd, EncUnitHdr& hdr) {
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        ssize_t read_bytes = pread(fd, &hdr, sizeof(hdr), header_offset);
        if (read_bytes != sizeof(hdr)) return false;
        return hdr.isValid();
    }
    
    bool writeHeaderToDevice(int fd, const EncUnitHdr& hdr) {
        int flags = fcntl(fd, F_GETFL);
        if (flags == -1) return false;
        bool was_direct = (flags & O_DIRECT);
        if (was_direct) { int new_flags = flags & ~O_DIRECT; fcntl(fd, F_SETFL, new_flags); }
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        ssize_t written = pwrite(fd, &hdr, sizeof(hdr), header_offset);
        if (was_direct) fcntl(fd, F_SETFL, flags);
        return (written == sizeof(hdr));
    }
    
    std::vector<StorUnit> detectUnits() {
        std::vector<StorUnit> units;
        std::map<std::string, StorUnit> unique_by_device;
        std::set<std::string> seen_devices;
        
        std::string root_dev;
        FILE* fp = popen("df / | tail -1 | awk '{print $1}'", "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp)) { buf[strcspn(buf, "\n")] = 0; root_dev = buf; }
            pclose(fp);
        }
        
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (mounts) {
            struct mntent* ent;
            while ((ent = getmntent(mounts))) {
                std::string dev = ent->mnt_fsname;
                if (dev.find("/dev/") == 0 && isPhysicalDevice(dev)) {
                    
                    StorUnit u;
                    u.device_path = dev;
                    u.mount_point = ent->mnt_dir;
                    u.filesystem = ent->mnt_type;
                    u.is_mounted = true;
                    u.is_partition = (dev.find_first_of("0123456789") != std::string::npos);
                    u.parent_device = getParentDevice(dev);
                    u.is_system_disk = (dev == root_dev);
                    
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        if (ioctl(fd, BLKGETSIZE64, &u.total_size) != 0) u.total_size = 0;
                        
                        u.is_encrypted = isUnitEncrypted(dev);
                        if (u.is_encrypted) {
                            EncUnitHdr hdr;
                            if (readHeaderFromDevice(fd, hdr)) {
                                u.fs_info = hdr.fs_info;
                            }
                        }
                        close(fd);
                    }
                    
                    if (!u.is_encrypted) {
                        u.fs_info = getFileSystemInfo(dev);
                        u.label = u.fs_info.label;
                    } else {
                        u.label = u.fs_info.label;
                    }
                    
                    u.device_type = DevDetect::detect(dev);
                    u.has_header_backup = backup_mgr.backupExists(dev);
                    
                    std::string key = dev;
                    unique_by_device[key] = u;
                    seen_devices.insert(dev);
                }
            }
            endmntent(mounts);
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
                    
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        if (ioctl(fd, BLKGETSIZE64, &u.total_size) != 0) u.total_size = 0;
                        
                        u.is_encrypted = isUnitEncrypted(dev);
                        if (u.is_encrypted) {
                            EncUnitHdr hdr;
                            if (readHeaderFromDevice(fd, hdr)) {
                                u.fs_info = hdr.fs_info;
                            }
                        }
                        close(fd);
                    }
                    
                    if (u.total_size > 0) {
                        if (!u.is_encrypted) {
                            u.fs_info = getFileSystemInfo(dev);
                            u.label = u.fs_info.label;
                        } else {
                            u.label = u.fs_info.label;
                        }
                        
                        u.device_type = DevDetect::detect(dev);
                        u.has_header_backup = backup_mgr.backupExists(dev);
                        
                        std::string key = dev;
                        unique_by_device[key] = u;
                    }
                }
            }
            closedir(dir);
        }
        
        for (auto& pair : unique_by_device) {
            units.push_back(pair.second);
        }
        
        std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
            if (a.is_system_disk != b.is_system_disk) return a.is_system_disk > b.is_system_disk;
            return a.total_size > b.total_size;
        });
        
        return units;
    }
    
    bool unmount(StorUnit& u) {
        if (!u.is_mounted) return true;
        log("Desmontando " + u.mount_point + "...");
        std::string cmd = "umount -l \"" + u.mount_point + "\" 2>/dev/null";
        int ret = system(cmd.c_str()); (void)ret;
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (mounts) {
            struct mntent* ent;
            while ((ent = getmntent(mounts))) {
                if (u.device_path == ent->mnt_fsname) { endmntent(mounts); return false; }
            }
            endmntent(mounts);
        }
        u.is_mounted = false;
        u.mount_point.clear();
        log("✓ Desmontado");
        return true;
    }
    
    bool mount(const StorUnit& u, const std::string& point) {
        log("Montando en " + point + "...");
        std::string mkdir_cmd = "mkdir -p \"" + point + "\" 2>/dev/null";
        int ret = system(mkdir_cmd.c_str()); (void)ret;
        std::string fs = u.filesystem;
        if (fs.empty() && strlen(u.fs_info.fstype) > 0) {
            std::string safe_fs = u.getSafeFSType();
            if (!safe_fs.empty()) fs = safe_fs;
        }
        std::string cmd;
        if (!fs.empty()) cmd = "mount -t " + fs + " " + u.device_path + " \"" + point + "\" 2>/dev/null";
        else cmd = "mount " + u.device_path + " \"" + point + "\" 2>/dev/null";
        ret = system(cmd.c_str());
        if (ret == 0) { log("✓ Montada en " + point); return true; }
        log("✗ Error (código: " + std::to_string(ret) + ")");
        return false;
    }
    
public:
    UnitEncryptor() : keyManager(nullptr), use_custom_config(false), last_refresh(0), useDirectKey(false) {
        fixed_config = FixedThCfg::getConfigForSystem();
        custom_config.loadFromFile("rubic_config.cfg");
        use_custom_config = custom_config.custom_mode;
        refreshUnits();
    }
    
    void setLogCallback(LogCallback cb) { log_cb_ = std::move(cb); }
    void setProgressCallback(ProgressCallback cb) { progress_cb_ = std::move(cb); }
    
    void setKeyManager(KeyManager* km) { 
        keyManager = km; 
        useDirectKey = false;
    }
    
    void setDirectKey(const Botan::secure_vector<uint8_t>& key) {
        directKey = key;
        useDirectKey = true;
        keyManager = nullptr;
    }
    
    void setDirectKeyHex(const std::string& hexKey) {
        try {
            Botan::secure_vector<uint8_t> key(32);
            for (size_t i = 0; i < 32 && i + 1 < hexKey.length(); i += 2) {
                key[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
            }
            directKey = key;
            useDirectKey = true;
            keyManager = nullptr;
        } catch (...) {
            useDirectKey = false;
        }
    }
    
    bool hasKey() const {
        if (useDirectKey) return !directKey.empty();
        return keyManager != nullptr && !keyManager->getActiveKeys().empty();
    }
    
    std::vector<StorUnit> getUnits() {
        refreshUnits();
        return cached_units;
    }
    
    void refresh() {
        cached_units = detectUnits();
        last_refresh = time(nullptr);
    }
    
    CustCfg& getCustomConfig() { return custom_config; }
    FixedThCfg& getFixedConfig() { return fixed_config; }
    bool& getUseCustomConfig() { return use_custom_config; }
    
    const CustCfg& getCustomConfig() const { return custom_config; }
    const FixedThCfg& getFixedConfig() const { return fixed_config; }
    bool getUseCustomConfig() const { return use_custom_config; }
    
    void reloadCustomConfig() {
        custom_config.loadFromFile("rubic_config.cfg");
        use_custom_config = custom_config.custom_mode;
    }
    
    bool processUnit(StorUnit& unit, bool encrypt, 
                     const Botan::secure_vector<uint8_t>& master_key) {
        if (!isRoot()) return false;
        
        if (encrypt && unit.is_encrypted) { 
            log("La unidad ya está cifrada"); 
            return false; 
        }
        if (!encrypt && !unit.is_encrypted) { 
            log("La unidad no está cifrada"); 
            return false; 
        }
        if (unit.is_system_disk) { 
            log("⚠ NO SE PUEDE CIFRAR EL DISCO DEL SISTEMA"); 
            return false; 
        }
        if (unit.is_mounted) {
            log("⚠ La unidad está montada");
            return false;
        }
        
        if (master_key.empty() || master_key.size() != 32) {
            log("No se pudo obtener la clave maestra");
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
            
            std::stringstream ss;
            ss << "\n┌─[ESTADÍSTICAS]─────────────────────────────────────────┐\n";
            ss << "│ Total: " << StorUnit::formatBytes(stats.total_bytes) << "\n";
            ss << "│ Tiempo: " << (stats.total_time_ms / 1000) << "s\n";
            ss << "│ Velocidad: " << std::fixed << std::setprecision(2) << speed_meter.getAvgSpeed() << " MB/s";
            ss << " (pico: " << std::fixed << std::setprecision(2) << speed_meter.getPeakSpeed() << " MB/s)\n";
            ss << "└────────────────────────────────────────────────────────┘";
            log(ss.str());
            
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            refreshUnits();
        }
        return ok;
    }
    
    bool doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
        ThCfg proc_config;
        if (use_custom_config && custom_config.custom_mode) proc_config.applyCustomConfig(custom_config);
        else proc_config.applyFixedConfig(fixed_config, unit.device_type);
        proc_config.validate();
        
        std::stringstream ss;
        ss << "Tipo detectado: " << unit.getDevTypeStr() << "\n";
        if (use_custom_config && custom_config.custom_mode) {
            ss << "Modo: PERSONALIZADO\n";
            ss << "  Buffer: " << custom_config.buffer_size_mb << " MB\n";
            ss << "  I/O Threads: " << custom_config.io_threads << "\n";
            ss << "  Crypto Threads: " << custom_config.crypto_threads << "\n";
        } else {
            ss << "Modo: AUTOMÁTICO\n";
            ss << "  I/O Threads: " << fixed_config.io_threads << "\n";
            ss << "  Crypto Threads: " << fixed_config.crypto_threads << "\n";
        }
        ss << "Chunk: " << proc_config.chunk_size_mb << " MB\n";
        ss << "Modo I/O: " << (proc_config.use_direct_io ? "DIRECTO" : "NORMAL");
        log(ss.str());
        
        int flags = O_RDWR | O_SYNC;
        if (proc_config.use_direct_io) flags |= O_DIRECT;
        
        int fd = open(unit.device_path.c_str(), flags);
        if (fd < 0) {
            log(std::string("No se puede abrir: ") + strerror(errno));
            if (proc_config.use_direct_io && errno == EINVAL) {
                log("Reintentando sin O_DIRECT...");
                flags &= ~O_DIRECT;
                fd = open(unit.device_path.c_str(), flags);
                if (fd < 0) return false;
                proc_config.use_direct_io = false;
            } else return false;
        }
        
        uint64_t total_size = 0;
        if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) { 
            log("Error obteniendo tamaño"); 
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
            log("Generando salt KDF...");
            kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
            if (kdf_salt.empty()) { 
                log("Error generando salt KDF"); 
                close(fd); 
                return false; 
            }
            
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { 
                log("Error derivando clave secundaria"); 
                close(fd); 
                return false; 
            }
            log("✓ Clave derivada");
            
            if (strlen(fs_info.fstype) == 0) fs_info = getFileSystemInfo(unit.device_path);
            
            EncUnitHdr hdr;
            memset(&hdr, 0, sizeof(hdr));
            memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
            hdr.version = HEADER_VERSION_CURRENT;
            hdr.data_start_sector = data_start_sector;
            hdr.total_sectors = total_sectors;
            hdr.fs_info = fs_info;
            
            try {
                HMACProc hmac(master_key);
                auto hmac_result = hmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, hmac));
                if (hmac_result.size() == HMAC_SIZE) memcpy(hdr.hmac, hmac_result.data(), HMAC_SIZE);
                else { 
                    log("Error: Tamaño de HMAC incorrecto"); 
                    close(fd); 
                    return false; 
                }
            } catch (const std::exception& e) {
                log(std::string("Error calculando HMAC: ") + e.what()); 
                close(fd); 
                return false;
            }
            
            if (!backup_mgr.saveHeader(unit.device_path, hdr, master_key))
                log("Advertencia: No se pudo guardar backup");
            
            if (!writeHeaderToDevice(fd, hdr)) {
                log(std::string("Error escribiendo header: ") + strerror(errno)); 
                close(fd); 
                return false;
            }
            fsync(fd);
            log("✓ Header escrito");
        } else {
            EncUnitHdr hdr;
            if (!readHeaderFromDevice(fd, hdr)) {
                if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
                    log("Header recuperado desde backup");
                else { 
                    log("No se pudo leer header"); 
                    close(fd); 
                    return false; 
                }
            }
            
            if (hdr.version < 2) {
                log("Versión antigua (sin KDF)");
                xts_key.resize(64);
                memcpy(xts_key.data(), master_key.data(), 32);
                memcpy(xts_key.data() + 32, master_key.data(), 32);
            } else {
                kdf_salt.resize(KDF_SALT_SIZE);
                memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
                xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
                if (xts_key.empty()) { 
                    log("Error derivando clave"); 
                    close(fd); 
                    return false; 
                }
                log("✓ Clave derivada");
            }
            
            try {
                HMACProc hmac(master_key);
                if (!hmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, hmac), hdr.hmac, HMAC_SIZE)) {
                    log("Error: Autenticación HMAC falló"); 
                    close(fd); 
                    return false;
                }
            } catch (const std::exception& e) {
                log(std::string("Error verificando HMAC: ") + e.what()); 
                close(fd); 
                return false;
            }
            log("✓ Header verificado");
            
            fs_info = hdr.fs_info;
            data_start_sector = hdr.data_start_sector;
            data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
        }
        
        std::stringstream ss2;
        ss2 << "Datos a procesar: " << StorUnit::formatBytes(data_size);
        log(ss2.str());
        
        size_t chunk_size = proc_config.getChunkSize();
        uint64_t total_chunks = (data_size + chunk_size - 1) / chunk_size;
        
        ss2.str("");
        ss2 << "Procesando " << total_chunks << " chunks...";
        log(ss2.str());
        log(proc_config.use_direct_io ? "Usando I/O Directo" : "Usando I/O normal");
        
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
                    log(std::string("Error de lectura en chunk ") + std::to_string(c) + ": " + strerror(errno));
                    error = true;
                    break;
                }
                read_queue.push(std::move(chunk));
            }
            read_queue.close();
        });
        
        int num_cpu_threads = (use_custom_config && custom_config.custom_mode) ? custom_config.crypto_threads : fixed_config.crypto_threads;
        std::vector<std::thread> cpu_threads;
        
        for (int t = 0; t < num_cpu_threads; t++) {
            cpu_threads.emplace_back([&, t]() {
                AESXTSProc proc(xts_key, encrypt);
                PipeChunk chunk(chunk_size, proc_config.use_direct_io);
                while (read_queue.pop(chunk) && !error && !stop_requested) {
                    if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                        log(std::string("Error procesando chunk ") + std::to_string(chunk.index));
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
                            log(std::string("Error de escritura en chunk ") + std::to_string(chunk.index) + ": " + strerror(errno));
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
            log("Eliminando header y backup...");
            off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
            size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
            std::vector<uint8_t> zeros(header_size, 0);
            if (pwrite(fd, zeros.data(), header_size, header_offset) == (ssize_t)header_size) {
                fsync(fd);
                log("✓ Header eliminado");
            }
            if (backup_mgr.removeBackup(unit.device_path)) log("✓ Backup eliminado");
        }
        
        close(fd);
        stats.total_bytes = bytes_processed.load();
        
        if (error) log("✗ Error durante el procesamiento");
        else if (stop_requested) log("⚠ Procesamiento detenido");
        else log("✓ Procesamiento completado");
        
        return !error && (chunks_done == total_chunks) && !stop_requested;
    }
    
    void stop() { if (processing_active) stop_requested = true; }
    
    bool mountUnit(const StorUnit& u, const std::string& point) { return mount(u, point); }
    bool unmountUnit(StorUnit& u) { return unmount(u); }
    bool hasHeaderBackup(const std::string& device_path) { return backup_mgr.backupExists(device_path); }
    bool removeHeaderBackup(const std::string& device_path) { return backup_mgr.removeBackup(device_path); }
    
    bool cleanHeader(const StorUnit& unit) {
        log("Limpiando header...");
        int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
        if (fd < 0) { log(std::string("No se puede abrir: ") + strerror(errno)); return false; }
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(header_size, 0);
        ssize_t written = pwrite(fd, zeros.data(), header_size, header_offset);
        fsync(fd);
        close(fd);
        if (written == (ssize_t)header_size) {
            log("✓ Header eliminado");
            if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
                log("✓ Backup eliminado");
            return true;
        } else {
            log("✗ Error limpiando header");
            return false;
        }
    }
    
    bool restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key) {
        log("Restaurando header desde backup...");
        EncUnitHdr hdr;
        if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
            log("✗ No se pudo cargar backup");
            return false;
        }
        int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
        if (fd < 0) {
            log("✗ No se pudo abrir dispositivo");
            return false;
        }
        if (!writeHeaderToDevice(fd, hdr)) {
            log("✗ Error escribiendo header");
            close(fd);
            return false;
        }
        close(fd);
        log("✓ Header restaurado correctamente");
        return true;
    }
    
    bool formatUnit(const StorUnit& unit, const std::string& fstype) {
        std::string cmd;
        if (fstype == "vfat" || fstype == "fat32") cmd = "mkfs.vfat -F 32 " + unit.device_path + " 2>/dev/null";
        else if (fstype == "ntfs") cmd = "mkfs.ntfs -f " + unit.device_path + " 2>/dev/null";
        else if (fstype == "ext4") cmd = "mkfs.ext4 -F " + unit.device_path + " 2>/dev/null";
        else cmd = "mkfs." + fstype + " " + unit.device_path + " 2>/dev/null";
        int res = system(cmd.c_str());
        if (res == 0) {
            log("✓ Formateado correctamente");
            return true;
        }
        log("✗ Error formateando (código: " + std::to_string(res) + ")");
        return false;
    }
    
    // Info para la UI
    std::string getCPUInfo() const { return HWDetect::getCPUInfo(); }
    int getCoreCount() const { return HWDetect::getCoreCount(); }
};

#endif // CIPHER_UNIT_ENCRYPTOR_H
