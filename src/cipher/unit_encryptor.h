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
#include <errno.h>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <stdlib.h>
#include <filesystem>
#include <x86intrin.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/kdf.h>
#include <botan/hash.h>

#include "../hardware_detect.h"

class KeyManager;

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
#define KMAC_SIZE 64
#define KDF_SALT_SIZE 64
#define KEY_DERIVATION_INFO "RUBI-C-AES-XTS-KEY-V1-OFFSET-1MB"
#define PIPELINE_DEPTH 3
#define MAX_QUEUE_SIZE 2
#define HEADER_VERSION_CURRENT 3

// ▼▼▼ Eventos estructurados para la UI ▼▼▼
enum class LogLevel {
    Info,
    Warning,
    Error,
    Success,
    Progress
};

enum class LogEvent {
    // Header
    HeaderWriting,
    HeaderWritten,
    HeaderReadFailed,
    HeaderVerified,
    HeaderRemoved,
    HeaderRestoring,
    HeaderRestored,
    HeaderRestoreFailed,
    HeaderCleanFailed,
    
    // Backup
    BackupSaved,
    BackupSaveFailed,
    BackupLoaded,
    BackupLoadFailed,
    BackupRemoved,
    
    // KDF
    SaltGenerating,
    SaltGenerated,
    SaltError,
    KeyDeriving,
    KeyDerived,
    KeyDeriveError,
    
    // KMAC
    KmacCalculating,
    KmacError,
    KmacVerified,
    KmacFailed,
    
    // Sanity checks
    SystemDiskBlocked,
    UnitAlreadyEncrypted,
    UnitNotEncrypted,
    UnitMounted,
    UnitMountedUnmounting,
    UnitUnmountFailed,
    MasterKeyInvalid,
    DeviceOpenFailed,
    DeviceOpenRetry,
    DeviceSizeFailed,
    
    // Detección
    DeviceTypeDetected,
    ConfigAuto,
    ConfigCustom,
    ChunkSizeInfo,
    IoModeInfo,
    DataSizeInfo,
    ChunkCountInfo,
    
    // Progreso
    Processing,
    ProcessingComplete,
    ProcessingFailed,
    ProcessingStopped,
    ChunkReadError,
    ChunkProcessError,
    ChunkWriteError,
    
    // Mount
    Mounting,
    Mounted,
    MountFailed,
    Unmounting,
    Unmounted,
    
    // Cleanup
    CleanupHeader,
    CleanupBackup,
    
    // Format
    FormatStart,
    FormatOk,
    FormatFailed
};

// VERIFICACIÓN DE PERMISOS
inline bool isRoot() {
    return geteuid() == 0;
}

// DERIVACIÓN DE CLAVES
class KeyDeriv {
public:
    static Botan::secure_vector<uint8_t> deriveSubKey(
        const Botan::secure_vector<uint8_t>& master_key,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_length = 64);
    
    static Botan::secure_vector<uint8_t> generateSalt(size_t size = KDF_SALT_SIZE);
};

// CONFIGURACIÓN
struct CustCfg {
    size_t buffer_size_mb;
    int io_threads;
    int crypto_threads;
    bool use_direct_io;
    bool custom_mode;
    
    CustCfg();
    
    void loadFromFile(const std::string& filename);
    void saveToFile(const std::string& filename);
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

// PROCESAMIENTO AVX2/AVX-512
class SIMDProc {
public:
    static void xor_blocks(uint8_t* dst, const uint8_t* src, size_t blocks) {
        size_t i = 0;
        size_t total_bytes = blocks * 16;
#ifdef __AVX512F__
        if (HardwareDetect::hasAVX512()) {
            for (; i + 64 <= total_bytes; i += 64) {
                __m512i vdst = _mm512_loadu_si512((__m512i*)(dst + i));
                __m512i vsrc = _mm512_loadu_si512((__m512i*)(src + i));
                vdst = _mm512_xor_si512(vdst, vsrc);
                _mm512_storeu_si512((__m512i*)(dst + i), vdst);
            }
        } else 
#endif
#ifdef __AVX2__
        if (HardwareDetect::hasAVX2()) {
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
    static std::string getSysPath(const std::string& device);
    static bool checkUSB(const std::string& syspath);
    static std::string readSpeed(const std::string& syspath);
    static bool checkNVMe(const std::string& device);
    static bool checkSD(const std::string& device);
    static bool isRemovable(const std::string& syspath);
    
public:
    static DevType detect(const std::string& device);
    
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
    
    static FixedThCfg getConfigForSystem();
};

struct ThCfg {
    int num_threads;
    size_t chunk_size_mb;
    bool use_direct_io;
    
    ThCfg();
    
    void applyFixedConfig(const FixedThCfg& fixed_cfg, DevType device_type);
    void applyCustomConfig(const CustCfg& custom_cfg);
    void validate();
    size_t getChunkSize() const;
    std::string getDesc() const;
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
    SpeedMtr();
    void addBytes(uint64_t bytes);
    double getCurrentSpeed();
    double getAvgSpeed();
    double getPeakSpeed();
    uint64_t getTotalBytes();
    void reset();
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
    uint8_t Kmac[KMAC_SIZE];
    
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
    std::string getBackupPath(const std::string& device_path);
    Botan::secure_vector<uint8_t> encryptBackup(const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key);
    bool decryptBackup(const std::string& backup_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key);
    Botan::secure_vector<uint8_t> deriveBackupKey(const std::string& device_path);
    
public:
    bool saveHeader(const std::string& device_path, const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key);
    bool loadHeader(const std::string& device_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key);
    bool backupExists(const std::string& device_path);
    bool removeBackup(const std::string& device_path);
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
    bool requires_elevation;
    
    StorUnit() : total_size(0), is_mounted(false), is_encrypted(false), 
                 is_partition(false), is_system_disk(false), 
                 device_type(DevType::UNKNOWN), has_header_backup(false),
                 requires_elevation(false) {}
    
    std::string getSizeStr() const { return formatBytes(total_size); }
    std::string getDevTypeStr() const { return DevDetect::devTypeToStr(device_type); }
    
    static std::string formatBytes(uint64_t bytes);
    std::string getSafeFSType() const;
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

// PROCESADOR KMAC
class KMACProc {
private:
    std::unique_ptr<Botan::MessageAuthenticationCode> Kmac;
    Botan::secure_vector<uint8_t> key;
    
public:
    KMACProc(const Botan::secure_vector<uint8_t>& key_data);
    Botan::secure_vector<uint8_t> calculate(const uint8_t* data, size_t size);
    bool verify(const uint8_t* data, size_t size, const uint8_t* expected_Kmac, size_t Kmac_size);
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
    AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt);
    bool processBuffer(uint8_t* data, size_t size, uint64_t start_sector);
    bool processSecBuf(SecBuf& buffer, uint64_t start_sector);
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
    using LogCallback = std::function<void(LogLevel level, LogEvent event, const std::string& data)>;
   
    using ProgressCallback = std::function<void(uint64_t current_bytes, uint64_t total_bytes, double speed_mbps)>;

    struct Stats {
        uint64_t total_bytes = 0;
        uint64_t total_time_ms = 0;
        uint64_t errors = 0;
        double avg_speed_mbps = 0.0;
        double peak_speed_mbps = 0.0;
    };
    
    const Stats& getLastStats() const { return stats; }
    
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
    
    void log(LogLevel level, LogEvent event, const std::string& data = "") {
        if (log_cb_) log_cb_(level, event, data);
    }
    
    void progress(uint64_t cur, uint64_t total, double speed) {
        if (progress_cb_) progress_cb_(cur, total, speed);
    }
    
    Stats stats;
    
    // Helpers privados (cuerpos en .cpp)
    void refreshUnits();
    bool isPhysicalDevice(const std::string& path);
    std::string getParentDevice(const std::string& path);
    bool isSystemDisk(const std::string& path);
    FSInfo getFileSystemInfo(const std::string& path);
    bool isUnitEncrypted(const std::string& device_path);
    bool readHeaderFromDevice(int fd, EncUnitHdr& hdr);
    bool writeHeaderToDevice(int fd, const EncUnitHdr& hdr);
    std::vector<StorUnit> detectUnits();
    bool unmount(StorUnit& u);
    bool mount(const StorUnit& u, const std::string& point);
    
    bool tryElevatedProcess(const StorUnit& unit, bool encrypt,
                            const Botan::secure_vector<uint8_t>& master_key);
    
public:
    UnitEncryptor();
    
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
    
    bool hasKey() const;
    
    std::vector<StorUnit> getUnits();
    void refresh();
    
    CustCfg& getCustomConfig() { return custom_config; }
    FixedThCfg& getFixedConfig() { return fixed_config; }
    bool& getUseCustomConfig() { return use_custom_config; }
    
    const CustCfg& getCustomConfig() const { return custom_config; }
    const FixedThCfg& getFixedConfig() const { return fixed_config; }
    bool getUseCustomConfig() const { return use_custom_config; }
    
    void reloadCustomConfig();
    
    bool processUnit(StorUnit& unit, bool encrypt, 
                     const Botan::secure_vector<uint8_t>& master_key);
    
    bool doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt);
    
    void stop() { if (processing_active) stop_requested = true; }
    
    bool mountUnit(const StorUnit& u, const std::string& point) { return mount(u, point); }
    bool unmountUnit(StorUnit& u) { return unmount(u); }
    bool hasHeaderBackup(const std::string& device_path) { return backup_mgr.backupExists(device_path); }
    bool removeHeaderBackup(const std::string& device_path) { return backup_mgr.removeBackup(device_path); }
    
    bool cleanHeader(const StorUnit& unit);
    bool restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key);
    bool formatUnit(const StorUnit& unit, const std::string& fstype);
    
    std::string getCPUInfo() const { return HardwareDetect::getCPUInfoExtended(); }
    int getCoreCount() const { return HardwareDetect::getCoreCount(); }
};

#endif // CIPHER_UNIT_ENCRYPTOR_H