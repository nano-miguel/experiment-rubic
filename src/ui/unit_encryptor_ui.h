// ui/unit_encryptor_ui.h - 0.1 alpha
// Toda la UI de UnitEncryptor: menús, prompts, lectura de teclado.
// La lógica vive en cipher/unit_encryptor.h

#ifndef UI_UNIT_ENCRYPTOR_UI_H
#define UI_UNIT_ENCRYPTOR_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>
#include <iomanip>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <dirent.h>

#include "../cipher/unit_encryptor.h"
#include "../keygest/key_manager.h"

// ============================================
// COLORES (propios, con guard)
// ============================================
#ifndef UI_UNIT_COLORS_DEFINED
#define UI_UNIT_COLORS_DEFINED
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

// ============================================
// BARRA DE PROGRESO
// ============================================
class ProgBar {
private:
    int width;
    std::string prefix;
    std::string suffix;
    std::chrono::steady_clock::time_point start_time;
    uint64_t total_bytes;
    uint64_t current_bytes;
    double last_speed;
    
public:
    ProgBar(int bar_width = 50, const std::string& pre = "", const std::string& suf = "") 
        : width(bar_width), prefix(pre), suffix(suf), total_bytes(0), current_bytes(0), last_speed(0) {
        start_time = std::chrono::steady_clock::now();
    }
    
    void setTotal(uint64_t total) { total_bytes = total; }
    
    void update(uint64_t current) {
        current_bytes = current;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed > 0) last_speed = (current_bytes / 1048576.0) / (elapsed / 1000.0);
        render();
    }
    
    void render() {
        if (total_bytes == 0) return;
        double progress = (double)current_bytes / total_bytes;
        int pos = (int)(width * progress);
        double gb_done = current_bytes / (double)(1024ULL*1024ULL*1024ULL);
        double gb_total = total_bytes / (double)(1024ULL*1024ULL*1024ULL);
        int percent = (int)(progress * 100);
        
        auto now = std::chrono::steady_clock::now();
        std::string eta = "calculando";
        if (last_speed > 0 && current_bytes > 0) {
            uint64_t remaining_bytes = total_bytes - current_bytes;
            double remaining_secs = remaining_bytes / (last_speed * 1048576.0);
            if (remaining_secs < 3600) {
                int minutes = (int)remaining_secs / 60;
                int seconds = (int)remaining_secs % 60;
                std::stringstream ss;
                ss << minutes << "m " << seconds << "s";
                eta = ss.str();
            } else {
                int hours = (int)remaining_secs / 3600;
                int minutes = ((int)remaining_secs % 3600) / 60;
                std::stringstream ss;
                ss << hours << "h " << minutes << "m";
                eta = ss.str();
            }
        }
        
        std::cout << "\r" << prefix << " " << BLUE << "[" << RESET;
        for (int i = 0; i < width; ++i) {
            if (i < pos) std::cout << GREEN << "█" << RESET;
            else if (i == pos) std::cout << BLUE << "█" << RESET;
            else std::cout << "░";
        }
        std::cout << BLUE << "]" << RESET;
        std::cout << " " << GREEN << std::setw(3) << percent << "%" << RESET;
        std::cout << " " << BLUE << std::fixed << std::setprecision(2) << gb_done << "/" << gb_total << " GB" << RESET;
        std::cout << " " << GREEN << std::fixed << std::setprecision(2) << last_speed << " MB/s" << RESET;
        std::cout << " " << BLUE << "ETA: " << eta << RESET;
        std::cout << suffix;
        std::cout.flush();
    }
    
    void finish() { std::cout << std::endl; }
};

// ============================================
// FORMATEADOR (UI del formateo)
// ============================================
class FormatterUI {
public:
    static bool cleanHeader(UnitEncryptor& core, const StorUnit& unit) {
        return core.cleanHeader(unit);
    }
    
    static bool quickFormat(UnitEncryptor& core, const StorUnit& unit, const std::string& fstype) {
        std::cout << YELLOW << "\n⚠ FORMATEO RÁPIDO" << RESET << std::endl;
        std::cout << "Unidad: " << unit.device_path << std::endl;
        std::cout << "Tamaño: " << unit.getSizeStr() << std::endl;
        std::cout << "Formato: " << fstype << std::endl;
        std::cout << "\nEscriba 'FORMATEAR' para confirmar: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "FORMATEAR") { std::cout << "Cancelado." << std::endl; return false; }
        std::cout << YELLOW << "Formateando..." << RESET << std::endl;
        return core.formatUnit(unit, fstype);
    }
};

// ============================================
// CLASE PRINCIPAL UnitEncryptorUI
// ============================================

class UnitEncryptorUI {
private:
    UnitEncryptor& core_;
    KeyManager* keyManager_;
    std::string currentKeyName;
    
    // Signal handling
    inline static UnitEncryptorUI* instance = nullptr;
    
    static void signalHandler(int signal) {
        exit(signal);
    }
    
    static void setupSignalHandlers() {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP, signalHandler);
        signal(SIGQUIT, signalHandler);
    }
    
    // Termios para echo on/off
    struct termios oldt, newt;
    
    void disable_echo() {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    
    void enable_echo() {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
    
    std::string get_secure_input(const std::string& prompt) {
        std::cout << prompt;
        disable_echo();
        std::string input;
        std::getline(std::cin, input);
        enable_echo();
        std::cout << std::endl;
        return input;
    }
    
    std::string getInput(const std::string& prompt) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        return input;
    }
    
    void waitForEnter() {
        std::cout << "\n" << YELLOW << "Presione Enter para continuar..." << RESET;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string dummy;
        std::getline(std::cin, dummy);
    }
    
    bool checkRoot() {
        if (geteuid() != 0) {
            std::cout << BRIGHT_RED << "\n✗ ERROR: SE REQUIEREN PERMISOS DE ROOT" << RESET << std::endl;
            std::cout << "Ejecute con: sudo" << RESET << std::endl;
            return false;
        }
        return true;
    }
    
    // Callback para log del core
    void onCoreLog(const std::string& msg) {
        std::cout << msg << std::endl;
    }
    
    // Callback para progreso del core (vacío: la barra se pinta en processUnit)
    void onCoreProgress(uint64_t current, uint64_t total, double speed) {
        (void)current; (void)total; (void)speed;
    }
    
    // Selector de clave
    std::string selectKeyFromManager() {
        if (!keyManager_) return "";
        auto keys = keyManager_->getActiveKeys();
        if (keys.empty()) {
            std::cout << YELLOW << "No hay claves activas" << RESET << std::endl;
            return "";
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "CLAVES" << BLUE << "]──────────────────────────────────────────────┐\n";
        for (size_t i = 0; i < keys.size(); i++)
            std::cout << BLUE << "│ " << GREEN << " [" << i+1 << "] " << MAGENTA << keys[i] << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(keys.size()) + BRIGHT_GREEN + "]: " + RESET;
        std::string c = getInput(prompt);
        if (c == "0") return "";
        try {
            int idx = std::stoi(c) - 1;
            if (idx >= 0 && idx < (int)keys.size()) return keys[idx];
        } catch (...) {}
        return "";
    }
    
    // Obtener master key del usuario
    Botan::secure_vector<uint8_t> getMasterKey() {
        if (!keyManager_) return {};
        
        std::string keyName = currentKeyName;
        if (keyName.empty()) {
            keyName = selectKeyFromManager();
            if (keyName.empty()) return {};
            currentKeyName = keyName;
        }
        
        Botan::secure_vector<uint8_t> keyBytes = keyManager_->getKeyValue(keyName);
        if (keyBytes.empty()) return {};
        
        if (keyBytes.size() != 32) {
            std::cout << RED << "Error: Clave inválida (debe ser 32 bytes, actual: " << keyBytes.size() << ")" << RESET << std::endl;
            return {};
        }
        
        return keyBytes;
    }
    
    void showConfigMenu() {
        while (true) {
            CustCfg& custom = core_.getCustomConfig();
            FixedThCfg& fixed = core_.getFixedConfig();
            bool& use_custom = core_.getUseCustomConfig();
            
            std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN" << BLUE << "]──────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << MAGENTA << "CONFIGURACIÓN POR DEFECTO:" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Núcleos: " << GREEN << HWDetect::getCoreCount() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  I/O Threads: " << GREEN << fixed.io_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Crypto Threads: " << GREEN << fixed.crypto_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Reserved OS: " << GREEN << fixed.reserved_os << RESET << std::endl;
            
            if (use_custom && custom.custom_mode) {
                std::cout << BLUE << "\n│ " << MAGENTA << "  Configuración personalizada:" << RESET << std::endl;
                std::cout << BLUE << "│ " << RESET << "  " << GREEN << "Buffer:" << RESET << " " << custom.buffer_size_mb << " MB" << std::endl;
                std::cout << BLUE << "│ " << RESET << "  " << GREEN << "I/O Threads:" << RESET << " " << custom.io_threads << std::endl;
                std::cout << BLUE << "│ " << RESET << "  " << GREEN << "Crypto Threads:" << RESET << " " << custom.crypto_threads << std::endl;
                std::cout << BLUE << "│ " << RESET << "  " << GREEN << "I/O Directo:" << RESET << " " << (custom.use_direct_io ? "Si" : "No") << std::endl;
                std::cout << BLUE << "│ " << RESET << "  " << GREEN << "Modo personalizado:" << RESET << " " << (custom.custom_mode ? "Activado" : "Desactivado") << std::endl;
            } else {
                std::cout << BLUE << "│ " << YELLOW << "  Modo personalizado: INACTIVO" << RESET << std::endl;
            }
            
            std::cout << BLUE << "│ " << RESET << "\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Configuración personalizada" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Alternar modo personalizado" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione opción [" + BRIGHT_MAGENTA + "0-2" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "1") {
                std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN PERSONALIZADA" << BLUE << "]────────────────────────────────────┐\n";
                std::string input;
                std::cout << BLUE << "│ " << RESET << "Tamaño de buffer (MB) [" << custom.buffer_size_mb << "]: ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.buffer_size_mb = std::stoul(input);
                std::cout << BLUE << "│ " << RESET << "Hilos I/O [" << custom.io_threads << "]: ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.io_threads = std::stoi(input);
                std::cout << BLUE << "│ " << RESET << "Hilos cifrado [" << custom.crypto_threads << "]: ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.crypto_threads = std::stoi(input);
                std::cout << BLUE << "│ " << RESET << "Usar I/O Directo (s/n) [" << (custom.use_direct_io ? "s" : "n") << "]: ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.use_direct_io = (input == "s" || input == "S");
                std::cout << BLUE << "│ " << RESET << "Activar modo personalizado (s/n) [" << (custom.custom_mode ? "s" : "n") << "]: ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.custom_mode = (input == "s" || input == "S");
                std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
                custom.saveToFile("rubic_config.cfg");
                std::cout << GREEN << "\n✓ Configuración guardada en rubic_config.cfg" << RESET << std::endl;
            }
            else if (c == "2") {
                use_custom = !use_custom;
                custom.custom_mode = use_custom;
                custom.saveToFile("rubic_config.cfg");
                std::cout << GREEN << "\n✓ Modo personalizado " << (use_custom ? "activado" : "desactivado") << RESET << std::endl;
            }
        }
    }
    
    bool processUnit(StorUnit& unit, bool encrypt) {
        if (!checkRoot()) return false;
        
        if (encrypt && unit.is_encrypted) { 
            std::cout << YELLOW << "La unidad ya está cifrada" << RESET << std::endl; 
            return false; 
        }
        if (!encrypt && !unit.is_encrypted) { 
            std::cout << YELLOW << "La unidad no está cifrada" << RESET << std::endl; 
            return false; 
        }
        if (unit.is_system_disk) { 
            std::cout << BRIGHT_RED << "\n⚠ NO SE PUEDE CIFRAR EL DISCO DEL SISTEMA" << RESET << std::endl; 
            return false; 
        }
        if (unit.is_mounted) {
            std::cout << YELLOW << "⚠ La unidad está montada en " << unit.mount_point << RESET << std::endl;
            std::cout << "¿Desmontar? (S/n): ";
            std::string resp = getInput("");
            if (resp.empty() || resp == "S" || resp == "s") {
                if (!core_.unmountUnit(unit)) {
                    std::cout << RED << "No se puede continuar con la unidad montada" << RESET << std::endl;
                    return false;
                }
            } else {
                return false;
            }
        }
        
        Botan::secure_vector<uint8_t> master_key = getMasterKey();
        
        if (master_key.empty() || master_key.size() != 32) {
            std::cout << RED << "No se pudo obtener la clave maestra" << RESET << std::endl;
            return false;
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << (encrypt ? "CIFRAR" : "DESCIFRAR") << BLUE << "]─────────────────────────────────────────┐\n";
        std::cout << BLUE << "│ " << RESET << "Unidad: " << CYAN << unit.device_path << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Tamaño: " << YELLOW << unit.getSizeStr() << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Tipo: " << unit.getDevTypeColor() << unit.getDevTypeStr() << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string confirm = getInput("\nEscriba '" + std::string(encrypt ? "CIFRAR" : "DESCIFRAR") + "': ");
        if ((encrypt && confirm != "CIFRAR") || (!encrypt && confirm != "DESCIFRAR")) return false;
        
        // Iniciar barra de progreso
        uint64_t total_size = unit.total_size;
        ProgBar progress_bar(50, "", "");
        progress_bar.setTotal(total_size);
        
        core_.setProgressCallback([&progress_bar](uint64_t cur, uint64_t total, double speed) {
            progress_bar.update(cur);
            (void)total; (void)speed;
        });
        
        bool ok = core_.processUnit(unit, encrypt, master_key);
        
        progress_bar.finish();
        
        if (ok) {
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            
            if (!encrypt) {
                std::cout << "\n¿Montar la unidad descifrada? (s/N): ";
                std::string resp;
                std::getline(std::cin, resp);
                if (resp == "s" || resp == "S") {
                    std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                    core_.mountUnit(unit, mp);
                }
            }
            core_.refresh();
        }
        return ok;
    }
    
public:
    UnitEncryptorUI(UnitEncryptor& core, KeyManager* km)
        : core_(core), keyManager_(km) {
        instance = this;
        setupSignalHandlers();
        
        core_.setLogCallback([this](const std::string& msg) {
            this->onCoreLog(msg);
        });
        core_.setProgressCallback([this](uint64_t cur, uint64_t total, double speed) {
            this->onCoreProgress(cur, total, speed);
        });
    }
    
    ~UnitEncryptorUI() {
        instance = nullptr;
    }
    
    // ============================================================
    // MENÚ DE FORMATO
    // ============================================================
    void showFormatMenu(StorUnit& unit) {
        std::cout << BLUE << "\n┌─[" << MAGENTA << "FORMATO DE UNIDAD" << BLUE << "]────────────────────────────────────────┐\n";
        if (unit.is_encrypted) {
            std::cout << BLUE << "│ " << YELLOW << "⚠ La unidad está marcada como CIFRADA" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Limpiar solo header (quitar marca)" << RESET << std::endl;
        }
        std::cout << BLUE << "│ " << RESET << "\n";
        std::cout << BLUE << "│ " << MAGENTA << "SISTEMA DE ARCHIVOS:" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "FAT32 (USB, compatible)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "NTFS (Windows)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "ext4 (Linux)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "exFAT (grandes)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        std::cout << BRIGHT_GREEN << "\nSeleccione opción [" << BRIGHT_MAGENTA << "0-5" << BRIGHT_GREEN << "]: " << RESET;
        std::string c;
        std::getline(std::cin, c);
        if (c == "0") return;
        if (c == "1" && unit.is_encrypted) {
            if (FormatterUI::cleanHeader(core_, unit)) {
                unit.is_encrypted = false;
                unit.has_header_backup = false;
                std::cout << GREEN << "\n✓ Unidad marcada como NO CIFRADA" << RESET << std::endl;
            }
            return;
        }
        std::string fstype;
        if (c == "2") fstype = "vfat";
        else if (c == "3") fstype = "ntfs";
        else if (c == "4") fstype = "ext4";
        else if (c == "5") fstype = "exfat";
        else return;
        if (FormatterUI::quickFormat(core_, unit, fstype)) {
            unit.is_encrypted = false;
            unit.has_header_backup = false;
            unit.filesystem = fstype;
            std::cout << GREEN << "\n✓ Unidad formateada y marcada como NO CIFRADA" << RESET << std::endl;
        }
    }
    
    // ============================================================
    // SUBMENÚ DE UNIDAD
    // ============================================================
    void unitMenu(StorUnit& u) {
        while (true) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << u.device_path << BLUE << "]────────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << RESET << "Tamaño: " << GREEN << u.getSizeStr() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Tipo: " << u.getDevTypeColor() << u.getDevTypeStr() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Estado: " << (u.is_encrypted ? BRIGHT_RED "CIFRADA" : GREEN "SIN CIFRAR") << RESET << std::endl;
            
            if (u.has_header_backup && u.is_encrypted)
                std::cout << BLUE << "│ " << GREEN << "Backup disponible" << RESET << std::endl;
            if (!u.mount_point.empty())
                std::cout << BLUE << "│ " << RESET << "Montada en: " << YELLOW << u.mount_point << RESET << std::endl;
            if (u.is_system_disk)
                std::cout << BLUE << "│ " << BRIGHT_RED << "⚠ DISCO DEL SISTEMA - OPERACIONES RESTRINGIDAS" << RESET << std::endl;
            
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            
            if (!u.is_system_disk)
                std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << (u.is_encrypted ? "Descifrar unidad" : "Cifrar unidad") << RESET << std::endl;
            
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Montar unidad" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "Desmontar unidad" << RESET << std::endl;
            
            if (!u.is_system_disk)
                std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "Formatear unidad" << RESET << std::endl;
            if (u.is_encrypted && u.has_header_backup)
                std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "Restaurar header desde backup" << RESET << std::endl;
            
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-5" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "1" && !u.is_system_disk) {
                if (processUnit(u, !u.is_encrypted)) getInput("\nPresione Enter para continuar...");
                core_.refresh();
            }
            else if (c == "2") {
                if (!u.is_mounted) {
                    std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                    std::cout << "Punto de montaje [" << mp << "]: ";
                    std::string input;
                    std::getline(std::cin, input);
                    if (!input.empty()) mp = input;
                    if (core_.mountUnit(u, mp)) { u.is_mounted = true; u.mount_point = mp; }
                } else std::cout << YELLOW << "Ya montada en " << u.mount_point << RESET << std::endl;
                getInput("\nPresione Enter para continuar...");
            }
            else if (c == "3") {
                if (u.is_mounted) core_.unmountUnit(u);
                else std::cout << YELLOW << "La unidad no está montada" << RESET << std::endl;
                getInput("\nPresione Enter para continuar...");
            }
            else if (c == "4" && !u.is_system_disk) {
                if (u.is_mounted) core_.unmountUnit(u);
                showFormatMenu(u);
                getInput("\nPresione Enter para continuar...");
                core_.refresh();
            }
            else if (c == "5" && u.is_encrypted && u.has_header_backup) {
                Botan::secure_vector<uint8_t> master_key = getMasterKey();
                if (master_key.empty()) { 
                    std::cout << RED << "No se pudo obtener la clave" << RESET << std::endl; 
                    continue; 
                }
                core_.restoreHeader(u, master_key);
                getInput("\nPresione Enter para continuar...");
                core_.refresh();
            }
        }
    }
    
    // ============================================================
    // MENÚ PRINCIPAL
    // ============================================================
    void showMenu() {
        while (true) {
            if (geteuid() != 0) {
                std::cout << BRIGHT_RED << "\nRequiere root" << RESET << std::endl;
                getInput("Enter...");
                break;
            }
            
            core_.refresh();
            auto units = core_.getUnits();
            
            std::cout << BLUE;
            std::cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│" << GREEN << BOLD << "                       CIFRADOR DE UNIDADES                          " << BLUE << "│\n";
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << "│" << MAGENTA << "  " << HWDetect::getCPUInfo() << BLUE << "                                          │\n";
            
            bool use_custom = core_.getUseCustomConfig();
            if (use_custom) {
                std::cout << "│" << YELLOW << "  Modo personalizado activo                                          " << BLUE << "│\n";
            }
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            if (units.empty()) {
                std::cout << YELLOW << "\nNo hay unidades detectadas" << RESET << std::endl;
            } else {
                std::cout << GREEN << "\nUNIDADES DETECTADAS:" << RESET << std::endl;
                for (size_t i = 0; i < units.size(); i++) {
                    auto& u = units[i];
                    std::string icon = u.is_system_disk ? "S" : (u.is_encrypted ? "E" : "N");
                    if (u.has_header_backup && u.is_encrypted) icon += "B";
                    
                    std::cout << "  [" << GREEN << i+1 << RESET << "] " << icon << " ";
                    std::cout << (u.is_encrypted ? BRIGHT_RED : GREEN) << std::setw(7) 
                              << (u.is_system_disk ? "SISTEMA" : (u.is_encrypted ? "CIFRADA" : "NORMAL")) << RESET;
                    std::cout << " " << CYAN << u.device_path << RESET;
                    
                    if (!u.label.empty()) std::cout << " (" << u.label << ")";
                    std::cout << " - " << u.getSizeStr();
                    std::cout << " " << u.getDevTypeColor() << "[" << u.getDevTypeStr() << "]" << RESET;
                    if (u.is_mounted) std::cout << " (M)";
                    if (u.has_header_backup) std::cout << " [B]";
                    
                    std::string safe_fs = u.getSafeFSType();
                    if (u.is_encrypted && !safe_fs.empty()) {
                        std::cout << " → " << GREEN << safe_fs << RESET;
                    } else if (!u.is_encrypted && !u.filesystem.empty()) {
                        std::cout << " → " << GREEN << u.filesystem << RESET;
                    }
                    
                    std::cout << std::endl;
                }
            }
            
            std::cout << BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << GREEN << " [" << MAGENTA << "1-" << units.size() << GREEN << "] " << MAGENTA << "Seleccionar unidad" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [C] " << MAGENTA << "Configuración" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [R] " << MAGENTA << "Refrescar" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Salir" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(units.size()) + ",C,R" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "R" || c == "r") { core_.refresh(); continue; }
            else if (c == "C" || c == "c") showConfigMenu();
            else {
                try {
                    int idx = std::stoi(c) - 1;
                    if (idx >= 0 && idx < (int)units.size()) {
                        unitMenu(units[idx]);
                        core_.refresh();
                    }
                } catch (...) {}
            }
        }
    }
};

#endif // UI_UNIT_ENCRYPTOR_UI_H
