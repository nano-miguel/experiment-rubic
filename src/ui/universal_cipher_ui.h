// ui/universal_cipher_ui.h - 0.1 alpha
// Toda la UI de UniversalCipher: menús, prompts, lectura de teclado.
// La lógica vive en cipher/universal_cipher.h y se comunica por callbacks.

#ifndef UI_UNIVERSAL_CIPHER_UI_H
#define UI_UNIVERSAL_CIPHER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>

#include "../cipher/universal_cipher.h"
#include "../keygest/key_manager.h"


#ifndef UI_CIPHER_COLORS_DEFINED
#define UI_CIPHER_COLORS_DEFINED
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

// *******************************************
// CIFRADOR UNIVERSAL UI - CLASE PRINCIPAL

class UniversalCipherUI {
private:
    UniversalCipher& core_;
    KeyManager* keyManager_;
    
    // Signal handling (para guardar contadores al recibir Ctrl+C)
    inline static UniversalCipherUI* instance = nullptr;
    
    static void signalHandler(int signal) {
        if (instance && instance->core_.getNameObfuscator()) {
            instance->core_.getNameObfuscator()->force_save_counters();
        }
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
    
    // Callback que se registra en el core para recibir logs
    void onCoreLog(const std::string& msg) {
        std::cout << msg << std::endl;
    }
    
    // Callback que se registra en el core para recibir progreso
    void onCoreProgress(size_t current, size_t total, const std::string& file) {
        std::cout << "\n[" << current << "/" << total << "] "
                  << BRIGHT_WHITE << file << RESET << std::endl;
    }

public:
    UniversalCipherUI(UniversalCipher& core, KeyManager* km)
        : core_(core), keyManager_(km) {
        instance = this;
        setupSignalHandlers();
        
        // Registrar callbacks en el core
        core_.setLogCallback([this](const std::string& msg) {
            this->onCoreLog(msg);
        });
        core_.setProgressCallback([this](size_t cur, size_t total, const std::string& file) {
            this->onCoreProgress(cur, total, file);
        });
    }
    
    ~UniversalCipherUI() {
        if (core_.getNameObfuscator()) {
            core_.getNameObfuscator()->force_save_counters();
        }
        instance = nullptr;
    }
    
    std::string selectKey() {
        if (!keyManager_) {
            std::cout << RED << "✗ Gestor de claves no disponible" << RESET << std::endl;
            return "";
        }
        
        std::vector<std::string> activeKeys = keyManager_->getActiveKeys();
        if (activeKeys.empty()) {
            std::cout << YELLOW << "\nNo hay claves activas disponibles." << RESET << std::endl;
            return "";
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "CLAVES DISPONIBLES" << BLUE << "]──────────────────────────────────────┐\n";
        std::cout << BLUE << "│" << RESET << "\n";
        std::cout << BLUE << "│ " << GREEN << "CLAVES ACTIVAS:" << RESET << std::endl;
        for (size_t i = 0; i < activeKeys.size(); i++) {
            std::cout << BLUE << "│   [" << GREEN << i+1 << BLUE << "] " << CYAN << activeKeys[i] << RESET << std::endl;
        }
        std::cout << BLUE << "│   [" << GREEN << "0" << BLUE << "] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(activeKeys.size()) + BRIGHT_GREEN + "]: " + RESET;
        std::string choiceStr = getInput(prompt);
        if (choiceStr == "0") return "";
        
        try {
            int choice = std::stoi(choiceStr) - 1;
            if (choice >= 0 && choice < static_cast<int>(activeKeys.size())) {
                return activeKeys[choice];
            }
        } catch (...) {}
        
        std::cout << RED << "✗ Selección inválida" << RESET << std::endl;
        return "";
    }
    
    void showMenu() {
        while (true) {
            std::cout << BLUE;
            std::cout << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│" << GREEN << BOLD << "                       CIFRADO UNIVERSAL                            " << BLUE << "│\n";
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            
            std::string hwInfo = "  AES-256-GCM | " + CipherHWDetect::getCPUInfo();
            std::string pad1(std::max(0, 69 - (int)hwInfo.length()), ' ');
            std::cout << "│" << MAGENTA << hwInfo << pad1 << BLUE << "│\n";
            
            std::string thInfo = "  Hilos: " + std::to_string(core_.getConfig().thread_config.crypto_threads) 
                               + " | Paralelo: " + std::to_string(core_.getConfig().max_parallel_files) + " archivos";
            std::string pad2(std::max(0, 69 - (int)thInfo.length()), ' ');
            std::cout << "│" << CYAN << thInfo << pad2 << BLUE << "│\n";
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::cout << BLUE << "\n┌─[" << MAGENTA << "MENÚ PRINCIPAL" << BLUE << "]───────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Cifrar archivo/directorio                                           " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Descifrar archivo/directorio                                        " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "Configuración                                                       " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Salir                                                               " << BLUE << "│\n";
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione opción [" + BRIGHT_MAGENTA + "0-3" + BRIGHT_GREEN + "]: " + RESET;
            std::string choice = getInput(prompt);
            
            if (choice == "1" || choice == "2") {
                std::string keyName = selectKey();
                if (keyName.empty()) {
                    waitForEnter();
                    continue;
                }
                
                // Si la clave requiere activación, pedir el código aquí (en la UI)
                if (keyManager_ && !keyManager_->isKeyActive(keyName) && 
                    keyManager_->keyRequiresActivation(keyName)) {
                    std::string activationCode = get_secure_input("Clave de activación: ");
                    Botan::secure_vector<uint8_t> code(activationCode.begin(), activationCode.end());
                    if (!keyManager_->activateKey(keyName, code)) {
                        std::cout << RED << "✗ Clave de activación incorrecta" << RESET << std::endl;
                        waitForEnter();
                        continue;
                    }
                }
                
                if (!core_.setCipherKey(keyName)) {
                    waitForEnter();
                    continue;
                }
                
                std::string path = getInput("\nRuta: ");
                
                bool result;
                if (choice == "1") {
                    result = core_.encryptPath(path);
                } else {
                    result = core_.decryptPath(path);
                }
                
                core_.getNameObfuscator()->force_save_counters();
                
                if (result) {
                    std::cout << GREEN << "\n✓ Operación completada" << RESET << std::endl;
                }
                waitForEnter();
                
            } else if (choice == "3") {
                showConfigMenu();
            } else if (choice == "0") {
                core_.getNameObfuscator()->force_save_counters();
                break;
            }
        }
    }
    
    void showConfigMenu() {
        while (true) {
            SystemConfig& config = core_.getConfig();
            
            std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN" << BLUE << "]──────────────────────────────────────────┐\n";
            
            // Mostrar config actual (replicamos el print() que estaba en el core)
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << BLUE << "│ " << MAGENTA << "CONFIGURACIÓN ACTUAL:" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Hilos sistema: " << GREEN << config.thread_config.total_system_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  → Cifrado: " << GREEN << config.thread_config.crypto_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  → I/O: " << GREEN << config.thread_config.io_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  → Reservados SO: " << YELLOW << config.thread_config.reserved_os << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Buffer: " << GREEN << (config.min_buffer_size/1024) << "KB - " 
                      << (config.max_buffer_size/(1024*1024)) << "MB" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Reintentos: " << GREEN << config.max_retries << RESET 
                      << " (delay " << config.retry_delay_ms << "ms)" << std::endl;
            std::cout << BLUE << "│ " << RESET << "mmap (> " << (config.mmap_threshold/(1024*1024)) << "MB): " 
                      << GREEN << (config.should_use_mmap(config.mmap_threshold) ? "✓" : "✗") << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Archivos paralelos: " << GREEN << config.max_parallel_files << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "HMAC header: " << GREEN << (config.use_header_hmac ? "Sí" : "No") << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
            
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Buffer máximo (" << (config.max_buffer_size/(1024*1024)) << " MB)" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Rate limit (" << (config.max_bytes_per_second/(1024*1024)) << " MB/s)" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "HMAC header (" << (config.use_header_hmac ? "Sí" : "No") << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "Archivos paralelos (" << config.max_parallel_files << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "Reintentos (" << config.max_retries << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [6] " << MAGENTA << "Limpiar contadores" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-6" + BRIGHT_GREEN + "]: " + RESET;
            std::string choice = getInput(prompt);
            
            if (choice == "0") break;
            else if (choice == "1") {
                std::string size = getInput("MB (2-32): ");
                try {
                    size_t s = std::stoul(size);
                    if (s >= 2 && s <= 32) {
                        config.max_buffer_size = s * 1024 * 1024;
                        config.optimal_buffer_size = config.max_buffer_size / 2;
                    }
                } catch (...) {}
            }
            else if (choice == "2") {
                std::string mb = getInput("MB/s (10-1000): ");
                try {
                    size_t m = std::stoul(mb);
                    if (m >= 10 && m <= 1000) {
                        config.max_bytes_per_second = m * 1024 * 1024;
                    }
                } catch (...) {}
            }
            else if (choice == "3") {
                config.use_header_hmac = !config.use_header_hmac;
            }
            else if (choice == "4") {
                std::string num = getInput("Número (1-16): ");
                try {
                    size_t n = std::stoul(num);
                    if (n >= 1 && n <= 16) {
                        config.max_parallel_files = n;
                    }
                } catch (...) {}
            }
            else if (choice == "5") {
                std::string num = getInput("Número (0-5): ");
                try {
                    size_t n = std::stoul(num);
                    if (n <= 5) {
                        config.max_retries = n;
                    }
                } catch (...) {}
            }
            else if (choice == "6") {
                std::string confirm = getInput("¿Eliminar todos los contadores? (s/N): ");
                if (confirm == "s" || confirm == "S") {
                    std::remove(config.counter_file_path.c_str());
                    std::remove(config.name_key_file_path.c_str());
                    std::cout << YELLOW << "⚠ Contadores eliminados (reinicia la app para recrearlos)" << RESET << std::endl;
                }
            }
            
            waitForEnter();
        }
    }
};

#endif // UI_UNIVERSAL_CIPHER_UI_H
