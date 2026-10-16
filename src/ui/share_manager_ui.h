// ui/share_manager_ui.h - 0.1 alpha
// Toda la UI del gestor de compartir archivos: menús, prompts, TOFU, colores.
// La lógica vive en share/share_manager.h

#ifndef UI_SHARE_MANAGER_UI_H
#define UI_SHARE_MANAGER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <limits>
#include <algorithm>
#include <csignal>
#include <unistd.h>
#include <termios.h>

#include "../share/share_manager.h"

// ============================================
// COLORES (propios, con guard)
// ============================================
#ifndef UI_SHARE_COLORS_DEFINED
#define UI_SHARE_COLORS_DEFINED
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
// SHARE MANAGER UI - CLASE PRINCIPAL

class ShareManagerUI {
private:
    ShareManager& core_;
    
    // Signal handling
    inline static ShareManagerUI* instance = nullptr;
    
    static void signalHandler(int signal) {
        if (instance) {
            instance->core_.stopReceiving();
        }
        exit(signal);
    }
    
    static void setupSignalHandlers() {
        signal(SIGINT,  signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP,  signalHandler);
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
    
    // ============================================================
    // ▼▼▼ NUEVO: traducción de eventos estructurados ▼▼▼
    // ============================================================
    void onCoreLog(share_log::LogLevel level, share_log::LogEvent event, const std::string& data) {
        (void)level;
        switch (event) {
            // Conexión
            case share_log::LogEvent::Connecting:
                std::cout << "  Conectando a " << data << "..." << std::endl; break;
            case share_log::LogEvent::ConnectFailed:
                std::cout << RED << "  ✗ Falló la conexión: " << data << RESET << std::endl; break;
            case share_log::LogEvent::ExchangeKeysFailed:
                std::cout << RED << "  ✗ Falló el intercambio de claves con " << data << RESET << std::endl; break;
            case share_log::LogEvent::MitmDetected:
                std::cout << BRIGHT_RED << BOLD 
                          << "\n  ⚠⚠⚠ ¡ALERTA DE SEGURIDAD! ⚠⚠⚠\n"
                          << "  Posible ataque MITM detectado contra: " << data << "\n"
                          << "  La firma Dilithium del remoto es INVÁLIDA. Conexión abortada.\n"
                          << RESET << std::endl; break;
            case share_log::LogEvent::SessionEstablished:
                std::cout << GREEN << "  ✓ Sesión segura: " << data << RESET << std::endl; break;
            
            // Recepción
            case share_log::LogEvent::ReceivingFrom:
                std::cout << MAGENTA << "  Recibiendo de " << data << "..." << RESET << std::endl; break;
            case share_log::LogEvent::ServerStartFailed:
                std::cout << RED << "  ✗ No se pudieron iniciar los servidores" << RESET << std::endl; break;
            case share_log::LogEvent::KyberGenFailed:
                std::cout << RED << "  ✗ No se pudieron generar claves Kyber" << RESET << std::endl; break;
            case share_log::LogEvent::ServerStarted:
                std::cout << GREEN << "  ✓ Servidores iniciados" << RESET << std::endl; break;
            case share_log::LogEvent::ServerStopped:
                std::cout << GREEN << "  ✓ Servidores detenidos" << RESET << std::endl; break;
            
            // Envío
            case share_log::LogEvent::NoFilesToSend:
                std::cout << YELLOW << "  ⚠ No hay archivos para enviar" << RESET << std::endl; break;
            case share_log::LogEvent::SendingFiles:
                std::cout << MAGENTA << "  Enviando " << data << " archivos..." << RESET << std::endl; break;
            case share_log::LogEvent::SendComplete:
                std::cout << GREEN << "  ✓ Envío completado (" << data << ")" << RESET << std::endl; break;
            case share_log::LogEvent::SendFailed:
                std::cout << RED << "  ✗ Envío falló hacia " << data << RESET << std::endl; break;
            
            // Identidad
            case share_log::LogEvent::IdentityLoadError:
                std::cout << RED << "  ✗ Error cargando la identidad Dilithium" << RESET << std::endl; break;
            
            // TOFU
            case share_log::LogEvent::TrustPromptShown:
                // El prompt real lo maneja askTrust(), no acá
                break;
            case share_log::LogEvent::TrustAccepted:
                std::cout << GREEN << "  ✓ Identidad " << data << " marcada como confiable" << RESET << std::endl; break;
            case share_log::LogEvent::TrustRejected:
                std::cout << RED << "  ✗ Identidad " << data << " rechazada" << RESET << std::endl; break;
        }
    }
    // ▲▲▲ NUEVO ▲▲▲
    
    // ============================================================
    // Callbacks que se registran en el core
    // ============================================================
    
    bool askTrust(const std::string& rem_user, const std::string& fprint, bool is_srv) {
        std::cout << BRIGHT_YELLOW << "\n\n⚠ ALERTA DE SEGURIDAD (TOFU) ⚠" << RESET << std::endl;
        if (is_srv) {
            std::cout << "Se detectó una conexión entrante de una identidad nueva o no verificada." << std::endl;
        } else {
            std::cout << "Estás conectando a una identidad nueva o no verificada." << std::endl;
        }
        
        std::cout << "Usuario: " << BRIGHT_MAGENTA << rem_user << RESET << std::endl;
        std::cout << "Huella:  " << BRIGHT_CYAN << fprint << RESET << std::endl;
        std::cout << "¿Confiar en esta identidad, continuar de todos modos y guardar para el futuro? (s/N): ";
        
        std::string ans;
        std::getline(std::cin, ans);
        if (ans == "s" || ans == "S") {
            std::cout << GREEN << "✓ Identidad guardada como confiable. Continuando..." << RESET << "\n\n";
            return true;
        }
        std::cout << RED << "✗ Conexión cancelada." << RESET << "\n\n";
        return false;
    }
    
    void onNewSession(const std::string& rem_user, const std::string& rem_ip) {
        std::cout << GREEN << "\n✓ Sesión segura establecida: " << rem_user 
                  << " (" << rem_ip << ")" << RESET << std::endl;
    }
    
    void onFileRecv(const std::string& filename, size_t bytes, bool ok) {
        if (ok) {
            std::cout << GREEN << "  ✓ " << filename 
                      << " (" << (bytes / 1024.0 / 1024.0) << " MB)" << RESET << std::endl;
        } else {
            std::cout << RED << "  ✗ " << filename 
                      << " (Error de integridad)" << RESET << std::endl;
        }
    }
    
    void onFileSend(const std::string& filename, size_t current, size_t total, bool ok) {
        std::string short_name = std::filesystem::path(filename).filename().string();
        if (!ok && current == 0) {
            // Inicio
            std::cout << "  [" << current << "/" << total << "] " 
                      << short_name << " " << std::flush;
        } else {
            // Fin
            if (ok) std::cout << GREEN << "✓" << RESET << std::endl;
            else    std::cout << RED << "✗" << RESET << std::endl;
        }
    }
    
    // ============================================================
    // Submenús
    // ============================================================
    
    void manageTrust() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│      " << BRIGHT_GREEN << "HUELLAS DE CONFIANZA (TOFU)" << BRIGHT_BLUE << "         │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";
        
        auto fps = core_.getTrustedFingerprints();
        
        if (fps.empty()) {
            std::cout << YELLOW << "  No hay identidades registradas." << RESET << std::endl;
        } else {
            int i = 1;
            for (const auto& fp : fps) {
                std::cout << "  " << i++ << ". " << BRIGHT_CYAN << fp << RESET << std::endl;
            }
        }
        
        std::string add = getInput("\n¿Ingresar una huella manualmente? (s/N): ");
        if (add == "s" || add == "S") {
            std::string fp = getInput("Huella (Fingerprint): ");
            if (!fp.empty()) {
                if (core_.addTrustedFingerprint(fp)) {
                    std::cout << GREEN << " Huella guardada" << RESET << std::endl;
                } else {
                    std::cout << RED << "✗ No se pudo guardar la huella" << RESET << std::endl;
                }
            }
        }
    }
    
    void cfgNet() {
        std::cout << "\n  IP Actual: " << BRIGHT_YELLOW << core_.getCurrentIP() << RESET << "\n";
        std::cout << "  Puerto Intercambio (KEM): " << BRIGHT_YELLOW << core_.getKemPort() << RESET << "\n";
        std::cout << "  Puerto Transferencia:     " << BRIGHT_YELLOW << core_.getXferPort() << RESET << "\n";
        
        std::string ans = getInput("\n¿Deseas cambiar los puertos? (s/N): ");
        if (ans == "s" || ans == "S") {
            std::string p1 = getInput("Nuevo puerto de intercambio: ");
            std::string p2 = getInput("Nuevo puerto de transferencia: ");
            try {
                if (!p1.empty()) core_.setKemPort(std::stoi(p1));
                if (!p2.empty()) core_.setXferPort(std::stoi(p2));
                std::cout << GREEN << "✓ Puertos actualizados" << RESET << std::endl;
            } catch (...) {
                std::cout << RED << "✗ Puerto inválido" << RESET << std::endl;
            }
        }
    }
    
    void sendFiles() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│         " << BRIGHT_GREEN << "ENVIAR ARCHIVOS" << BRIGHT_BLUE << "                    │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";
        
        std::cout << YELLOW << "Formato: IP:PUERTO (por defecto :" << core_.getKemPort() << ")" << RESET << "\n";
        std::string addr = getInput("Dirección destino: ");
        if (addr.empty()) return;
        
        std::string rem_addr;
        int rem_port;
        if (!ShareManager::parseAddress(addr, rem_addr, rem_port)) {
            std::cout << RED << "✗ Dirección inválida. Formato: IP:PUERTO" << RESET << std::endl;
            return;
        }
        
        std::string path = getInput("Ruta del archivo/carpeta: ");
        if (path.empty()) return;
        if (path.front() == '"' && path.back() == '"') path = path.substr(1, path.size() - 2);
        
        std::vector<std::string> files = ShareManager::expandFiles(path);
        if (files.empty()) {
            std::cout << RED << "✗ No hay archivos" << RESET << std::endl;
            return;
        }
        
        size_t total = 0;
        for (const auto& f : files) {
            struct stat st;
            if (stat(f.c_str(), &st) == 0) total += st.st_size;
        }
        std::cout << "  Archivos: " << files.size() 
                  << " | Total: " << (total / 1024.0 / 1024.0) << " MB\n";
        
        std::string conf = getInput(YELLOW + std::string("¿Continuar? (s/N): ") + RESET);
        if (conf != "s" && conf != "S") return;
        
        std::cout << MAGENTA << "\nEnviando " << files.size() << " archivos..." << RESET << std::endl;
        
        bool ok = core_.sendFiles(files, rem_addr, rem_port);
        
        if (ok) {
            std::cout << GREEN << "\n✓ Envío completado" << RESET << std::endl;
        } else {
            std::cout << RED << "\n✗ Envío falló" << RESET << std::endl;
        }
        
        getInput("\nPresiona Enter...");
    }
    
    void recvFiles() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│        " << BRIGHT_GREEN << "RECIBIR ARCHIVOS" << BRIGHT_BLUE << "                     │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";
        
        if (!core_.startReceiving()) {
            std::cout << RED << "✗ No se pudo iniciar el servidor de recepción" << RESET << std::endl;
            getInput("");
            return;
        }
        
        std::string ip = core_.getCurrentIP();
        std::cout << GREEN << "✓ Esperando en " << BRIGHT_YELLOW << ip 
                  << ":" << core_.getKemPort() << RESET << "\n";
        if (core_.hasIdentity()) {
            std::cout << GREEN << "✓ Tu ID: " << BRIGHT_CYAN << core_.getFingerprint() << RESET << "\n";
        }
        std::cout << "  Carpeta de recepción: " << BRIGHT_CYAN << core_.getRecvDir() << RESET << "\n";
        std::cout << BRIGHT_RED << "\n[Escribe 'q' y presiona ENTER para detener la recepción]" << RESET << std::endl;
        
        std::string wait;
        while (core_.isReceiving()) {
            std::getline(std::cin, wait);
            if (wait == "q" || wait == "Q" || wait == "salir" || wait == "quit") {
                break;
            }
        }
        
        core_.stopReceiving();
        std::cout << GREEN << "\n✓ Recepción detenida" << RESET << std::endl;
        getInput("\nPresiona Enter para volver...");
    }
    
public:
    // ============================================================
    // Constructor / Destructor
    // ============================================================
    ShareManagerUI(ShareManager& core) : core_(core) {
        instance = this;
        setupSignalHandlers();
        
        // ▼▼▼ Firma actualizada: LogLevel, LogEvent, data ▼▼▼
        core_.setLogCallback([this](share_log::LogLevel level, share_log::LogEvent event, const std::string& data) {
            this->onCoreLog(level, event, data);
        });
        // ▲▲▲
        core_.setTrustPromptCallback([this](const std::string& u, const std::string& fp, bool srv) {
            return this->askTrust(u, fp, srv);
        });
        core_.setSessionCallback([this](const std::string& u, const std::string& ip) {
            this->onNewSession(u, ip);
        });
        core_.setFileRecvCallback([this](const std::string& f, size_t b, bool ok) {
            this->onFileRecv(f, b, ok);
        });
        core_.setFileSendCallback([this](const std::string& f, size_t c, size_t t, bool ok) {
            this->onFileSend(f, c, t, ok);
        });
    }
    
    ~ShareManagerUI() {
        core_.stopReceiving();
        instance = nullptr;
    }
    
    // ============================================================
    // MENÚ PRINCIPAL
    // ============================================================
    void showMenu() {
        while (true) {
            std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
            std::cout << "│     " << BRIGHT_GREEN << "COMPARTIR ARCHIVOS" << BRIGHT_BLUE << "                   │\n";
            std::cout << "├──────────────────────────────────────────┤\n";
            if (core_.hasIdentity()) {
                std::string fp = core_.getFingerprint();
                if (fp.length() > 16) fp = fp.substr(0, 16);
                std::cout << "│ ID: " << BRIGHT_CYAN << fp << RESET;
                for (int i = 0; i < 27; i++) std::cout << " ";
                std::cout << BRIGHT_BLUE << "│\n";
            }
            std::cout << "│  " << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Enviar archivos" << BRIGHT_BLUE << "                     │\n";
            std::cout << "│  " << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Recibir archivos" << BRIGHT_BLUE << "                    │\n";
            std::cout << "│  " << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Adm. Identidades de confianza " << BRIGHT_BLUE << "      │\n";
            std::cout << "│  " << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " Configuración de Red" << BRIGHT_BLUE << "                │\n";
            std::cout << "│  " << BRIGHT_GREEN << "[5]" << BRIGHT_MAGENTA << " Volver" << BRIGHT_BLUE << "                              │\n";
            std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";
            
            std::string opt = getInput(BRIGHT_GREEN + std::string("Opción: ") + RESET);
            
            if      (opt == "1") sendFiles();
            else if (opt == "2") recvFiles();
            else if (opt == "3") manageTrust();
            else if (opt == "4") cfgNet();
            else if (opt == "5") break;
        }
    }
};

#endif // UI_SHARE_MANAGER_UI_H