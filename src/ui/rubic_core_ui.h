// ui/rubic_core_ui.h - 0.1 alpha
// Toda la UI del core: login, registro, menú principal, config.
// La lógica vive en rubic_core.h (UserMgr)

#ifndef UI_RUBIC_CORE_UI_H
#define UI_RUBIC_CORE_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <limits>
#include <chrono>
#include <thread>
#include <csignal>
#include <unistd.h>
#include <termios.h>

#include "../rubic_core.h"

// ============================================
// COLORES (guard local, por si otra UI incluye primero)
// ============================================
#ifndef UI_RUBIC_CORE_COLORS_DEFINED
#define UI_RUBIC_CORE_COLORS_DEFINED
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
// LECTOR-DE-CONTRASEÑAS (vive en la UI)
// ============================================
class PwdReader {
private:
    inline static struct termios old_termios;
    inline static bool termios_saved = false;
    
    static void raw_mode(bool enable) {
        if (enable) {
            if (!termios_saved) {
                tcgetattr(STDIN_FILENO, &old_termios);
                termios_saved = true;
            }
            struct termios raw = old_termios;
            raw.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        } else if (termios_saved) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        }
    }
    
public:
    static Botan::secure_vector<uint8_t> readPassword(const string& prompt = "Contraseña: ") {
        raw_mode(true);
        Botan::secure_vector<uint8_t> pass;
        
        cout << prompt << flush;
        char c;
        while (::read(STDIN_FILENO, &c, 1) == 1) {
            if (c == '\n' || c == '\r') break;
            if (c == 127 || c == '\b') {
                if (!pass.empty()) {
                    pass.pop_back();
                    cout << "\b \b" << flush;
                }
                continue;
            }
            pass.push_back(static_cast<uint8_t>(c));
            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(50));
            cout << "\b*" << flush;
        }
        
        raw_mode(false);
        cout << endl;
        return pass;
    }
    
    static Botan::secure_vector<uint8_t> readWithConfirm() {
        for (int i = 0; i < 3; i++) {
            auto p1 = readPassword("Contraseña: ");
            if (p1.size() < 8) {
                cout << RED << "X Mínimo 8 caracteres" << RESET << endl;
                secure_c_container(p1);
                continue;
            }
            
            auto p2 = readPassword("Confirmar: ");
            if (secure_compare(p1, p2)) {
                secure_c_container(p2);
                return p1;
            }
            
            cout << RED << "✗ No coinciden (" << (i+1) << "/3)" << RESET << endl;
            secure_c_container(p1);
            secure_c_container(p2);
        }
        return {};
    }
};

// ============================================
// RUBIC CORE UI
// ============================================

class RubicCoreUI {
private:
    UserMgr& core_;
    
    // Signal handling
    inline static RubicCoreUI* instance = nullptr;
    
    static void signalHandler(int signal) {
        if (instance) {
            instance->core_.shutdown();
        }
        exit(signal);
    }
    
    static void setupSignalHandlers() {
        signal(SIGINT,  signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP,  signalHandler);
        signal(SIGQUIT, signalHandler);
    }
    
    string getInput(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }
    
    void waitForEnter(const string& msg = "Presione Enter para continuar...") {
        cout << "\n" << YELLOW << msg << RESET;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        string dummy;
        getline(cin, dummy);
    }
    
    void printBanner() {
        cout << BRIGHT_BLUE;
        cout << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "  ██████╗ ██╗   ██╗██████╗ ██╗      ██████╗   " << BRIGHT_BLUE << "                       │\n";
        cout << "│" << BRIGHT_GREEN << "  ██╔══██╗██║   ██║██╔══██╗██║      ██╔══██╗  " << BRIGHT_BLUE << "                      │\n";
        cout << "│" << BRIGHT_GREEN << "  ██████╔╝██║   ██║██████╔╝██║█████╗██║  ██║  " << BRIGHT_BLUE << "                      │\n";
        cout << "│" << BRIGHT_GREEN << "  ██╔══██╗██║   ██║██╔══██╗██║╚════╝██║  ██║  " << BRIGHT_BLUE << "                      │\n";
        cout << "│" << BRIGHT_GREEN << "  ██║  ██║╚██████╔╝██████╔╝██║      ██████╔╝  " << BRIGHT_BLUE << "                      │\n";
        cout << "│" << BRIGHT_GREEN << "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝   " << BRIGHT_BLUE << "                      │\n";
        cout << "│                                                                     │\n";
        cout << "│" << BRIGHT_MAGENTA << "        SISTEMA DE CIFRADO- v1.0             " << BRIGHT_BLUE << "                        │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    void showUserInfo() {
        auto info = core_.getUserInfo();
        if (info.username.empty()) {
            cout << RED << "✗ Error: No se pudo cargar la información del usuario" << RESET << endl;
            return;
        }
        
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "INFORMACIÓN DE USUARIO" << BRIGHT_BLUE << "                                        │\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        cout << "│ Usuario: " << BRIGHT_MAGENTA << info.username << RESET 
             << string(48 - info.username.length(), ' ') << BRIGHT_BLUE << "│\n";
        cout << "│ Algoritmo: " << BRIGHT_CYAN << info.algo << RESET 
             << string(46 - info.algo.length(), ' ') << BRIGHT_BLUE << "│\n";
        
        char buf[30];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", localtime(&info.created));
        cout << "│ Creado: " << buf << string(48 - strlen(buf), ' ') << BRIGHT_BLUE << "│\n";
        
        cout << "│ Identidad: " << (info.has_id ? BRIGHT_GREEN "✓ ACTIVA" : BRIGHT_RED "✗ PENDIENTE") 
             << RESET << string(36, ' ') << BRIGHT_BLUE << "│\n";
        
        if (info.has_id && !info.id_fprint.empty()) {
            cout << "│ Huella: " << BRIGHT_GREEN << info.id_fprint << RESET 
                 << string(48 - info.id_fprint.length(), ' ') << BRIGHT_BLUE << "│\n";
        }
        
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    void changePassword() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "CAMBIAR CONTRASEÑA" << BRIGHT_BLUE << "                                           │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        auto current = PwdReader::readPassword("Contraseña actual: ");
        
        auto new_pass = PwdReader::readWithConfirm();
        if (new_pass.empty()) {
            secure_c_container(current);
            return;
        }
        
        string error;
        bool ok = core_.changePassword(current, new_pass, error);
        
        if (ok) {
            cout << GREEN << "\n✓ Contraseña cambiada" << RESET << endl;
        } else {
            cout << RED << "\n✗ " << error << RESET << endl;
        }
        
        secure_c_container(current);
        secure_c_container(new_pass);
    }
    
    void generateIdentity() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "GENERAR IDENTIDAD DIGITAL" << BRIGHT_BLUE << "                                   │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        cout << MAGENTA << "\nGenerando clave Dilithium-6x5-AES-r3 (PQC)..." << RESET << endl;
        
        string fingerprint, error;
        if (core_.generateIdentity(fingerprint, error)) {
            cout << GREEN << "\n✓ Identidad generada exitosamente" << RESET << endl;
            cout << GREEN << "  Huella: " << BRIGHT_CYAN << fingerprint << RESET << endl;
        } else {
            cout << RED << "\n✗ " << error << RESET << endl;
        }
    }
    
    void showConfigMenu() {
        while (true) {
            cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│ " << BRIGHT_GREEN << "CONFIGURACIÓN" << BRIGHT_BLUE << "                                                       │\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            cout << "│ " << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Cambiar contraseña" << BRIGHT_BLUE << "                                              │\n";
            cout << "│ " << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Información de usuario" << BRIGHT_BLUE << "                                          │\n";
            cout << "│ " << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Generar identidad digital" << BRIGHT_BLUE << "                                       │\n";
            cout << "│ " << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " Volver" << BRIGHT_BLUE << "                                                          │\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            string opt = getInput(BRIGHT_GREEN + string("Opción [1-4]: ") + RESET);
            
            if      (opt == "1") changePassword();
            else if (opt == "2") showUserInfo();
            else if (opt == "3") generateIdentity();
            else if (opt == "4") break;
        }
    }
    
    bool doLogin() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "INICIAR SESIÓN" << BRIGHT_BLUE << "                                              │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string user = getInput("Usuario: ");
        auto pass = PwdReader::readPassword();
        
        auto result = core_.authenticate(user, pass);
        secure_c_container(pass);
        
        if (result.throttled) {
            cout << RED << "✗ Bloqueado. Espere " << result.seconds_left << " segundos." << RESET << endl;
            return false;
        }
        
        if (!result.ok) {
            cout << RED << "✗ " << result.error << RESET << endl;
            return false;
        }
        
        cout << GREEN << "\n✓ Bienvenido, " << user << RESET << endl;
        return true;
    }
    
    bool doRegister() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "CREAR CUENTA" << BRIGHT_BLUE << "                                                │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string user = getInput("Usuario: ");
        
        auto pass = PwdReader::readWithConfirm();
        if (pass.empty()) return false;
        
        cout << MAGENTA << "\nGenerando credenciales con ARGON2 y vinculando al Hardware..." << RESET << endl;
        
        auto result = core_.createAccount(user, pass);
        secure_c_container(pass);
        
        if (!result.ok) {
            cout << RED << "✗ " << result.error << RESET << endl;
            return false;
        }
        
        if (result.id_generated) {
            cout << MAGENTA << "\nGenerando identidad digital Dilithium-6x5-AES-r3 automáticamente..." << RESET << endl;
            cout << GREEN << "✓ Identidad digital generada automáticamente" << RESET << endl;
            cout << CYAN << "  Huella: " << BRIGHT_GREEN << result.id_fingerprint << RESET << endl;
        } else {
            cout << YELLOW << "⚠ Advertencia: No se pudo generar la identidad digital automáticamente" << RESET << endl;
            cout << YELLOW << "  Puede generarla después desde el menú de configuración" << RESET << endl;
        }
        
        cout << GREEN << "\n✓ Cuenta creada exitosamente" << RESET << endl;
        cout << GREEN << "✓ Identidad digital vinculada al sistema" << RESET << endl;
        return true;
    }
    
    enum class MainAction { Continue, Logout, Exit };
    
    MainAction showMainMenu() {
        printBanner();
        
        string user = core_.getCurrentUser();
        
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_MAGENTA << "MENÚ PRINCIPAL - " << user 
             << string(48 - user.length(), ' ') << BRIGHT_BLUE << " │\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        cout << "│" << BRIGHT_CYAN  << "---HERRAMIENTAS DE CIFRADO//                  " << BRIGHT_BLUE << "                       │\n";
        cout << "│" << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Cifrar Unidad"      << BRIGHT_BLUE << "                                                    │\n";
        cout << "│" << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Cifrador Universal" << BRIGHT_BLUE << "                                               │\n";
        cout << "│" << BRIGHT_CYAN  << "---GESTIÓN DE SEGURIDAD// "                     << BRIGHT_BLUE << "                                           │\n";
        cout << "│" << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Gestor de Claves"   << BRIGHT_BLUE << "                                                 │\n";
        cout << "│" << BRIGHT_CYAN  << "---COMPARTIR ARCHIVOS//   "                     << BRIGHT_BLUE << "                                           │\n";
        cout << "│" << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " Compartir Archivos" << BRIGHT_BLUE << "                                               │\n";
        cout << "│" << BRIGHT_CYAN  << "---ADMINISTRACIÓN Y SESIÓN//"                   << BRIGHT_BLUE << "                                         │\n";
        cout << "│" << BRIGHT_GREEN << "[5]" << BRIGHT_MAGENTA << " Configuración"      << BRIGHT_BLUE << "                                                    │\n";
        cout << "│" << BRIGHT_GREEN << "[6]" << BRIGHT_MAGENTA << " Cerrar Sesión"      << BRIGHT_BLUE << "                                                    │\n";
        cout << "│" << BRIGHT_GREEN << "[0]" << BRIGHT_MAGENTA << " Salir del Sistema"  << BRIGHT_BLUE << "                                                │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "    \n";
        
        string opt = getInput(BRIGHT_GREEN + string("Opción [0-6]: ") + RESET);
        
        if (opt == "1") {
            auto* ui = core_.getUnitEncryptorUI();
            if (ui) ui->showMenu();
        } else if (opt == "2") {
            auto* ui = core_.getUniversalCipherUI();
            if (ui) ui->showMenu();
        } else if (opt == "3") {
            auto* ui = core_.getKeyManagerUI();
            if (ui) ui->showMenu();
        } else if (opt == "4") {
            auto* ui = core_.getShareManagerUI();
            if (ui) ui->showMenu();
        } else if (opt == "5") {
            showConfigMenu();
        } else if (opt == "6") {
            cout << MAGENTA << "\nCerrando sesión..." << RESET << endl;
            return MainAction::Logout;
        } else if (opt == "0") {
            cout << MAGENTA << "\nSaliendo...\n" << RESET;
            return MainAction::Exit;
        }
        
        return MainAction::Continue;
    }
    
public:
    explicit RubicCoreUI(UserMgr& core) : core_(core) {
        instance = this;
        setupSignalHandlers();
    }
    
    ~RubicCoreUI() {
        instance = nullptr;
    }
    
    void run() {
        while (true) {
            printBanner();
            
            cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│ " << BRIGHT_GREEN << "ACCESO AL SISTEMA" << BRIGHT_BLUE << "                                                   │\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            cout << "│" << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Iniciar sesión" << BRIGHT_BLUE << "                                                   │\n";
            cout << "│" << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Crear cuenta" << BRIGHT_BLUE << "                                                     │\n";
            cout << "│" << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Salir" << BRIGHT_BLUE << "                                                            │\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            string opt = getInput(BRIGHT_GREEN + string("Opción [1-3]: ") + RESET);
            
            bool logged_in = false;
            if (opt == "1") {
                logged_in = doLogin();
            } else if (opt == "2") {
                logged_in = doRegister();
            } else if (opt == "3") {
                cout << MAGENTA << "\nSaliendo...\n" << RESET;
                core_.shutdown();
                return;
            }
            
            if (!logged_in) continue;
            
            while (core_.isAuthenticated()) {
                auto action = showMainMenu();
                if (action == MainAction::Exit) {
                    core_.shutdown();
                    return;
                } else if (action == MainAction::Logout) {
                    core_.logout();
                    break;
                }
            }
        }
    }
};

#endif // UI_RUBIC_CORE_UI_H