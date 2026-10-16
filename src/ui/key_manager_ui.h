// ui/key_manager_ui.h - 0.1 alpha
// Toda la UI del gestor de claves: menús, prompts, lectura de teclado.
// La lógica vive en keygest/key_manager.h

#ifndef UI_KEY_MANAGER_UI_H
#define UI_KEY_MANAGER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <memory>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>

#include "../keygest/key_manager.h"

// ============================================
// COLORES (propios, con guard)
// ============================================
#ifndef UI_KEYMGR_COLORS_DEFINED
#define UI_KEYMGR_COLORS_DEFINED
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
// INPUT SEGURO (movido desde key_manager.h original)
// ============================================
class KeySecureInput {
private:
    static void setRawMode(bool enable) {
        static struct termios oldt;
        static bool initialized = false;
        struct termios tty;

        if (enable) {
            if (!initialized) {
                tcgetattr(STDIN_FILENO, &oldt);
                initialized = true;
            }
            tty = oldt;
            tty.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        } else {
            if (initialized) {
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            }
        }
    }

public:
    static Botan::secure_vector<uint8_t> readAccessCode(const string& prompt = "Clave de acceso: ", const string& prefix = "") {
        setRawMode(true);
        Botan::secure_vector<uint8_t> code;
        char c;
        const int SHOW_TIME_MS = 50;  

        cout << "\r" << prefix << prompt << flush;

        while (true) {
            ssize_t result = read(STDIN_FILENO, &c, 1);
            if (result != 1) {
                break;
            }

            if (c == '\n' || c == '\r') {
                break;
            }

            if (c == 127 || c == '\b') {
                if (!code.empty()) {
                    code.pop_back();
                    cout << "\r" << prefix << prompt << string(code.size(), '*') << "\033[K" << flush;
                }
                continue;
            }

            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(SHOW_TIME_MS));
            
            code.push_back(static_cast<uint8_t>(c));
            cout << "\r" << prefix << prompt << string(code.size(), '*') << "\033[K" << flush;
        }

        setRawMode(false);
        cout << "\n";
        
        return code;
    }

    static Botan::secure_vector<uint8_t> readAccessCodeWithConfirm(
        const string& prompt = "Clave de acceso: ", 
        const string& confirmPrompt = "Confirmar clave de acceso: ",
        const string& prefix = "") {
        
        Botan::secure_vector<uint8_t> code1, code2;
        int attempts = 0;
        const int MAX_ATTEMPTS = 3;

        while (attempts < MAX_ATTEMPTS) {
            code1 = readAccessCode(prompt, prefix);
            
            if (code1.empty()) {
                cout << RED << "✗ La clave no puede estar vacía" << RESET << endl;
                attempts++;
                continue;
            }

            if (code1.size() < 4) {
                cout << RED << "✗ La clave debe tener al menos 4 caracteres" << RESET << endl;
                code1.clear();
                attempts++;
                continue;
            }

            code2 = readAccessCode(confirmPrompt, prefix);

            bool match = (code1.size() == code2.size() && 
                         secure_memcmp(code1.data(), code2.data(), code1.size()));
            
            if (match) {
                code2.clear();
                return code1;
            } else {
                cout << RED << "✗ Las claves no coinciden. Intento " 
                     << (attempts + 1) << " de " << MAX_ATTEMPTS << RESET << endl;
                code1.clear();
                code2.clear();
                attempts++;
            }
        }

        cout << RED << "✗ Demasiados intentos fallidos" << RESET << endl;
        return Botan::secure_vector<uint8_t>();
    }

    static string readStringNormal(const string& prompt, const string& prefix = "") {
        cout << prefix << prompt;
        string input;
        getline(cin, input);
        return input;
    }
};

// ============================================
// CLASE PRINCIPAL KeyManagerUI
// ============================================

class KeyManagerUI {
private:
    KeyManager& core_;
    
    // ============================================================
    // VERIFICACIÓN DE CONTRASEÑA (movido desde KeyManager original)
    // ============================================================
    bool verifyUserPasswordOnce() {
        if (core_.isPasswordVerified()) {
            return true;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "VERIFICACIÓN DE SEGURIDAD" << BRIGHT_BLUE << "]─────────────────────────────────────────┐\n";
        
        Botan::secure_vector<uint8_t> inputPass = 
            KeySecureInput::readAccessCode("Ingrese su contraseña: ", string(BRIGHT_BLUE) + "│ " + string(RESET));
        
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (inputPass.empty()) {
            cout << RED << "✗ Contraseña vacía" << RESET << endl;
            return false;
        }
        
        bool ok = core_.verifyPassword(inputPass);
        inputPass.clear();
        
        if (!ok) {
            cout << RED << "✗ Contraseña incorrecta. Acceso denegado." << RESET << endl;
            return false;
        }
        
        cout << GREEN << "✓ Acceso concedido." << RESET << endl;
        return true;
    }
    
    // ============================================================
    // HEADER DEL GESTOR
    // ============================================================
    void printKeyManagerHeader() const {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    GESTOR DE CLAVES AES-256                      " << BRIGHT_BLUE << "│\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        
        string userStr = "  Usuario: " + core_.getUsername();
        int spaces1 = 69 - userStr.length();
        if (spaces1 < 0) spaces1 = 0;
        cout << "│" << RESET << "  Usuario: " << BRIGHT_MAGENTA << core_.getUsername() 
             << string(spaces1, ' ') << BRIGHT_BLUE << "│\n";
        
        string countStr = "  Claves almacenadas: " + to_string(core_.keyCount());
        int spaces2 = 69 - countStr.length();
        if (spaces2 < 0) spaces2 = 0;
        cout << "│" << RESET << "  Claves almacenadas: " << BRIGHT_CYAN << core_.keyCount() 
             << string(spaces2, ' ') << BRIGHT_BLUE << "│\n";
        
        if (KeyCryptoUtils::isArgon2Available()) {
            cout << "│" << BRIGHT_GREEN << "  Protección: Argon2id + AES-256-GCM                               " << BRIGHT_BLUE << "│\n";
        }
        
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    // ============================================================
    // MOSTRAR UNA CLAVE (reemplaza KeyInfo::display)
    // ============================================================
    void displayKeyInfo(const KeyInfo& key, int index = -1) const {
        if (index != -1) {
            cout << BRIGHT_BLUE << "[" << index + 1 << "] " << RESET;
        }
        
        cout << BRIGHT_GREEN << key.key_name << RESET;
        
        if (!key.is_active) {
            cout << RED << " (INACTIVA)" << RESET;
        }
        
        cout << "\n";
        cout << "   Tipo: " << BRIGHT_CYAN << key.key_type << RESET << " (" << key.strength << " bits)\n";
        cout << "   Uso: " << BRIGHT_MAGENTA << key.key_usage << RESET << "\n";
        
        char timeStr[100];
        if (key.created_at > 0) {
            struct tm* timeinfo = localtime(&key.created_at);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   Creada: " << BRIGHT_WHITE << timeStr << RESET << "\n";
        }
        
        if (key.last_used > 0) {
            struct tm* timeinfo = localtime(&key.last_used);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   Último uso: " << BRIGHT_YELLOW << timeStr << RESET << "\n";
        }
        
        cout << "   Estado: " << (key.is_active ? BRIGHT_GREEN "ACTIVA" : RED "INACTIVA") << RESET << "\n";
        cout << "\n";
    }
    
    // ============================================================
    // CREAR CLAVE
    // ============================================================
    void createKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                   CREAR NUEVA CLAVE AES-256                     " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string keyName;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "NOMBRE DE LA CLAVE" << BRIGHT_BLUE << "]────────────────────────────────────────────────┐\n";
        keyName = KeySecureInput::readStringNormal("Nombre para identificar la clave: ", string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (keyName.empty()) {
            cout << RED << "\n✗ El nombre de la clave no puede estar vacío" << RESET << endl;
            return;
        }
        
        if (core_.hasKey(keyName)) {
            cout << RED << "\n✗ Ya existe una clave con ese nombre" << RESET << endl;
            return;
        }
        
        string keyUsage;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "USO DE LA CLAVE" << BRIGHT_BLUE << "]───────────────────────────────────────────────────┐\n";
        keyUsage = KeySecureInput::readStringNormal("Para qué usará esta clave: ", string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (keyUsage.empty()) {
            keyUsage = "Cifrado de unidades/Cifrador universal";
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "CLAVE DE ACCESO" << BRIGHT_BLUE << "]───────────────────────────────────────────────────┐\n";
        cout << "│" << RESET << "  Configure una clave de acceso para esta clave.                     " << BRIGHT_BLUE << "│\n";
        
        Botan::secure_vector<uint8_t> accessCode = 
            KeySecureInput::readAccessCodeWithConfirm(
                "Clave de acceso: ", 
                "Confirmar clave de acceso: ", 
                string(BRIGHT_BLUE) + "│ " + string(RESET)
            );
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (accessCode.empty()) {
            cout << RED << "\n✗ La clave de acceso no puede estar vacía" << RESET << endl;
            return;
        }
        
        cout << MAGENTA << "\nGenerando clave AES-256..." << RESET << endl;
        
        string error_out;
        string created = core_.createKey(keyName, keyUsage, accessCode, error_out);
        accessCode.clear();
        
        if (created.empty()) {
            cout << RED << "\n✗ " << error_out << RESET << endl;
            return;
        }
        
        cout << GREEN << "✓ Clave generada exitosamente" << RESET << endl;
        
        cout << GREEN;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                   CLAVE CREADA EXITOSAMENTE                     " << GREEN << "│\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        
        string line1 = "  Nombre: " + keyName;
        int sp1 = 69 - line1.length();
        if (sp1 < 0) sp1 = 0;
        cout << "│" << RESET << "  Nombre: " << BRIGHT_MAGENTA << keyName 
             << RESET << string(sp1, ' ') << GREEN << "│\n";
        
        string line2 = "  Tipo: AES-256 (256 bits)";
        int sp2 = 69 - line2.length();
        if (sp2 < 0) sp2 = 0;
        cout << "│" << RESET << "  Tipo: " << BRIGHT_CYAN << "AES-256 (256 bits)" 
             << RESET << string(sp2, ' ') << GREEN << "│\n";
        
        string line3 = "  Uso: " + keyUsage;
        int sp3 = 69 - line3.length();
        if (sp3 < 0) sp3 = 0;
        cout << "│" << RESET << "  Uso: " << BRIGHT_GREEN << keyUsage 
             << RESET << string(sp3, ' ') << GREEN << "│\n";
        
        string line4 = "  Estado: INACTIVA";
        int sp4 = 69 - line4.length();
        if (sp4 < 0) sp4 = 0;
        cout << "│" << RESET << "  Estado: " << RED << "INACTIVA" 
             << RESET << string(sp4, ' ') << GREEN << "│\n";
        
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        cout << "│" << BRIGHT_BLUE << "   ████╗                                                             " << GREEN << "│\n";
        cout << "│" << BRIGHT_BLUE << "  ██╔═████████████╗                                                  " << GREEN << "│\n";
        cout << "│" << BRIGHT_BLUE << "  ██║   ██╔══██╔══██║                                                " << GREEN << "│\n";
        cout << "│" << BRIGHT_BLUE << "   ╚████╝ ╚═╝  ╚═╝                                                   " << GREEN << "│\n";
        cout << GREEN << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    // ============================================================
    // ACTIVAR / DESACTIVAR
    // ============================================================
    void toggleKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                  ACTIVAR/DESACTIVAR CLAVE                       " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (core_.getKeys().empty()) {
            cout << YELLOW << "\nNo hay claves almacenadas." << RESET << endl;
            return;
        }
        
        cout << "\nClaves disponibles:\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            keyNames.push_back(pair.first);
            index++;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "SELECCIONAR CLAVE" << BRIGHT_BLUE << "]─────────────────────────────────────────────────┐\n";
        string choiceStr = KeySecureInput::readStringNormal("Seleccione el número de la clave: ", string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n✗ Selección inválida" << RESET << endl;
                return;
            }
            
            string selectedKey = keyNames[choice];
            const KeyInfo* keyInfo = core_.getKeyInfo(selectedKey);
            if (!keyInfo) return;
            bool wasActive = keyInfo->is_active;
            
            if (wasActive) {
                string confirm = KeySecureInput::readStringNormal("¿Desactivar la clave \"" + selectedKey + "\"? (s/N): ");
                
                if (confirm != "s" && confirm != "S") {
                    cout << "Operación cancelada." << endl;
                    return;
                }
                
                string error_out;
                Botan::secure_vector<uint8_t> emptyCode;
                if (core_.toggleKey(selectedKey, emptyCode, error_out)) {
                    cout << GREEN << "\n✓ Clave desactivada" << RESET << endl;
                } else {
                    cout << RED << "\n✗ " << error_out << RESET << endl;
                }
                return;
            }
            
            // Activar
            Botan::secure_vector<uint8_t> inputCode;
            if (keyInfo->requires_access) {
                inputCode = KeySecureInput::readAccessCode(
                    "Clave de acceso para \"" + selectedKey + "\": ", 
                    string(BRIGHT_BLUE) + "│ " + string(RESET));
            }
            
            string confirm = KeySecureInput::readStringNormal("¿Activar la clave \"" + selectedKey + "\"? (s/N): ");
            
            if (confirm != "s" && confirm != "S") {
                cout << "Operación cancelada." << endl;
                inputCode.clear();
                return;
            }
            
            string error_out;
            if (core_.toggleKey(selectedKey, inputCode, error_out)) {
                cout << GREEN << "\n✓ Clave activada" << RESET << endl;
                cout << "Nombre: " << BRIGHT_MAGENTA << selectedKey << RESET << endl;
                cout << "Estado: " << BRIGHT_GREEN << "ACTIVA" << RESET << endl;
            } else {
                cout << RED << "\n✗ " << error_out << RESET << endl;
            }
            
            inputCode.clear();
            
        } catch(...) {
            cout << RED << "\n✗ Selección inválida" << RESET << endl;
        }
    }
    
    // ============================================================
    // LISTAR CLAVES
    // ============================================================
    void listKeysMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    LISTA DE CLAVES AES-256                      " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (core_.getKeys().empty()) {
            cout << YELLOW << "\nNo hay claves almacenadas." << RESET << endl;
            cout << "\nPresione Enter para continuar...";
            cin.get();
            return;
        }
        
        cout << "\nClaves almacenadas (" << core_.keyCount() << "):\n" << endl;
        
        int index = 0;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            index++;
        }
        
        int total = core_.keyCount();
        int activeCount = core_.activeCount();
        int inactiveCount = total - activeCount;
        
        string tStr = to_string(total);
        string aStr = to_string(activeCount);
        string iStr = to_string(inactiveCount);
        int visible_len = string("  Total: ").length() + tStr.length() 
                        + string(" claves | Activas: ").length() + aStr.length() 
                        + string(" | Inactivas: ").length() + iStr.length();
        int spaces = 69 - visible_len;
        if (spaces < 0) spaces = 0;

        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << RESET << "  Total: " << BRIGHT_CYAN << tStr << RESET 
             << " claves | Activas: " << BRIGHT_GREEN << aStr << RESET 
             << " | Inactivas: " << BRIGHT_RED << iStr << RESET 
             << string(spaces, ' ') << BRIGHT_BLUE << "│\n";
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        cout << "\nPresione Enter para continuar...";
        cin.get();
    }
    
    // ============================================================
    // ELIMINAR CLAVE
    // ============================================================
    void deleteKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    ELIMINAR CLAVE                              " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (core_.getKeys().empty()) {
            cout << YELLOW << "\nNo hay claves para eliminar." << RESET << endl;
            return;
        }
        
        cout << "\nClaves disponibles:\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            keyNames.push_back(pair.first);
            index++;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "SELECCIONAR CLAVE A ELIMINAR" << BRIGHT_BLUE << "]──────────────────────────────────────┐\n";
        string choiceStr = KeySecureInput::readStringNormal("Seleccione el número de la clave a eliminar: ", string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n✗ Selección inválida" << RESET << endl;
                return;
            }
            
            string selectedKey = keyNames[choice];
            
            cout << RED << "\n⚠ ADVERTENCIA: Esta acción no se puede deshacer." << RESET << endl;
            string confirm = KeySecureInput::readStringNormal("¿Está seguro que desea eliminar la clave \"" + selectedKey + "\"? (s/N): ");
            
            if (confirm != "s" && confirm != "S") {
                cout << "Operación cancelada." << endl;
                return;
            }
            
            Botan::secure_vector<uint8_t> inputCode;
            const KeyInfo* keyInfo = core_.getKeyInfo(selectedKey);
            if (keyInfo && keyInfo->requires_access && !keyInfo->access_code.empty()) {
                inputCode = KeySecureInput::readAccessCode(
                    "Clave de acceso para confirmar: ", 
                    string(BRIGHT_BLUE) + "│ " + string(RESET));
            }
            
            string error_out;
            if (core_.deleteKey(selectedKey, inputCode, error_out)) {
                cout << GREEN << "\n✓ Clave eliminada" << RESET << endl;
            } else {
                cout << RED << "\n✗ " << error_out << RESET << endl;
            }
            
            inputCode.clear();
            
        } catch(...) {
            cout << RED << "\n✗ Selección inválida" << RESET << endl;
        }
    }
    
public:
    KeyManagerUI(KeyManager& core) : core_(core) {}
    
    // ============================================================
    // MENÚ PRINCIPAL
    // ============================================================
    void showMenu() {
        if (!verifyUserPasswordOnce()) {
            return;
        }
        
        while (true) {
            printKeyManagerHeader();
            
            cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "OPCIONES" << BRIGHT_BLUE << "]──────────────────────────────────────────────────────────┐\n";
            cout << "│" << BRIGHT_GREEN << " [1] " << BRIGHT_MAGENTA << " Crear nueva clave AES-256                                      " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [2] " << BRIGHT_MAGENTA << " Activar/Desactivar clave                                       " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [3] " << BRIGHT_MAGENTA << " Lista de claves                                                " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [4] " << BRIGHT_MAGENTA << " Eliminar clave                                                 " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [5] " << BRIGHT_MAGENTA << " Volver                                                         " << BRIGHT_BLUE << "│\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            string choice = KeySecureInput::readStringNormal(
                "Seleccione opción [" + string(BRIGHT_MAGENTA) + "1-5" + string(BRIGHT_GREEN) + "]: " + string(RESET));
            
            if (choice == "1") {
                createKeyMenu();
            } else if (choice == "2") {
                toggleKeyMenu();
            } else if (choice == "3") {
                listKeysMenu();
            } else if (choice == "4") {
                deleteKeyMenu();
            } else if (choice == "5") {
                core_.saveKeys();
                break;
            } else {
                cout << RED << "\n✗ Opción no válida" << RESET << endl;
            }
        }
    }
};

#endif // UI_KEY_MANAGER_UI_H
