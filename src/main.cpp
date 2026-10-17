#include "rubic_core.h"
#include "ui/rubic_core_ui.h"
#include "ui/translator.h"   // explícito hasta que rubic_core.h lo incluya (Commit 2)

int main(int argc, char* argv[]) {
    try {
        // AVISO DE RESPONSABILIDAD 
        std::cout << GREEN << "rubi-c es un codigo abierto y de uso libre no me responsabiliso por el mal uso de la herramiento o perdida de datos es una herramienta en fase alpha\n" << RESET << std::endl;
        
        std::cout << "\033[2J\033[1;1H";
        Memguardin::lockProcess();
        CrashHnd::setup();
        
        // ▼▼▼ NUEVO: modo worker elevado (--unit-op) ▼▼▼
        // Si el binario fue lanzado por sudo desde tryElevatedProcess(),
        // corre la operación y sale. Si no, sigue con el arranque normal.
        int worker_rc = UnitEncryptor::tryRunAsWorker(argc, argv);
        if (worker_rc >= 0) {
            Memguardin::unlockProcess();
            return worker_rc;
        }
        // ▲▲▲ NUEVO ▲▲▲

        // ============================================================
        // SMOKE TEST i18n — BORRAR cuando valides el Commit 1
        // ============================================================
        {
            auto& tr = Translator::instance();
            std::cout << "\n=== i18n smoke test ===\n";
            std::cout << "dir:   " << Translator::translationsDir() << "\n";
            std::cout << "langs: ";
            for (auto& l : tr.availableLangs()) std::cout << l << " ";
            std::cout << "\n\n";

            // --- Anchos UTF-8 ---
            struct { const char* s; size_t expect; } cases[] = {
                {"hello",        5},
                {"Contraseña",  10},
                {"\u5bc6\u7801", 4},              // 密码
                {"\u65e5\u672c\u8a9e\u3067\u3059", 10},  // 日本語です
                {"\u043f\u0430\u0440\u043e\u043b\u044c", 6},  // пароль
            };
            bool widths_ok = true;
            for (auto& c : cases) {
                size_t w = utf8_width(c.s);
                bool ok = (w == c.expect);
                if (!ok) widths_ok = false;
                std::cout << "utf8_width('" << c.s << "') = " << w
                          << (ok ? "  \u2713" : "  \u2717 esperado ")
                          << (ok ? "" : std::to_string(c.expect).c_str()) << "\n";
            }

            // --- Truncado ---
            std::cout << "\ntruncate('\u65e5\u672c\u8a9e\u3067\u3059', 4) = "
                      << truncate_utf8("\u65e5\u672c\u8a9e\u3067\u3059", 4)
                      << "  (esperado '\u65e5\u2026')\n";
            std::cout << "truncate('Contrase\u00f1a', 5) = "
                      << truncate_utf8("Contrase\u00f1a", 5)
                      << " (esperado 'Cont\u2026')\n";

            // --- Carga real y fallback ---
            for (const char* L : {"es", "en"}) {
                if (!tr.load(L)) {
                    std::cout << "\n" << L << ": FALLO AL CARGAR\n";
                    continue;
                }
                std::cout << "\n--- " << L << " (" << tr.currentLang() << ") ---\n";
                std::cout << "  login_title       = " << tr.t("login_title") << "\n";
                std::cout << "  login_ok          = " << tr.t("login_ok", {"wallace"}) << "\n";
                std::cout << "  main_menu_title   = " << tr.t("main_menu_title", {"wallace"}) << "\n";
                std::cout << "  tofu_title        = " << tr.t("tofu_title") << "\n";
                std::cout << "  mitm_detail       = " << tr.t("mitm_detail", {"evil.corp"}) << "\n";
                std::cout << "  log_unit_hmac_ok  = " << tr.t("log_unit_hmac_verified") << "\n";
            }

            // Reset a español para que el login se vea en ese idioma
            tr.load("es");
            std::cout << "\n=== fin smoke test (widths_ok="
                      << (widths_ok ? "true" : "false") << ") ===\n\n";
            std::cout << "Presione Enter para continuar al login...";
            std::string dummy;
            std::getline(std::cin, dummy);
        }
        // ============================================================
        // FIN SMOKE TEST
        // ============================================================

        // Idioma default antes del login (el usuario real se carga en authenticate())
        TR().load("es");
        
        UserMgr um;
        RubicCoreUI ui(um);
        ui.run();
    } 
    catch (const std::exception& e) {
        std::cerr << RED << "\n\u2717 ERROR: " << e.what() << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }
    catch (...) {
        std::cerr << RED << "\n\u2717 ERROR DESCONOCIDO" << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }

    Memguardin::unlockProcess();
    return 0;
}