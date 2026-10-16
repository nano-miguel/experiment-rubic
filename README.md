# RUBIC-A

Herramienta de cifrado de unidades y archivos para Linux.
Cifrado AES-256 (XTS y GCM), firmas post-cuánticas (Dilithium + Kyber) via Botan 3.

Estado: **alpha (v0.1.0)** — en desarrollo activo, no usar en datos críticos todavía.

---

## Qué hace

- Cifrado de unidades completas con AES-256-XTS
- Cifrado de archivos y directorios con AES-256-GCM
- Ofuscación de nombres de archivo
- Gestor de claves propio cifrado con la contraseña del usuario
- Compartir archivos P2P con KEM post-cuántico y TOFU
- Sistema multi-usuario con Argon2id y binding al hardware
- Interfaz de terminal

---

## Requisitos

- Linux (probado en Ubuntu 24.04, kernel 6.x)
- GCC 13+ o Clang 17+ con soporte C++20
- CMake 3.16+
- Botan 3 (incluido en `external/botan/build/`)
- Permisos de administrador para operaciones sobre discos

---

## Compilar

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
