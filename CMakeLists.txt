cmake_minimum_required(VERSION 3.16)

project(RUBIC-A VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

# =========================
# EXECUTABLE
# =========================

# Recoge automáticamente todos los .cpp dentro de src/ y subcarpetas
# (main.cpp, y los que agregues después en cipher/, ui/, etc.)
file(GLOB_RECURSE RUBIC_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.cpp
)

add_executable(RUBIC-A ${RUBIC_SOURCES})

# =========================
# INCLUDE
# =========================

target_include_directories(RUBIC-A PRIVATE
    src
    ${CMAKE_SOURCE_DIR}/external/botan/build/include/botan-3
)

# =========================
# LINK
# =========================

target_link_directories(RUBIC-A PRIVATE
    ${CMAKE_SOURCE_DIR}/external/botan/build/lib
)

target_link_libraries(RUBIC-A PRIVATE
    botan-3
    pthread
    dl
)

# =========================
# RUNTIME FIX (IMPORTANTÍSIMO)
# =========================

set_target_properties(RUBIC-A PROPERTIES
    BUILD_RPATH "${CMAKE_SOURCE_DIR}/external/botan/build/lib"
    INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
)

# =========================
# OPTIMIZATION (General para x86_64)
# =========================

# NOTA: Eliminamos -march=native y -mavx2 para que el binario corra 
# en cualquier procesador x86 de 64 bits (Intel/AMD) sin crashear.
target_compile_options(RUBIC-A PRIVATE
    $<$<CONFIG:Release>:-O3 -flto -DNDEBUG>
)

# =========================
# INSTALL BINARIO
# =========================

install(TARGETS RUBIC-A
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# =========================
# BOTAN LIBS (FIX RUNTIME)
# =========================

install(DIRECTORY
    ${CMAKE_SOURCE_DIR}/external/botan/build/lib/
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILES_MATCHING PATTERN "libbotan-3.so*"
)

# =========================
# DESKTOP FILE
# =========================

install(FILES assets/RUBIC-A.desktop
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications
)

# =========================
# ICONO PNG (250x250 PRO)
# =========================

install(FILES assets/rubic.png
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/256x256/apps
    RENAME rubic-a.png
)

# =========================
# CPACK (.DEB)
# =========================

set(CPACK_GENERATOR "DEB")

set(CPACK_PACKAGE_NAME "rubic-a")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "wallace")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RUBIC-A encrypted system tool")

# 1. Detectar arquitectura de forma dinámica en lugar de hardcodear amd64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
else()
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "all")
endif()

# 2. Forzar el nombre exacto que pediste: rubic-a_0.1.deb
set(CPACK_DEBIAN_FILE_NAME "rubic-a_${PROJECT_VERSION}.deb")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6")

include(CPack)