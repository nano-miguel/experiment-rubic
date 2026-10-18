// src/hardware_detect.h
#ifndef HARDWARE_DETECT_H
#define HARDWARE_DETECT_H

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <cpuid.h>

class HardwareDetect {
public:
    static bool hasAESNI() { 
        static bool aesni = check_aesni(); 
        return aesni; 
    }
    
    static bool hasAVX2() { 
        static bool avx2 = check_avx2(); 
        return avx2; 
    }
    
    static bool hasAVX512() { 
        static bool avx512 = check_avx512(); 
        return avx512; 
    }
    
    static int getCoreCount() { 
        static int cores = std::thread::hardware_concurrency(); 
        return cores > 0 ? cores : 4; 
    }

    // Para la UI del UnitEncryptor (con los checkmarks)
    static std::string getCPUInfoExtended() {
        std::stringstream ss;
        ss << "Núcleos: " << getCoreCount();
        if (hasAESNI())  ss << " | AES-NI: ✓";
        if (hasAVX2())   ss << " | AVX2: ✓";
        if (hasAVX512()) ss << " | AVX-512: ✓";
        return ss.str();
    }

    // Para la UI del UniversalCipher (el formato que tenías)
    static std::string getCPUInfo() {
        std::stringstream ss;
        ss << "Nucleos: " << getCoreCount();
        if (hasAESNI()) ss << " | AES-NI: Si"; else ss << " | AES-NI: No";
        if (hasAVX512()) ss << " | SIMD: AVX-512";
        else if (hasAVX2()) ss << " | SIMD: AVX2";
        else ss << " | SIMD: SSE";
        return ss.str();
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

#endif // HARDWARE_DETECT_H
