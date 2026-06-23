// DedupRing.h — Ring buffer de pares (src, msgId) para deduplicacion.
// Lib pura: sin Arduino.h. Compila en env:native y env:esp32dev.
#ifndef DEDUP_RING_H
#define DEDUP_RING_H

#include <cstdint>

// Ring buffer circular de CAP=8 entradas (src, msgId).
// Desaloja la entrada mas antigua cuando el ring esta lleno.
// Usa flag `valid` como centinela: evita falsos positivos con valores iniciales.
class DedupRing {
public:
    static const int CAP = 8;

    DedupRing();

    // Retorna true si el par (src, msgId) ya fue visto (NO lo re-registra).
    // Retorna false si es nuevo: lo registra en el ring y avanza head.
    bool seen(uint16_t src, uint16_t msgId);

private:
    struct Entry {
        uint16_t src;
        uint16_t msgId;
        bool     valid;  // centinela: true solo si la entrada fue escrita
    };

    Entry _entries[CAP];
    int   _head;  // proximo slot a sobrescribir
};

#endif  // DEDUP_RING_H
