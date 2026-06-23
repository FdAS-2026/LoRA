// DedupRing.cpp — Implementacion del ring buffer de deduplicacion.
// Sin Arduino.h. Lookup lineal sobre CAP=8 entradas.
#include "DedupRing.h"

DedupRing::DedupRing() : _head(0) {
    for (int i = 0; i < CAP; i++) {
        _entries[i].src   = 0;
        _entries[i].msgId = 0;
        _entries[i].valid = false;  // centinela: no matchea hasta que se escriba
    }
}

bool DedupRing::seen(uint16_t src, uint16_t msgId) {
    // Scan lineal: buscar el par exacto entre las entradas validas.
    for (int i = 0; i < CAP; i++) {
        if (_entries[i].valid &&
            _entries[i].src   == src &&
            _entries[i].msgId == msgId) {
            // Par ya visto — no re-registrar.
            return true;
        }
    }
    // Par nuevo: sobrescribir el slot mas antiguo (head circular) y avanzar.
    _entries[_head].src   = src;
    _entries[_head].msgId = msgId;
    _entries[_head].valid = true;
    _head = (_head + 1) % CAP;
    return false;
}
