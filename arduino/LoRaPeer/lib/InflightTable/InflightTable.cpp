// InflightTable.cpp — Implementacion de la tabla de mensajes en vuelo.
// Sin Arduino.h. Recibe `now` por parametro (nunca llama a millis()).
#include "InflightTable.h"
#include <cstring>

InflightTable::InflightTable() {
    for (int i = 0; i < CAP; i++) {
        _slots[i].stage   = EMPTY;
        _slots[i].msgId   = 0;
        _slots[i].dst     = 0;
        _slots[i].blobLen = 0;
        _slots[i].ts      = 0;
    }
}

int InflightTable::add(uint16_t msgId, uint16_t dst,
                       const uint8_t* blob, size_t blobLen,
                       uint32_t now) {
    if (blobLen > sizeof(_slots[0].blob)) return -1;  // payload no cabe en el slot
    for (int i = 0; i < CAP; i++) {
        if (_slots[i].stage == EMPTY) {
            _slots[i].msgId   = msgId;
            _slots[i].dst     = dst;
            _slots[i].blobLen = blobLen;
            if (blob && blobLen > 0) {
                memcpy(_slots[i].blob, blob, blobLen);
            }
            _slots[i].ts    = now;
            _slots[i].stage = LORA;
            return i;
        }
    }
    return -1;  // tabla llena
}

int InflightTable::find(uint16_t msgId) const {
    for (int i = 0; i < CAP; i++) {
        if (_slots[i].stage != EMPTY && _slots[i].msgId == msgId) {
            return i;
        }
    }
    return -1;
}

void InflightTable::clearByMsgId(uint16_t msgId) {
    for (int i = 0; i < CAP; i++) {
        if (_slots[i].stage != EMPTY && _slots[i].msgId == msgId) {
            _slots[i].stage = EMPTY;
            return;
        }
    }
}

void InflightTable::promoteToMqtt(int idx, uint32_t now) {
    if (idx < 0 || idx >= CAP) return;
    _slots[idx].stage = MQTT;
    _slots[idx].ts    = now;
}

void InflightTable::release(int idx) {
    if (idx < 0 || idx >= CAP) return;
    _slots[idx].stage = EMPTY;
}

InflightTable::DueAction InflightTable::due(int idx, uint32_t now,
                                            uint32_t loraTimeoutMs,
                                            uint32_t mqttTimeoutMs) const {
    if (idx < 0 || idx >= CAP) return DUE_NONE;
    const Slot& s = _slots[idx];

    // Resta unsigned: wrap-safe ante overflow de uint32_t (Pitfall 1).
    // (uint32_t)(now - s.ts) da el delta correcto incluso cuando now < s.ts.
    uint32_t elapsed = (uint32_t)(now - s.ts);

    if (s.stage == LORA && elapsed >= loraTimeoutMs) {
        return DUE_FALLBACK;
    }
    if (s.stage == MQTT && elapsed >= mqttTimeoutMs) {
        return DUE_FAIL;
    }
    return DUE_NONE;
}

InflightTable::Stage InflightTable::stage(int idx) const {
    if (idx < 0 || idx >= CAP) return EMPTY;
    return _slots[idx].stage;
}

uint16_t InflightTable::msgId(int idx) const {
    if (idx < 0 || idx >= CAP) return 0;
    return _slots[idx].msgId;
}

uint16_t InflightTable::dst(int idx) const {
    if (idx < 0 || idx >= CAP) return 0;
    return _slots[idx].dst;
}

const uint8_t* InflightTable::blob(int idx) const {
    if (idx < 0 || idx >= CAP) return nullptr;
    return _slots[idx].blob;
}

size_t InflightTable::blobLen(int idx) const {
    if (idx < 0 || idx >= CAP) return 0;
    return _slots[idx].blobLen;
}
