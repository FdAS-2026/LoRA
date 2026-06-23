// InflightTable.h — Tabla acotada de mensajes en vuelo (pending-ACK).
// Lib pura: sin Arduino.h, sin millis(). Recibe `now` por parametro.
// Compila en env:native y env:esp32dev.
#ifndef INFLIGHT_TABLE_H
#define INFLIGHT_TABLE_H

#include <cstdint>
#include <cstddef>

// Maquina de estados: LORA → MQTT → FAIL.
// Capacidad fija CAP=6; blob maximo 305 bytes por slot (5B header MQTT + 300B cifrado).
class InflightTable {
public:
    static const int CAP = 6;

    enum Stage : uint8_t { EMPTY = 0, LORA, MQTT };
    enum DueAction : uint8_t { DUE_NONE = 0, DUE_FALLBACK, DUE_FAIL };

    InflightTable();

    // Agrega un mensaje al primer slot EMPTY.
    // Retorna el indice del slot (0..CAP-1), o -1 si la tabla esta llena o blobLen > capacidad del slot.
    // `now` es el timestamp de inicio del estado LORA (en ms, sin llamar a millis()).
    int add(uint16_t msgId, uint16_t dst,
            const uint8_t* blob, size_t blobLen,
            uint32_t now);

    // Devuelve el indice del slot con el msgId dado, o -1 si no existe.
    int find(uint16_t msgId) const;

    // Libera el slot con el msgId dado (stage → EMPTY). No hace nada si no existe.
    void clearByMsgId(uint16_t msgId);

    // Promueve el slot idx de LORA a MQTT y resetea ts = now.
    void promoteToMqtt(int idx, uint32_t now);

    // Libera directamente un slot por indice (stage → EMPTY).
    void release(int idx);

    // Evalua si el slot idx requiere accion segun el tiempo transcurrido.
    // Usa resta unsigned: wrap-safe ante overflow de uint32_t (Pitfall 1).
    //   LORA y (now - ts) >= loraTimeoutMs  → DUE_FALLBACK
    //   MQTT y (now - ts) >= mqttTimeoutMs  → DUE_FAIL
    //   cualquier otro caso                 → DUE_NONE
    DueAction due(int idx, uint32_t now,
                  uint32_t loraTimeoutMs,
                  uint32_t mqttTimeoutMs) const;

    // Accesores con bounds check: retornan valor centinela si idx esta fuera de rango.
    // stage → EMPTY, msgId/dst → 0, blob → nullptr, blobLen → 0.
    Stage          stage(int idx)   const;
    uint16_t       msgId(int idx)   const;
    uint16_t       dst(int idx)     const;
    const uint8_t* blob(int idx)    const;
    size_t         blobLen(int idx) const;

private:
    struct Slot {
        uint16_t msgId;
        uint16_t dst;
        uint8_t  blob[5 + 300];  // header MQTT (5B) + blob cifrado (<=300B)
        size_t   blobLen;
        uint32_t ts;
        Stage    stage;
    };

    Slot _slots[CAP];
};

#endif  // INFLIGHT_TABLE_H
