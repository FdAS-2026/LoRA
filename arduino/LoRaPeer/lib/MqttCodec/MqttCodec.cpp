#include "MqttCodec.h"
#include <cstdio>
#include <cstring>

namespace MqttCodec {

// Genera "lorapeer/<idHex>/inbox".
// idHex: 4 caracteres hexadecimales en MAYUSCULA con padding izquierdo,
// igual que hex16() en main.cpp (snprintf "%04X").
std::string inboxTopic(uint16_t id) {
  char hex[5];
  snprintf(hex, sizeof(hex), "%04X", id);
  return std::string("lorapeer/") + hex + "/inbox";
}

// Serializa [srcHi][srcLo][type][msgIdHi][msgIdLo][blob...] en out.
// Header de 5 bytes: src big-endian (2B) + type (1B) + msgId big-endian (2B).
// Usa memcpy para el blob: preserva bytes 0x00 arbitrarios (sin strlen/strcpy).
// Guard de capacidad: retorna 0 sin escribir si 5+blobLen > outCap.
size_t buildDataPayload(uint16_t src, uint8_t type, uint16_t msgId,
                        const uint8_t* blob, size_t blobLen,
                        uint8_t* out, size_t outCap) {
  if (!blob) blobLen = 0;  // blob==nullptr: ignorar blobLen para evitar retorno incorrecto
  if (blobLen > outCap || outCap - blobLen < 5) return 0;

  out[0] = (src >> 8) & 0xFF;    // srcHi (big-endian)
  out[1] = src & 0xFF;            // srcLo
  out[2] = type;
  out[3] = (msgId >> 8) & 0xFF;  // msgIdHi (big-endian)
  out[4] = msgId & 0xFF;          // msgIdLo

  if (blob && blobLen > 0) {
    memcpy(out + 5, blob, blobLen);
  }

  return 5 + blobLen;
}

// Lee la cabecera de 5 bytes del payload MQTT.
// Guard: rechaza len < 5. Decode big-endian consistente con el parser LoRa (main.cpp).
bool parseDataHeader(const uint8_t* payload, size_t len,
                     uint16_t& src, uint8_t& type, uint16_t& msgId,
                     const uint8_t*& blob, size_t& blobLen) {
  if (!payload || len < 5) return false;

  src   = ((uint16_t)payload[0] << 8) | payload[1];  // big-endian
  type  = payload[2];
  msgId = ((uint16_t)payload[3] << 8) | payload[4];  // big-endian
  blob  = payload + 5;
  blobLen = len - 5;

  return true;
}

}  // namespace MqttCodec
