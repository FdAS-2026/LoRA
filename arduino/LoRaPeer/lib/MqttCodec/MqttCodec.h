#ifndef MQTT_CODEC_H
#define MQTT_CODEC_H

#include <string>
#include <cstdint>
#include <cstddef>

// Logica pura de topic y serializacion del payload MQTT.
// Sin dependencias de frameworks de hardware ni librerias de red.
// Compila en env:native (std::string + buffers uint8_t).
namespace MqttCodec {

  // Devuelve "lorapeer/<idHex>/inbox" donde idHex son 4 caracteres
  // hexadecimales en MAYUSCULA con padding a la izquierda (ej. "0001", "ABCD").
  std::string inboxTopic(uint16_t id);

  // Serializa [srcHi][srcLo][type][msgIdHi][msgIdLo][blob...] en out.
  // Header de 5 bytes: src (big-endian, 2B) + type (1B) + msgId (big-endian, 2B).
  // Devuelve bytes escritos (5 + blobLen), o 0 si no cabe en outCap.
  // Usa memcpy: preserva bytes 0x00 arbitrarios del blob.
  // Si blob es nullptr o blobLen es 0, escribe solo el header (retorna 5).
  size_t buildDataPayload(uint16_t src, uint8_t type, uint16_t msgId,
                          const uint8_t* blob, size_t blobLen,
                          uint8_t* out, size_t outCap);

  // Lee la cabecera de 5 bytes. Devuelve false si len < 5.
  // Setea src (big-endian de payload[0..1]), type (payload[2]),
  // msgId (big-endian de payload[3..4]), blob (puntero a payload+5)
  // y blobLen (len-5).
  bool parseDataHeader(const uint8_t* payload, size_t len,
                       uint16_t& src, uint8_t& type, uint16_t& msgId,
                       const uint8_t*& blob, size_t& blobLen);

}  // namespace MqttCodec

#endif  // MQTT_CODEC_H
