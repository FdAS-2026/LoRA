#ifndef HUFFMAN_CODEC_H
#define HUFFMAN_CODEC_H

#include <string>
#include <vector>
#include <cstdint>

// Codec Huffman puro (sin dependencias de Arduino) para comprimir mensajes
// de texto y aprovechar mejor el payload limitado de LoRa (~50 bytes).
//
// Formato del buffer codificado (autodescriptivo, el decodificador
// reconstruye el mismo arbol a partir de la cabecera):
//   [uint32 LE]  longitud original en bytes (0 => buffer vacio)
//   [uint16 LE]  cantidad de simbolos distintos (m)
//   m * { [uint8 simbolo][uint32 LE frecuencia] }
//   bits empaquetados de los codigos (MSB primero)
class HuffmanCodec {
public:
  // Comprime la entrada. Cadena vacia => vector vacio.
  std::vector<uint8_t> encode(const std::string &input);

  // Descomprime. Datos invalidos/incompletos => cadena vacia.
  std::string decode(const std::vector<uint8_t> &data);
};

#endif
