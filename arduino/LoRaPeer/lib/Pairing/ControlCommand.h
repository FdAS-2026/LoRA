#ifndef CONTROL_COMMAND_H
#define CONTROL_COMMAND_H

#include <string>

// Comandos de control que el telefono envia a la placa por BLE.
enum CommandType {
  CMD_NONE,
  CMD_PAIR,     // "PAIR:<pin>"  -> iniciar emparejamiento con otra placa
  CMD_UNPAIR,   // "UNPAIR"      -> deshacer el emparejamiento de placas
  CMD_UNLINK,   // "UNLINK"      -> borrar el bonding BLE de este telefono
  CMD_STATUS    // "STATUS"      -> pedir el estado actual
};

struct Command {
  CommandType type;
  std::string arg;
};

// Parsea una linea de control. Recorta espacios y es insensible a mayusculas
// en la palabra clave. Devuelve CMD_NONE si no se reconoce.
Command parseControlCommand(const std::string &line);

#endif
