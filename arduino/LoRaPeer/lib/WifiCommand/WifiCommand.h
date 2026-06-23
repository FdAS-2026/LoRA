#ifndef WIFI_COMMAND_H
#define WIFI_COMMAND_H

#include <string>

// Credenciales extraidas del comando "SETWIFI:<ssid>:<pass>" recibido por BLE.
// ssid ya tiene trim() aplicado. pass puede contener ':' y puede ser "" (red abierta).
// valid es true solo si el prefijo es correcto, hay separador ':' y ssid no esta vacio.
struct WifiCredentials {
  std::string ssid;  // garantizado no vacio cuando valid == true
  std::string pass;  // puede contener ':'; puede ser "" (red abierta)
  bool valid;
};

// Parsea una linea con formato "SETWIFI:<ssid>:<pass>".
// El PRIMER ':' tras la keyword separa el ssid del resto (que es el pass completo,
// incluyendo cualquier ':' adicional). Devuelve valid=false si el prefijo no es
// exactamente "SETWIFI:", el ssid esta vacio o no hay separador.
WifiCredentials parseSetWifi(const std::string& line);

#endif
