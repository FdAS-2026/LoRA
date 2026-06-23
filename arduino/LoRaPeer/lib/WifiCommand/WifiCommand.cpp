#include "WifiCommand.h"
#include <algorithm>

// Trim de espacios en ambos extremos. Helper local, sin dependencias externas.
static std::string trimSpaces(const std::string& s) {
  const std::string SPACES = " \t\r\n";
  size_t start = s.find_first_not_of(SPACES);
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(SPACES);
  return s.substr(start, end - start + 1);
}

// Parsea "SETWIFI:<ssid>:<pass>".
//
// Algoritmo:
//   1. Verificar prefijo exacto "SETWIFI:" (8 chars) con rfind(…, 0).
//   2. Localizar el PRIMER ':' tras la keyword con find(':', 8).
//      Equivalente al indexOf(':', 5) del handler SEND (main.cpp:410) pero
//      con keyword de longitud 8 en lugar de 5.
//   3. Si no hay separador (npos) o esta en posicion 8 (ssid vacio), invalido.
//   4. ssid = substr(8, sep-8) con trim; pass = substr(sep+1) SIN trim
//      (conserva cualquier ':' o espacio en la contrasena).
//   5. valid = !ssid.empty() (pass vacia es valida: red abierta).
//
// Nota de seguridad: la pass se almacena en NVS en texto plano
// (decision aceptada; ver RESEARCH §NVS — limitacion del hardware ESP32).
WifiCredentials parseSetWifi(const std::string& line) {
  const std::string PREFIX = "SETWIFI:";
  const size_t PREFIX_LEN = PREFIX.size();  // 8

  // Verificar prefijo exacto.
  if (line.rfind(PREFIX, 0) != 0) {
    return {"", "", false};
  }

  // Buscar el PRIMER ':' que delimita ssid del pass.
  size_t sep = line.find(':', PREFIX_LEN);
  if (sep == std::string::npos) {
    // No hay separador => falta el ':' entre ssid y pass.
    return {"", "", false};
  }

  // Extraer ssid y aplicar trim.
  std::string ssid = trimSpaces(line.substr(PREFIX_LEN, sep - PREFIX_LEN));
  if (ssid.empty()) {
    // ssid vacio (e.g. "SETWIFI::algo") => invalido.
    return {"", "", false};
  }

  // Pass: todo lo que sigue al separador, sin modificar (puede tener ':').
  std::string pass = line.substr(sep + 1);

  return {ssid, pass, true};
}
