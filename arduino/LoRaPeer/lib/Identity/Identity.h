#ifndef IDENTITY_H
#define IDENTITY_H

#include <string>
#include <cstdint>

// Identidad de la placa: un id unico (la "direccion", como un numero de
// telefono) y un nombre editable que otros ven al emparejar. Logica pura.
class Identity {
public:
  Identity() : _id(0), _name("") {}

  // Nombre por defecto derivado del id: "LoRa-XXXX" (hex en mayusculas).
  static std::string defaultName(uint16_t id);

  void set(uint16_t id, const std::string &name);
  void setName(const std::string &name);

  uint16_t getId() const { return _id; }
  // Devuelve el nombre, o el por defecto si esta vacio.
  std::string getName() const;

private:
  uint16_t _id;
  std::string _name;
};

#endif
