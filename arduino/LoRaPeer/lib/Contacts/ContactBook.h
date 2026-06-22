#ifndef CONTACT_BOOK_H
#define CONTACT_BOOK_H

#include <string>
#include <cstdint>

// Un contacto = otra placa emparejada (otra persona): su id, su nombre y su
// clave publica X25519 (32 bytes) para el cifrado E2E.
struct Contact {
  uint16_t id;
  std::string name;
  uint8_t pubKey[32];
  bool hasKey;
};

// Agenda de contactos de la placa. Logica pura (sin Arduino), testeable.
class ContactBook {
public:
  static const int MAX_CONTACTS = 16;

  ContactBook() : _count(0) {}

  // Agrega o actualiza por id (no duplica). pubKey puede ser null (sin clave).
  // Devuelve false si esta llena y el id es nuevo.
  bool addOrUpdate(uint16_t id, const std::string &name, const uint8_t *pubKey);
  bool rename(uint16_t id, const std::string &name);
  bool remove(uint16_t id);

  const Contact *find(uint16_t id) const;
  int count() const { return _count; }
  const Contact &get(int index) const { return _contacts[index]; }

private:
  Contact _contacts[MAX_CONTACTS];
  int _count;
  int indexOf(uint16_t id) const;
};

#endif
