#include "ContactBook.h"
#include <cstring>

int ContactBook::indexOf(uint16_t id) const {
  for (int i = 0; i < _count; i++) {
    if (_contacts[i].id == id) return i;
  }
  return -1;
}

bool ContactBook::addOrUpdate(uint16_t id, const std::string &name,
                              const uint8_t *pubKey) {
  int idx = indexOf(id);
  if (idx < 0) {
    if (_count >= MAX_CONTACTS) return false;  // agenda llena
    idx = _count++;
    _contacts[idx].id = id;
  }
  _contacts[idx].name = name;
  if (pubKey != nullptr) {
    memcpy(_contacts[idx].pubKey, pubKey, 32);
    _contacts[idx].hasKey = true;
  } else if (idx == _count - 1) {
    // contacto nuevo sin clave
    _contacts[idx].hasKey = false;
  }
  return true;
}

bool ContactBook::rename(uint16_t id, const std::string &name) {
  int idx = indexOf(id);
  if (idx < 0) return false;
  _contacts[idx].name = name;
  return true;
}

bool ContactBook::remove(uint16_t id) {
  int idx = indexOf(id);
  if (idx < 0) return false;
  for (int i = idx; i < _count - 1; i++) {
    _contacts[i] = _contacts[i + 1];
  }
  _count--;
  return true;
}

const Contact *ContactBook::find(uint16_t id) const {
  int idx = indexOf(id);
  return idx < 0 ? nullptr : &_contacts[idx];
}
