#include "Identity.h"

std::string Identity::defaultName(uint16_t id) {
  static const char *hex = "0123456789ABCDEF";
  std::string s = "LoRa-";
  s += hex[(id >> 12) & 0xF];
  s += hex[(id >> 8) & 0xF];
  s += hex[(id >> 4) & 0xF];
  s += hex[id & 0xF];
  return s;
}

void Identity::set(uint16_t id, const std::string &name) {
  _id = id;
  _name = name;
}

void Identity::setName(const std::string &name) {
  _name = name;
}

std::string Identity::getName() const {
  return _name.empty() ? defaultName(_id) : _name;
}
