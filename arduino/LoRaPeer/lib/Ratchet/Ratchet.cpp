#include "Ratchet.h"

int Ratchet::sendDir(const std::string &myPub, const std::string &theirPub) {
  return (myPub < theirPub) ? 0 : 1;
}

std::string Ratchet::chainRoot(const std::string &ck0, int dir, const HmacFn &h) {
  return h(ck0, dir == 0 ? std::string("dir0") : std::string("dir1"));
}

std::string Ratchet::messageKey(const std::string &ck, const HmacFn &h) {
  return h(ck, "mk");
}

std::string Ratchet::nextChainKey(const std::string &ck, const HmacFn &h) {
  return h(ck, "ck");
}

std::string Ratchet::deriveMessageKey(const std::string &ckIn, uint32_t have,
                                      uint32_t target, const HmacFn &h,
                                      std::string &ckOut) {
  if (have > target) {
    ckOut = ckIn;
    return "";
  }
  std::string ck = ckIn;
  // Avanzar la cadena hasta `target`, descartando las MKs intermedias.
  for (uint32_t i = have; i < target; i++) {
    ck = nextChainKey(ck, h);
  }
  std::string mk = messageKey(ck, h);
  // Dejar la cadena en target+1 para la proxima.
  ckOut = nextChainKey(ck, h);
  return mk;
}
