// test_ratchet.cpp — suite Unity para Ratchet (env:native)
// Corre con: pio test -e native --filter test_ratchet
//
// Verifica la maquina de la cadena (avance, descarte de MKs intermedias,
// direccion canonica, determinismo) con un HMAC fake. El vector de interop con
// HMAC-SHA256 real se fija del lado Dart (ratchet_test.dart) y el firmware usa
// el mismo mbedtls ya interop-verificado para la clave E2E.

#include <unity.h>
#include "Ratchet.h"
#include <string>

void setUp(void) {}
void tearDown(void) {}

// HMAC fake determinista dependiente de key y msg.
static std::string fakeHmac(const std::string &key, const std::string &msg) {
  std::string d(32, 0);
  uint32_t a = 2166136261u;
  for (unsigned char c : key) { a ^= c; a *= 16777619u; d[a % 32] ^= (char)c; }
  for (unsigned char c : msg) { a ^= (c + 7); a *= 16777619u; d[a % 32] ^= (char)(c + 1); }
  for (int i = 0; i < 4; i++) d[i] ^= (char)((a >> (i * 8)) & 0xFF);
  return d;
}
static Ratchet::HmacFn H = fakeHmac;

// ==================== direccion canonica ====================

void test_send_dir_by_pub_order(void) {
  std::string lo(32, 'A'), hi(32, 'B');
  TEST_ASSERT_EQUAL_INT(0, Ratchet::sendDir(lo, hi));  // propia menor -> dir 0
  TEST_ASSERT_EQUAL_INT(1, Ratchet::sendDir(hi, lo));  // propia mayor -> dir 1
}

void test_dirs_are_opposite(void) {
  std::string a(32, 'A'), b(32, 'B');
  // A envia por sendDir(a,b); B recibe por la contraria = sendDir(b,a).
  TEST_ASSERT_TRUE(Ratchet::sendDir(a, b) != Ratchet::sendDir(b, a));
}

// ==================== derivaciones distintas ====================

void test_mk_ck_root_differ(void) {
  std::string ck0(32, 'X');
  std::string root0 = Ratchet::chainRoot(ck0, 0, H);
  std::string root1 = Ratchet::chainRoot(ck0, 1, H);
  std::string mk = Ratchet::messageKey(root0, H);
  std::string ck1 = Ratchet::nextChainKey(root0, H);
  TEST_ASSERT_TRUE(root0 != root1);   // direcciones separadas
  TEST_ASSERT_TRUE(mk != ck1);        // MK != siguiente CK
  TEST_ASSERT_TRUE(mk != root0);
  TEST_ASSERT_EQUAL_UINT32(32, mk.size());
}

// ==================== avance de cadena ====================

void test_derive_in_order(void) {
  std::string ck0(32, 'X');
  std::string root = Ratchet::chainRoot(ck0, 0, H);

  // Emisor: MK del mensaje 0, luego 1, avanzando la cadena.
  std::string ckA;
  std::string mk0 = Ratchet::deriveMessageKey(root, 0, 0, H, ckA);  // msg 0
  std::string ckB;
  std::string mk1 = Ratchet::deriveMessageKey(ckA, 1, 1, H, ckB);   // msg 1 desde ck en idx1
  TEST_ASSERT_TRUE(mk0 != mk1);

  // Receptor que arranca de cero y recibe 0 y 1 debe obtener las mismas MK.
  std::string rckA;
  std::string rmk0 = Ratchet::deriveMessageKey(root, 0, 0, H, rckA);
  std::string rckB;
  std::string rmk1 = Ratchet::deriveMessageKey(rckA, 1, 1, H, rckB);
  TEST_ASSERT_EQUAL_STRING(mk0.c_str(), rmk0.c_str());
  TEST_ASSERT_EQUAL_STRING(mk1.c_str(), rmk1.c_str());
}

void test_derive_with_gap(void) {
  // Receptor pierde el mensaje 1 y recibe directo el 2: avanza have=1 -> target=2.
  std::string ck0(32, 'Y');
  std::string root = Ratchet::chainRoot(ck0, 0, H);

  // Emisor deriva 0,1,2 en orden.
  std::string ck;
  std::string mkS0 = Ratchet::deriveMessageKey(root, 0, 0, H, ck);
  std::string mkS1 = Ratchet::deriveMessageKey(ck, 1, 1, H, ck);
  std::string mkS2 = Ratchet::deriveMessageKey(ck, 2, 2, H, ck);

  // Receptor: recibe 0, luego salta a 2 (have=1, target=2).
  std::string rck;
  std::string rmk0 = Ratchet::deriveMessageKey(root, 0, 0, H, rck);
  std::string rmk2 = Ratchet::deriveMessageKey(rck, 1, 2, H, rck);
  TEST_ASSERT_EQUAL_STRING(mkS0.c_str(), rmk0.c_str());
  TEST_ASSERT_EQUAL_STRING(mkS2.c_str(), rmk2.c_str());
  TEST_ASSERT_TRUE(mkS1 != rmk2);  // la del hueco es distinta
}

void test_backwards_rejected(void) {
  std::string ck0(32, 'Z');
  std::string root = Ratchet::chainRoot(ck0, 0, H);
  std::string out;
  std::string mk = Ratchet::deriveMessageKey(root, 5, 3, H, out);  // have>target
  TEST_ASSERT_EQUAL_STRING("", mk.c_str());
}

// ==================== forward secrecy (estructural) ====================

void test_forward_key_independent(void) {
  // Con solo CK_i (i alto) no se puede recomputar MK_{i-1}: la cadena es
  // one-way (nextChainKey no es invertible). Verificamos que MK_0 no se deriva
  // de CK_1 con las mismas llamadas.
  std::string ck0(32, 'W');
  std::string root = Ratchet::chainRoot(ck0, 0, H);
  std::string mk0 = Ratchet::messageKey(root, H);
  std::string ck1 = Ratchet::nextChainKey(root, H);
  std::string mkFromCk1 = Ratchet::messageKey(ck1, H);
  TEST_ASSERT_TRUE(mk0 != mkFromCk1);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_send_dir_by_pub_order);
  RUN_TEST(test_dirs_are_opposite);
  RUN_TEST(test_mk_ck_root_differ);
  RUN_TEST(test_derive_in_order);
  RUN_TEST(test_derive_with_gap);
  RUN_TEST(test_backwards_rejected);
  RUN_TEST(test_forward_key_independent);
  return UNITY_END();
}
