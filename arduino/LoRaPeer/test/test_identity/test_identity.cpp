#include <unity.h>
#include "Identity.h"
#include "ContactBook.h"
#include <cstring>

void setUp(void) {}
void tearDown(void) {}

// ==================== Identity ====================

void test_default_name_from_id(void) {
  // Nombre por defecto deriva del id en hex (4 digitos).
  TEST_ASSERT_EQUAL_STRING("LoRa-1A2B", Identity::defaultName(0x1A2B).c_str());
  TEST_ASSERT_EQUAL_STRING("LoRa-00FF", Identity::defaultName(0x00FF).c_str());
}

void test_identity_set_and_get(void) {
  Identity id;
  id.set(0x1234, "Juan");
  TEST_ASSERT_EQUAL_UINT16(0x1234, id.getId());
  TEST_ASSERT_EQUAL_STRING("Juan", id.getName().c_str());
}

void test_identity_rename(void) {
  Identity id;
  id.set(0x1234, "Juan");
  id.setName("Casa");
  TEST_ASSERT_EQUAL_STRING("Casa", id.getName().c_str());
}

void test_identity_empty_name_falls_back_to_default(void) {
  Identity id;
  id.set(0xABCD, "");
  TEST_ASSERT_EQUAL_STRING("LoRa-ABCD", id.getName().c_str());
}

// ==================== ContactBook ====================

static void fillKey(uint8_t *k, uint8_t v) {
  for (int i = 0; i < 32; i++) k[i] = v + i;
}

void test_contactbook_empty(void) {
  ContactBook cb;
  TEST_ASSERT_EQUAL_INT(0, cb.count());
  TEST_ASSERT_NULL(cb.find(0x10));
}

void test_contactbook_add_and_find(void) {
  ContactBook cb;
  uint8_t key[32]; fillKey(key, 1);
  TEST_ASSERT_TRUE(cb.addOrUpdate(0x10, "Ana", key));
  TEST_ASSERT_EQUAL_INT(1, cb.count());
  const Contact *c = cb.find(0x10);
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_EQUAL_STRING("Ana", c->name.c_str());
  TEST_ASSERT_TRUE(c->hasKey);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(key, c->pubKey, 32);
}

void test_contactbook_no_duplicates_updates(void) {
  ContactBook cb;
  uint8_t k1[32]; fillKey(k1, 1);
  uint8_t k2[32]; fillKey(k2, 9);
  cb.addOrUpdate(0x10, "Ana", k1);
  cb.addOrUpdate(0x10, "Ana2", k2);  // mismo id => actualiza, no duplica
  TEST_ASSERT_EQUAL_INT(1, cb.count());
  const Contact *c = cb.find(0x10);
  TEST_ASSERT_EQUAL_STRING("Ana2", c->name.c_str());
  TEST_ASSERT_EQUAL_UINT8_ARRAY(k2, c->pubKey, 32);
}

void test_contactbook_rename(void) {
  ContactBook cb;
  uint8_t k[32]; fillKey(k, 1);
  cb.addOrUpdate(0x10, "Ana", k);
  TEST_ASSERT_TRUE(cb.rename(0x10, "Anita"));
  TEST_ASSERT_EQUAL_STRING("Anita", cb.find(0x10)->name.c_str());
  TEST_ASSERT_FALSE(cb.rename(0x99, "Nadie"));  // id inexistente
}

void test_contactbook_remove(void) {
  ContactBook cb;
  uint8_t k[32]; fillKey(k, 1);
  cb.addOrUpdate(0x10, "Ana", k);
  cb.addOrUpdate(0x20, "Beto", k);
  TEST_ASSERT_TRUE(cb.remove(0x10));
  TEST_ASSERT_EQUAL_INT(1, cb.count());
  TEST_ASSERT_NULL(cb.find(0x10));
  TEST_ASSERT_NOT_NULL(cb.find(0x20));
  TEST_ASSERT_FALSE(cb.remove(0x10));  // ya no esta
}

void test_contactbook_capacity(void) {
  ContactBook cb;
  uint8_t k[32]; fillKey(k, 1);
  for (int i = 0; i < ContactBook::MAX_CONTACTS; i++) {
    TEST_ASSERT_TRUE(cb.addOrUpdate(0x100 + i, "c", k));
  }
  TEST_ASSERT_EQUAL_INT(ContactBook::MAX_CONTACTS, cb.count());
  // Uno mas (id nuevo) se rechaza; actualizar uno existente sigue OK.
  TEST_ASSERT_FALSE(cb.addOrUpdate(0x999, "extra", k));
  TEST_ASSERT_TRUE(cb.addOrUpdate(0x100, "actualiza", k));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_default_name_from_id);
  RUN_TEST(test_identity_set_and_get);
  RUN_TEST(test_identity_rename);
  RUN_TEST(test_identity_empty_name_falls_back_to_default);
  RUN_TEST(test_contactbook_empty);
  RUN_TEST(test_contactbook_add_and_find);
  RUN_TEST(test_contactbook_no_duplicates_updates);
  RUN_TEST(test_contactbook_rename);
  RUN_TEST(test_contactbook_remove);
  RUN_TEST(test_contactbook_capacity);
  return UNITY_END();
}
