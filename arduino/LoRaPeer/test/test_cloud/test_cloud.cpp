#include <Arduino.h>
#include <unity.h>
#include "CloudManager.h"
#include "../../src/secrets.h"

// Test de integracion hardware (env:esp32dev, test_ignore en platformio.ini).
// Verifica conexion TLS real a HiveMQ y publish binario al inbox propio.

CloudManager cloud;

void setUp(void) {
}

void tearDown(void) {
}

void test_cloud_integration_connection_and_publish(void) {
  // Nueva API uint16: configure(boardId, user, pass) — sin ssid/password.
  // WiFi ya fue iniciado externamente (setup del test runner en hardware).
  cloud.configure(0x1001, HIVEMQ_USER, HIVEMQ_PASS);
  cloud.begin();

  // Esperar hasta 30 segundos para la conexion TLS + MQTT
  unsigned long start = millis();
  int lastStatus = -1;
  while (!cloud.isConnected() && millis() - start < 30000) {
    cloud.loop();

    // Imprimir estado de WiFi cada 2 segundos para diagnosticar
    if ((millis() - start) % 2000 < 50) {
      if (WiFi.status() != WL_CONNECTED) {
        Serial.print("Esperando WiFi... Estado: ");
        Serial.println(WiFi.status());
      } else {
        if (lastStatus != WL_CONNECTED) {
          Serial.println("WiFi Conectado! Intentando MQTT...");
          lastStatus = WL_CONNECTED;
        }
      }
    }
    delay(50);
  }

  String errMsg = "Fallo. WiFi_Status=" + String(cloud.getWifiStatus()) + ", MQTT_State=" + String(cloud.getMqttState());
  TEST_ASSERT_TRUE_MESSAGE(cloud.isConnected(), errMsg.c_str());

  // Publicar un blob binario de prueba al inbox propio (nueva API publishBlob).
  uint8_t buf[] = { 0x10, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
  bool success = cloud.publishBlob(cloud.getInboxTopic(0x1001), buf, sizeof(buf));
  TEST_ASSERT_TRUE_MESSAGE(success, "Fallo al publicar el blob en HiveMQ");

  // Mantener vivo un segundo para asegurar el envio de red
  unsigned long keepAlive = millis();
  while (millis() - keepAlive < 2000) {
    cloud.loop();
    delay(10);
  }
}

void setup() {
  delay(2000);

  UNITY_BEGIN();
  RUN_TEST(test_cloud_integration_connection_and_publish);
  UNITY_END();
}

void loop() {
}
