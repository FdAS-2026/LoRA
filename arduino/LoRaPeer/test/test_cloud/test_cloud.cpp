#include <Arduino.h>
#include <unity.h>
#include "CloudManager.h"
#include "../../src/secrets.h"

CloudManager cloud;

void setUp(void) {
}

void tearDown(void) {
}

void test_cloud_integration_connection_and_publish(void) {
  cloud.configure(WIFI_SSID, WIFI_PASSWORD, 1, HIVEMQ_USER_NODE1, HIVEMQ_PASS_NODE1);
  cloud.begin();
  
  // Esperar hasta 30 segundos para la conexión WiFi + TLS
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
  
  // Publicar un mensaje de integración
  bool success = cloud.publishMessage("PRUEBA DE INTEGRACION OK - " + String(millis()));
  TEST_ASSERT_TRUE_MESSAGE(success, "Fallo al publicar el mensaje en HiveMQ");
  
  // Mantener vivo un segundo para asegurar el envío de red
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
