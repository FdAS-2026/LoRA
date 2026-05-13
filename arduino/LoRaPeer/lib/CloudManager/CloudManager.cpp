#include "CloudManager.h"
#include <WiFi.h>

CloudManager::CloudManager() : mqttClient(secureClient) {
  isConfigured = false;
  lastReconnectAttempt = 0;
  _mqttServer = "ea2b2d4f22754a798415f56a0516657b.s1.eu.hivemq.cloud";
  _mqttPort = 8883;
}

String CloudManager::getTxTopic(uint8_t nodeId) {
  return "lorapeer/node" + String(nodeId) + "/tx";
}

String CloudManager::getRxTopic(uint8_t nodeId) {
  return "lorapeer/node" + String(nodeId) + "/rx";
}

void CloudManager::configure(const String& ssid, const String& password, uint8_t nodeId, const String& mqttUser, const String& mqttPass) {
  _ssid = ssid;
  _password = password;
  _nodeId = nodeId;
  
  _mqttUser = mqttUser;
  _mqttPass = mqttPass;
  _clientId = "ESP32_Node_" + String(nodeId) + "_" + String(random(0xffff), HEX);
  
  isConfigured = true;
}

void CloudManager::setCallback(MQTT_CALLBACK_SIGNATURE) {
  mqttClient.setCallback(callback);
}

void CloudManager::begin() {
  if (!isConfigured) return;
  
  Serial.print("Conectando a WiFi: ");
  Serial.println(_ssid);
  
  WiFi.begin(_ssid.c_str(), _password.c_str());
  
  // Ignorar validación de certificados para simplificar pruebas
  secureClient.setInsecure();
  
  mqttClient.setServer(_mqttServer.c_str(), _mqttPort);
}

void CloudManager::reconnect() {
  if (WiFi.status() != WL_CONNECTED) {
    return; // No intentar MQTT si no hay WiFi
  }
  
  if (millis() - lastReconnectAttempt > 5000) {
    lastReconnectAttempt = millis();
    Serial.print("Intentando conexión MQTT a HiveMQ... ");
    
    if (mqttClient.connect(_clientId.c_str(), _mqttUser.c_str(), _mqttPass.c_str())) {
      Serial.println("¡Conectado a HiveMQ!");
      // Suscribirse al topic de recepción de este nodo
      String rxTopic = getRxTopic(_nodeId);
      mqttClient.subscribe(rxTopic.c_str());
      Serial.println("Suscrito a: " + rxTopic);
    } else {
      int state = mqttClient.state();
      Serial.print("Falló, código de error: ");
      Serial.print(state);
      Serial.print(" (");
      if (state == -2) Serial.print("Fallo de conexión TLS/SSL");
      else if (state == -4) Serial.print("Timeout de red");
      else if (state == 4) Serial.print("Credenciales inválidas");
      else if (state == 5) Serial.print("No autorizado");
      else Serial.print("Ver PubSubClient.h para el código");
      Serial.println(") - intentando de nuevo en 5 segundos");
    }
  }
}

void CloudManager::loop() {
  if (!isConfigured) return;
  
  if (WiFi.status() == WL_CONNECTED) {
    if (!mqttClient.connected()) {
      reconnect();
    } else {
      mqttClient.loop();
    }
  }
}

bool CloudManager::isConnected() {
  return (WiFi.status() == WL_CONNECTED && mqttClient.connected());
}

bool CloudManager::publishMessage(const String& message) {
  if (isConnected()) {
    String txTopic = getTxTopic(_nodeId);
    return mqttClient.publish(txTopic.c_str(), message.c_str());
  }
  return false;
}

int CloudManager::getMqttState() { return mqttClient.state(); }
int CloudManager::getWifiStatus() { return WiFi.status(); }
