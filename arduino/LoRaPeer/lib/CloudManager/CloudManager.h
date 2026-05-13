#ifndef CLOUD_MANAGER_H
#define CLOUD_MANAGER_H

#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>

class CloudManager {
private:
  String _ssid;
  String _password;
  String _mqttServer;
  int _mqttPort;
  String _mqttUser;
  String _mqttPass;
  String _clientId;
  uint8_t _nodeId;
  
  WiFiClientSecure secureClient;
  PubSubClient mqttClient;
  
  bool isConfigured;
  unsigned long lastReconnectAttempt;

  void reconnect();

public:
  CloudManager();
  
  void configure(const String& ssid, const String& password, uint8_t nodeId, const String& mqttUser, const String& mqttPass);
  
  // Funciones puras para pruebas unitarias
  String getTxTopic(uint8_t nodeId);
  String getRxTopic(uint8_t nodeId);
  
  void begin();
  void loop();
  
  bool isConnected();
  bool publishMessage(const String& message);
  
  int getMqttState();
  int getWifiStatus();
  
  void setCallback(MQTT_CALLBACK_SIGNATURE);
};

#endif
