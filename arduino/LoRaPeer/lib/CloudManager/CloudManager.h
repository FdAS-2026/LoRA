#ifndef CLOUD_MANAGER_H
#define CLOUD_MANAGER_H

#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include "MqttCodec.h"

class CloudManager {
private:
  String _mqttServer;
  int _mqttPort;
  String _mqttUser;
  String _mqttPass;
  String _clientId;
  uint16_t _nodeId;

  WiFiClientSecure secureClient;
  PubSubClient mqttClient;

  bool isConfigured;
  unsigned long lastReconnectAttempt;

  // Fix DNS stall: la IP del broker se resuelve UNA vez (fuera del path
  // bloqueante de mqttClient.connect) y se cachea. _dnsResolved indica si
  // _brokerIp es valida; mientras sea false no se intenta el connect TLS.
  IPAddress _brokerIp;
  bool _dnsResolved;

  void reconnect();
  bool ensureDns();

public:
  CloudManager();

  void configure(uint16_t boardId, const String& mqttUser, const String& mqttPass);

  // Funcion pura para pruebas unitarias: devuelve el topic inbox canonico del id dado.
  // Delega en MqttCodec::inboxTopic -> "lorapeer/<idHex4mayus>/inbox".
  String getInboxTopic(uint16_t id);

  void begin();
  void loop();

  bool isConnected();

  // Publica un blob binario en el topic indicado (QoS0 efectivo — PubSubClient no
  // soporta QoS1 en publish; sobre TLS/TCP con ambos online alcanza).
  bool publishBlob(const String& topic, const uint8_t* data, size_t len);

  int getMqttState();
  int getWifiStatus();

  void setCallback(MQTT_CALLBACK_SIGNATURE);
};

#endif
