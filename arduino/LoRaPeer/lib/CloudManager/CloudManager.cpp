#include "CloudManager.h"
#include <WiFi.h>

// Certificado raiz que valida el broker (HiveMQ Cloud usa Let's Encrypt).
// ISRG Root X1, valido hasta 2035-06-04. Permite verificar la cadena TLS del
// broker y evitar ataques man-in-the-middle.
static const char BROKER_ROOT_CA[] PROGMEM = R"CA(-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)CA";

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

  // Validar el certificado del broker contra la CA raiz (TLS seguro).
  secureClient.setCACert(BROKER_ROOT_CA);

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
