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
  _dnsResolved = false;
  _nodeId = 0;
  _mqttServer = "ea2b2d4f22754a798415f56a0516657b.s1.eu.hivemq.cloud";
  _mqttPort = 8883;
}

// Funcion pura: delega en MqttCodec para el formato canonico de topic
// -> "lorapeer/<idHex4mayus>/inbox". NO re-implementa el snprintf.
String CloudManager::getInboxTopic(uint16_t id) {
  return String(MqttCodec::inboxTopic(id).c_str());
}

void CloudManager::configure(uint16_t boardId, const String& mqttUser, const String& mqttPass) {
  _nodeId = boardId;
  _mqttUser = mqttUser;
  _mqttPass = mqttPass;
  // clientId unico por placa: evita que dos placas con el mismo usuario
  // se desconecten mutuamente (pitfall clientId duplicado).
  _clientId = "ESP32_Node_" + String(_nodeId) + "_" + String(random(0xffff), HEX);
  isConfigured = true;
}

void CloudManager::setCallback(MQTT_CALLBACK_SIGNATURE) {
  mqttClient.setCallback(callback);
}

void CloudManager::begin() {
  if (!isConfigured) return;
  // Phase 1 es dueno del WiFi (la conexion se inicia en setup() de main.cpp).
  // begin() solo configura TLS y el servidor MQTT; no modifica el estado WiFi.

  // Fix B-01: acotar el handshake TLS para evitar stall indefinido en hardware.
  // setTimeout: timeout del socket TCP (en SEGUNDOS en WiFiClientSecure/ESP32).
  // setHandshakeTimeout: timeout del handshake TLS (en SEGUNDOS, NO en ms).
  // RIESGO PENDIENTE (validar en hardware): si el DNS tarda mas de 10 s,
  // el stall puede ocurrir antes del handshake y estos timeouts no lo cubren.
  secureClient.setTimeout(10);           // socket TCP: 10 s
  secureClient.setHandshakeTimeout(10);  // TLS handshake: 10 s (en segundos)

  secureClient.setCACert(BROKER_ROOT_CA);
  // El servidor MQTT se fija por IP en ensureDns() tras resolver el hostname,
  // para sacar la resolucion DNS del path bloqueante de mqttClient.connect().
}

// Resuelve el hostname del broker a IP una sola vez y fija el servidor MQTT por
// IP. WiFi.hostByName esta acotado por el timeout del resolver lwip (no queda
// colgado indefinidamente). Devuelve true si _brokerIp es valida y usable.
// Al separar el DNS del connect TLS, un fallo de DNS ya no arrastra el stall
// de 2-5 s del handshake: se reintenta barato en el proximo ciclo.
bool CloudManager::ensureDns() {
  if (_dnsResolved) return true;
  IPAddress ip;
  if (WiFi.hostByName(_mqttServer.c_str(), ip) == 1 && ip != IPAddress(0, 0, 0, 0)) {
    _brokerIp = ip;
    _dnsResolved = true;
    mqttClient.setServer(_brokerIp, _mqttPort);
    Serial.println("[MQTT] DNS resuelto: " + _brokerIp.toString());
    return true;
  }
  Serial.println("[MQTT] DNS del broker no resuelto - reintento en 5 s");
  return false;
}

void CloudManager::reconnect() {
  if (WiFi.status() != WL_CONNECTED) {
    _dnsResolved = false;  // al reconectar WiFi puede cambiar la red/DNS
    return; // No intentar MQTT si no hay WiFi
  }

  if (millis() - lastReconnectAttempt > 5000) {
    lastReconnectAttempt = millis();
    // Resolver DNS antes del connect TLS; si falla, no bloquear con el handshake.
    if (!ensureDns()) return;
    Serial.print("Intentando conexion MQTT a HiveMQ... ");

    if (mqttClient.connect(_clientId.c_str(), _mqttUser.c_str(), _mqttPass.c_str())) {
      Serial.println("Conectado a HiveMQ!");
      // Suscribirse al inbox propio con QoS1: el broker reentrega si se pierde el PUBACK.
      String inboxTopic = getInboxTopic(_nodeId);
      if (!mqttClient.subscribe(inboxTopic.c_str(), 1)) {
        Serial.println("[MQTT] ERR: subscribe fallo - sin mensajes entrantes");
        mqttClient.disconnect();
      } else {
        Serial.println("Suscrito a: " + inboxTopic);
      }
      Serial.printf("[MEM] heap=%u minheap=%u stackHWM=%u\n",
                    ESP.getFreeHeap(), ESP.getMinFreeHeap(),
                    uxTaskGetStackHighWaterMark(NULL));
    } else {
      int state = mqttClient.state();
      Serial.print("Fallo, codigo de error: ");
      Serial.print(state);
      Serial.print(" (");
      if (state == -2) Serial.print("Fallo de conexion TLS/SSL");
      else if (state == -4) Serial.print("Timeout de red");
      else if (state == 4) Serial.print("Credenciales invalidas");
      else if (state == 5) Serial.print("No autorizado");
      else Serial.print("Ver PubSubClient.h para el codigo");
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

bool CloudManager::publishBlob(const String& topic, const uint8_t* data, size_t len) {
  // publish es QoS0 efectivo (PubSubClient no soporta QoS1 en publish);
  // sobre TLS/TCP con ambos online alcanza.
  if (!isConnected()) return false;
  bool ok = mqttClient.publish(topic.c_str(), data, (unsigned int)len, false);
  if (!ok) {
    Serial.printf("[MQTT] publish fallo, len=%u\n", (unsigned int)len);
  }
  return ok;
}

int CloudManager::getMqttState() { return mqttClient.state(); }
int CloudManager::getWifiStatus() { return WiFi.status(); }
