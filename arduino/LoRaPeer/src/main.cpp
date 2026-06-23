#include <Arduino.h>
#include <SPI.h>
#include <LoRa.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLESecurity.h>
#include <esp_gap_ble_api.h>
#include <esp_random.h>
#include "Identity.h"
#include "ContactBook.h"
#include "E2ECrypto.h"
#include "PairingManager.h"
#include "ControlCommand.h"
#include <string>
#include <vector>
#include <WiFi.h>
#include "WifiCommand.h"
#include "CloudManager.h"
#include "MqttCodec.h"
#include "InflightTable.h"
#include "DedupRing.h"
#include "secrets.h"

// Mensajeria E2E sobre LoRa, sin internet (tipo WhatsApp offline):
//   - 1 telefono <-> 1 placa (su identidad; enlace BLE con passkey).
//   - la placa se empareja con varias placas-contacto (intercambio de claves).
//   - cada mensaje se cifra con la clave del contacto destino (X25519+AES-GCM):
//     solo ese contacto lo descifra.

// -------------------- PINOUT
const int LORA_MISO = 19, LORA_SS = 18, LORA_SCK = 5, LORA_MOSI = 27;
const int LORA_RST = 14, LORA_IRQ = 26;
const int OLED_SCL = 15, OLED_SDA = 4, OLED_RST = 16;
const long LORA_FREQ = 915E6;

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RST);

Preferences prefs;
Identity identity;
ContactBook contacts;
E2ECrypto e2e;
PairingManager pairing;
CloudManager cloud;
InflightTable inflight;
DedupRing dedup;

// Contador de msgId para mensajes salientes (uint16_t; 0 reservado para paquetes sin tracking).
static uint16_t _msgCounter = 0;

uint8_t myPriv[32], myPub[32];
bool e2eReady = false;

// Tipos y direcciones de trama LoRa: [dst(2)][src(2)][type(1)][msgId(2)][payload]
// Header de 7 bytes; msgId=0 en paquetes de pairing (no requieren tracking).
const uint8_t TYPE_DATA     = 0;
const uint8_t TYPE_PAIR_REQ = 2;
const uint8_t TYPE_PAIR_ACK = 3;
const uint8_t TYPE_ACK      = 4;  // confirmacion de entrega (sin cifrar)
const uint8_t TYPE_NACK     = 5;  // rechazo de entrega (sin cifrar)
const uint16_t BROADCAST = 0xFFFF;

// -------------------- BLE
#define SERVICE_UUID        "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_RX_UUID "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"  // (no usado, reservado)
#define CHARACTERISTIC_TX_UUID "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"  // notificaciones -> telefono
#define CHARACTERISTIC_CTRL_UUID "6E400004-B5A3-F393-E0A9-E50E24DCCA9E" // comandos <- telefono

bool displayReady = false;
int BLE_clients_connected = 0;
BLEServer *pServer = nullptr;
BLECharacteristic *pTxCharacteristic = nullptr;
uint32_t blePasskey = 0;
bool showingPasskey = false;
String pairingPin = "";
String lastEvent = "";
bool claimed = false;  // un telefono ya se vinculo como dueno

// -------------------- WiFi STA (no bloqueante, sin CloudManager)
enum WifiConnState { WIFI_NO_CREDS, WIFI_CONNECTING, WIFI_CONNECTED, WIFI_NO_NET };
static WifiConnState wifiConnState = WIFI_NO_CREDS;
static String wifiSSID = "";
static String wifiPass  = "";
static unsigned long lastWifiPoll = 0;
static const unsigned long WIFI_POLL_MS = 2000;

// Logs detallados solo en build de prueba (-D DIAG_LOGS).
#ifdef DIAG_LOGS
  #define DLOGF(...) Serial.printf(__VA_ARGS__)
#else
  #define DLOGF(...)
#endif

// ==================== FORWARD DECLARATIONS ====================
void displayStatus();
void displayPasskey(uint32_t passkey);
void displayPairing();
void notifyPhone(const String &s);
void sendFrame(uint16_t dst, uint8_t type, uint16_t msgId, const uint8_t *payload, size_t len);
void sendPairPacket(uint8_t type, uint16_t dst);
void handleControlCommand(const String &line);
void sendToContact(uint16_t dstId, const String &text);
void saveContacts();
void loadContacts();
String wifiStateStr();
void wifiPoll();
void sendAck(uint16_t dst, uint16_t msgId, bool viaLoRa);
void sendNack(uint16_t dst, uint16_t msgId, bool viaLoRa);
void handleDataPacket(uint16_t src, uint16_t msgId, bool viaLoRa, const uint8_t* blob, size_t len);
void onMqttMessage(char* topic, byte* payload, unsigned int length);

// ==================== HELPERS ====================
static String hex16(uint16_t v) {
  char b[5];
  snprintf(b, sizeof(b), "%04X", v);
  return String(b);
}

// Traduce el estado interno WiFi al string que se publica por BLE.
// CONNECTING se reporta como sin_red (transicion; no tiene red aun).
String wifiStateStr() {
  switch (wifiConnState) {
    case WIFI_CONNECTED:  return "conectado";
    case WIFI_NO_NET:     return "sin_red";
    case WIFI_CONNECTING: return "sin_red";
    default:              return "sin_cred";
  }
}

// Poll no bloqueante del estado WiFi (llamar desde loop() cada iteracion).
// Guard millis() evita llamadas excesivas a WiFi.status() que podrian
// interferir con Bluedroid. Notifica por BLE solo cuando el estado cambia.
void wifiPoll() {
  if (wifiConnState == WIFI_NO_CREDS) return;
  unsigned long now = millis();
  if (now - lastWifiPoll < WIFI_POLL_MS) return;
  lastWifiPoll = now;

  WifiConnState prev = wifiConnState;
  wl_status_t st = WiFi.status();
  WifiConnState next;
  if (st == WL_CONNECTED) next = WIFI_CONNECTED;
  else if (st == WL_NO_SSID_AVAIL || st == WL_CONNECT_FAILED || st == WL_CONNECTION_LOST) next = WIFI_NO_NET;
  else next = WIFI_CONNECTING;
  wifiConnState = next;
  if (wifiConnState != prev) {
    notifyPhone("WIFI:" + wifiStateStr());
    displayStatus();
  }
}

// ==================== BLE CALLBACKS ====================
class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *) {
    BLE_clients_connected++;
    DLOGF("[DIAG] BLE onConnect\n");
    displayStatus();
  }
  void onDisconnect(BLEServer *s) {
    if (BLE_clients_connected > 0) BLE_clients_connected--;
    s->getAdvertising()->start();
    displayStatus();
  }
};

class ControlCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *c) {
    String v = c->getValue().c_str();
    v.trim();
    if (v.length() > 0) {
      DLOGF("[DIAG] CTRL: %s\n", v.c_str());
      handleControlCommand(v);
    }
  }
};

class SecurityCallbacks : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() { return 0; }
  void onPassKeyNotify(uint32_t pass_key) {
    blePasskey = pass_key;
    showingPasskey = true;
    DLOGF("[DIAG] passkey=%06u\n", pass_key);
    displayPasskey(pass_key);
  }
  bool onConfirmPIN(uint32_t) { return true; }
  bool onSecurityRequest() { return true; }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) {
    showingPasskey = false;
    Serial.println(cmpl.success ? "BLE bonding OK" : "BLE bonding fallo");
    displayStatus();
  }
};

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(100);

  Wire.begin(OLED_SDA, OLED_SCL);
  displayReady = display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_SS);
  LoRa.setPins(LORA_SS, LORA_RST, LORA_IRQ);
  if (!LoRa.begin(LORA_FREQ)) {
    Serial.println("LoRa init failed.");
    if (displayReady) { display.setCursor(0,0); display.setTextSize(2); display.println("LoRa FAIL"); display.display(); }
    while (1) delay(2000);
  }

  prefs.begin("lora", false);

  // Identidad: boardId unico (se genera una vez) + nombre.
  uint16_t bid = prefs.getUShort("bid", 0);
  if (bid == 0) {
    bid = (uint16_t)(esp_random() & 0xFFFF);
    if (bid == 0 || bid == 0xFFFF) bid = 0x1001;  // evitar 0 y broadcast
    prefs.putUShort("bid", bid);
  }
  String name = prefs.getString("name", "");
  identity.set(bid, std::string(name.c_str()));

  // Par de claves X25519 (se genera una vez y persiste).
  e2eReady = e2e.begin();
  size_t got = prefs.getBytes("e2e_priv", myPriv, 32);
  if (got != 32) {
    if (e2e.generateKeyPair(myPriv, myPub)) {
      prefs.putBytes("e2e_priv", myPriv, 32);
    }
  } else {
    e2e.publicFromPrivate(myPriv, myPub);
  }

  loadContacts();
  claimed = prefs.getBool("claimed", false);

  Serial.printf("Identidad: %s id=%s contactos=%d\n",
                identity.getName().c_str(), hex16(identity.getId()).c_str(),
                contacts.count());

  // WiFi STA: autoconexion al boot si hay credenciales persistidas en NVS.
  // WiFi.begin() retorna inmediatamente; la conexion ocurre en background.
  // NUNCA busy-wait aqui: LoRa y BLE deben seguir funcionando.
  wifiSSID = prefs.getString("wifi_ssid", "");
  wifiPass  = prefs.getString("wifi_pass", "");
  if (wifiSSID.length() > 0) {
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(wifiSSID.c_str(), wifiPass.c_str());
    wifiConnState = WIFI_CONNECTING;
    Serial.printf("[WiFi] Iniciando conexion a '%s'...\n", wifiSSID.c_str());
  }

  // BLE: nombre = identidad. Caracteristicas SIN cifrado obligatorio para que
  // la conexion sea robusta (no depende de bonds que se desincronizan). Los
  // mensajes igual van E2E cifrados de placa a placa por LoRa.
  BLEDevice::init(identity.getName());
  BLEDevice::setPower(ESP_PWR_LVL_P7);

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());
  BLEService *svc = pServer->createService(SERVICE_UUID);

  pTxCharacteristic = svc->createCharacteristic(
      CHARACTERISTIC_TX_UUID,
      BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ);
  pTxCharacteristic->addDescriptor(new BLE2902());

  BLECharacteristic *ctrl = svc->createCharacteristic(
      CHARACTERISTIC_CTRL_UUID,
      BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  ctrl->setCallbacks(new ControlCallbacks());

  svc->start();
  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(SERVICE_UUID);
  adv->setScanResponse(true);
  BLEDevice::startAdvertising();
  BLEDevice::setMTU(185);

  // MQTT cloud: configure -> setCallback (ANTES de begin, pitfall #6) -> begin.
  // begin() solo setea CACert+server; la conexion ocurre cooperativamente en cloud.loop().
  cloud.configure(identity.getId(), HIVEMQ_USER, HIVEMQ_PASS);
  cloud.setCallback(onMqttMessage);
  cloud.begin();

  Serial.println(e2eReady ? "E2ECrypto listo." : "E2ECrypto FALLO.");
  displayStatus();
  Serial.printf("[MEM] Free heap: %u bytes\n", ESP.getFreeHeap());
}

// ==================== LOOP ====================
void loop() {
  // Diagnostico / control por serial (acceso fisico).
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) handleControlCommand(cmd);
  }

  // Recibir LoRa — header 7B: [dst(2)][src(2)][type(1)][msgId(2)][payload]
  int pkt = LoRa.parsePacket();
  if (pkt >= 7) {
    uint16_t dst    = ((uint16_t)LoRa.read() << 8) | LoRa.read();
    uint16_t src    = ((uint16_t)LoRa.read() << 8) | LoRa.read();
    uint8_t  type   = LoRa.read();
    uint16_t msgId  = ((uint16_t)LoRa.read() << 8) | LoRa.read();
    std::vector<uint8_t> payload;
    while (LoRa.available()) payload.push_back((uint8_t)LoRa.read());
    int rssi = LoRa.packetRssi();

    bool forMe = (dst == identity.getId());
    bool bcast = (dst == BROADCAST);

    if (type == TYPE_PAIR_REQ || type == TYPE_PAIR_ACK) {
      // payload: [pairId(2)][pubkey(32)][nameLen(1)][name...]
      if (payload.size() >= 35) {
        uint16_t pairId = ((uint16_t)payload[0] << 8) | payload[1];
        uint8_t theirPub[32];
        memcpy(theirPub, &payload[2], 32);
        uint8_t nameLen = payload[34];
        std::string theirName;
        if (payload.size() >= 35u + nameLen) {
          theirName.assign((char *)&payload[35], nameLen);
        }
        bool known = contacts.find(src) != nullptr;
        DLOGF("[DIAG] RX pair t=%u src=%s pid=%u known=%d\n", type,
              hex16(src).c_str(), pairId, known);
        PairAction act = pairing.onPairPacket(type, pairId, src,
                                              identity.getId(), known);
        if (act != PAIR_NONE) {
          contacts.addOrUpdate(src, theirName, theirPub);
          saveContacts();
          if (act == PAIR_SEND_ACK) sendPairPacket(TYPE_PAIR_ACK, src);
          lastEvent = "Pair: " + String(theirName.c_str());
          notifyPhone("PAIRED:" + hex16(src) + ":" + String(theirName.c_str()));
          Serial.printf("Emparejado con %s (%s)\n", theirName.c_str(),
                        hex16(src).c_str());
          displayStatus();
        }
      }
    } else if (type == TYPE_DATA && forMe) {
      // Deduplicacion: descarta reintentos/duplicados del mismo (src, msgId).
      // Si ya fue procesado, re-emite ACK para que el remitente no reintente.
      if (!dedup.seen(src, msgId)) {
        handleDataPacket(src, msgId, true, payload.data(), payload.size());
      } else {
        DLOGF("[DIAG] duplicado descartado src=%s msgId=%04X\n", hex16(src).c_str(), msgId);
        sendAck(src, msgId, true);  // re-ACK: ya fue procesado, no reintentar
      }
    } else if (type == TYPE_ACK && forMe) {
      int slot = inflight.find(msgId);
      if (slot >= 0) {
        notifyPhone("ACK:" + hex16(msgId) + ":lora");
        inflight.release(slot);
        DLOGF("[DIAG] ACK recibido LoRa msgId=%04X\n", msgId);
      }
    } else if (type == TYPE_NACK && forMe) {
      int slot = inflight.find(msgId);
      if (slot >= 0) {
        notifyPhone("NACK:" + hex16(msgId));
        inflight.release(slot);
        DLOGF("[DIAG] NACK recibido LoRa msgId=%04X\n", msgId);
      }
    }
    (void)bcast; (void)rssi;
  }

  // Beacon de pairing con jitter (evita colisiones sincronizadas).
  static unsigned long lastBeacon = 0;
  static unsigned long beaconIv = 800;
  unsigned long now = millis();
  if (pairing.inPairingMode() && now - lastBeacon > beaconIv) {
    lastBeacon = now;
    beaconIv = 600 + (esp_random() % 900);
    sendPairPacket(TYPE_PAIR_REQ, BROADCAST);
    DLOGF("[DIAG] TX PAIR_REQ pid=%u\n", pairing.pendingPairId());
  }

  // Chequeo de timeouts de mensajes en vuelo (guard 500 ms).
  // LORA → MQTT a los 3 s; MQTT → FAIL a los 5 s adicionales.
  {
    static uint32_t lastInflightCheck = 0;
    uint32_t nowMs = (uint32_t)millis();
    if (nowMs - lastInflightCheck >= 500) {
      lastInflightCheck = nowMs;
      for (int i = 0; i < InflightTable::CAP; i++) {
        if (inflight.stage(i) == InflightTable::EMPTY) continue;
        InflightTable::DueAction da = inflight.due(i, nowMs, 3000, 5000);
        if (da == InflightTable::DUE_FALLBACK) {
          uint16_t mid  = inflight.msgId(i);
          uint16_t dst  = inflight.dst(i);
          const uint8_t* blob = inflight.blob(i);
          size_t         blen = inflight.blobLen(i);
          if (cloud.isConnected()) {
            cloud.publishBlob(cloud.getInboxTopic(dst), blob, blen);
            inflight.promoteToMqtt(i, nowMs);  // solo si se publico; timeout FAIL si no llega ACK
            DLOGF("[DIAG] Fallback MQTT msgId=%04X dst=%04X\n", mid, dst);
          } else {
            // WiFi no disponible: el slot permanece en LORA para reintentar cuando conecte.
            // Throttle por slot: emitir NEEDNET a lo sumo una vez cada 3 s.
            static uint32_t lastNeednet[InflightTable::CAP] = {};
            if (nowMs - lastNeednet[i] >= 3000) {
              notifyPhone("NEEDNET:" + hex16(mid));
              lastNeednet[i] = nowMs;
              DLOGF("[DIAG] NEEDNET msgId=%04X dst=%04X (sin WiFi)\n", mid, dst);
            }
          }
        } else if (da == InflightTable::DUE_FAIL) {
          uint16_t mid = inflight.msgId(i);
          notifyPhone("FAIL:" + hex16(mid));
          inflight.release(i);
          DLOGF("[DIAG] FAIL msgId=%04X\n", mid);
        }
      }
    }
  }

  wifiPoll();
  cloud.loop();  // reconexion MQTT con guard millis() 5s interno
  delay(10);
}

// ==================== ENVIO LoRa ====================
// Header 7B: [dst(2)][src(2)][type(1)][msgId(2)]. msgId=0 para paquetes sin tracking.
void sendFrame(uint16_t dst, uint8_t type, uint16_t msgId, const uint8_t *payload, size_t len) {
  LoRa.beginPacket();
  LoRa.write((dst >> 8) & 0xFF);
  LoRa.write(dst & 0xFF);
  LoRa.write((identity.getId() >> 8) & 0xFF);
  LoRa.write(identity.getId() & 0xFF);
  LoRa.write(type);
  LoRa.write((msgId >> 8) & 0xFF);
  LoRa.write(msgId & 0xFF);
  if (payload && len) LoRa.write(payload, len);
  LoRa.endPacket();
}

// PAIR_REQ/ACK: comparte pairId + clave publica + nombre.
void sendPairPacket(uint8_t type, uint16_t dst) {
  std::vector<uint8_t> p;
  uint16_t pid = pairing.pendingPairId();
  p.push_back((pid >> 8) & 0xFF);
  p.push_back(pid & 0xFF);
  for (int i = 0; i < 32; i++) p.push_back(myPub[i]);
  std::string name = identity.getName();
  uint8_t nameLen = name.size() > 20 ? 20 : name.size();
  p.push_back(nameLen);
  for (int i = 0; i < nameLen; i++) p.push_back((uint8_t)name[i]);
  sendFrame(dst, type, 0, p.data(), p.size());  // msgId=0: pairing no usa tracking
}

// Envia un ACK (TYPE_ACK=4) al nodo src por el medio indicado.
// Payload vacio; msgId en header identifica el mensaje confirmado.
// Si el medio original no esta disponible, usa el otro como fallback.
void sendAck(uint16_t dst, uint16_t msgId, bool viaLoRa) {
  if (viaLoRa) {
    sendFrame(dst, TYPE_ACK, msgId, nullptr, 0);
  } else if (cloud.isConnected()) {
    uint8_t buf[5];
    size_t n = MqttCodec::buildDataPayload(identity.getId(), TYPE_ACK, msgId, nullptr, 0, buf, sizeof(buf));
    cloud.publishBlob(cloud.getInboxTopic(dst), buf, n);
  } else {
    // MQTT no disponible: usar LoRa como fallback para el ACK
    sendFrame(dst, TYPE_ACK, msgId, nullptr, 0);
  }
}

// Envia un NACK (TYPE_NACK=5) al nodo src por el medio indicado.
// Indica que el mensaje no pudo procesarse (contacto desconocido, clave faltante
// o fallo de descifrado). Payload vacio; msgId en header identifica el mensaje.
// Si el medio original no esta disponible, usa el otro como fallback.
void sendNack(uint16_t dst, uint16_t msgId, bool viaLoRa) {
  if (viaLoRa) {
    sendFrame(dst, TYPE_NACK, msgId, nullptr, 0);
  } else if (cloud.isConnected()) {
    uint8_t buf[5];
    size_t n = MqttCodec::buildDataPayload(identity.getId(), TYPE_NACK, msgId, nullptr, 0, buf, sizeof(buf));
    cloud.publishBlob(cloud.getInboxTopic(dst), buf, n);
  } else {
    // MQTT no disponible: usar LoRa como fallback para el NACK
    sendFrame(dst, TYPE_NACK, msgId, nullptr, 0);
  }
}

// Descifra y emite un blob E2E recibido (por LoRa o por MQTT).
// Guard de auto-mensaje: descarta el eco del propio publish (src == this node).
// Emite MSG:<srcHex>:<texto> por BLE y responde ACK/NACK al remitente
// por el mismo medio por el que llego (viaLoRa=true → LoRa; false → MQTT).
// NACK si: contacto desconocido, sin clave, deriveAesKey falla o falla descifrado.
void handleDataPacket(uint16_t src, uint16_t msgId, bool viaLoRa, const uint8_t* blob, size_t len) {
  if (src == identity.getId()) return;  // eco propio — ignorar
  const Contact *c = contacts.find(src);
  if (c == nullptr) {
    // Contacto borrado o nunca emparejado: rechazar
    sendNack(src, msgId, viaLoRa);
    DLOGF("[DIAG] NACK: contacto desconocido src=%s\n", hex16(src).c_str());
    return;
  }
  if (!c->hasKey || !e2eReady) {
    sendNack(src, msgId, viaLoRa);
    DLOGF("[DIAG] NACK: sin clave E2E src=%s\n", hex16(src).c_str());
    return;
  }
  uint8_t aesKey[32];
  if (!e2e.deriveAesKey(myPriv, c->pubKey, aesKey)) {
    sendNack(src, msgId, viaLoRa);
    DLOGF("[DIAG] NACK: deriveAesKey fallo src=%s\n", hex16(src).c_str());
    return;
  }
  uint8_t clear[256];
  int n = e2e.decrypt(aesKey, blob, len, clear, sizeof(clear));
  if (n < 0) {
    sendNack(src, msgId, viaLoRa);
    DLOGF("[DIAG] NACK: fallo descifrado de %s\n", hex16(src).c_str());
    return;
  }
  String text((char *)clear, n);
  lastEvent = String(c->name.c_str()) + ": " + text;
  notifyPhone("MSG:" + hex16(src) + ":" + text);
  Serial.printf("MSG de %s: %s\n", c->name.c_str(), text.c_str());
  displayStatus();
  sendAck(src, msgId, viaLoRa);
}

// Callback MQTT (firma PubSubClient MQTT_CALLBACK_SIGNATURE).
// Parsea [srcHi][srcLo][type][msgIdHi][msgIdLo][blob...] y delega segun tipo.
// Corre dentro de mqttClient.loop() (contexto del loop principal) -> seguro tocar globals.
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  // parseDataHeader rechaza length<5; el puntero blob apunta al buffer de
  // PubSubClient que es valido durante el callback. handleDataPacket consume
  // el blob sincronicamente (descifra antes de retornar), sin guardar el puntero.
  uint16_t src; uint8_t type; uint16_t msgId; const uint8_t* blob; size_t blobLen;
  if (!MqttCodec::parseDataHeader(payload, length, src, type, msgId, blob, blobLen)) return;

  if (type == TYPE_DATA) {
    // Deduplicacion: si ya se proceso el mismo (src, msgId) por LoRa, descarta pero re-ACK.
    if (!dedup.seen(src, msgId)) {
      handleDataPacket(src, msgId, false, blob, blobLen);
    } else {
      DLOGF("[DIAG] duplicado MQTT descartado src=%04X msgId=%04X\n", src, msgId);
      sendAck(src, msgId, false);  // re-ACK por MQTT: ya fue procesado, no reintentar
    }
  } else if (type == TYPE_ACK) {
    int slot = inflight.find(msgId);
    if (slot >= 0) {
      notifyPhone("ACK:" + hex16(msgId) + ":broker");
      inflight.release(slot);
      DLOGF("[DIAG] ACK recibido MQTT msgId=%04X\n", msgId);
    }
  } else if (type == TYPE_NACK) {
    int slot = inflight.find(msgId);
    if (slot >= 0) {
      notifyPhone("NACK:" + hex16(msgId));
      inflight.release(slot);
      DLOGF("[DIAG] NACK recibido MQTT msgId=%04X\n", msgId);
    }
  }
  (void)topic;
}

// Cifra un texto para un contacto, lo envia por LoRa y registra en InflightTable.
// El fallback MQTT ocurre automaticamente en loop() si LoRa no llega en ~3 s.
void sendToContact(uint16_t dstId, const String &text) {
  const Contact *c = contacts.find(dstId);
  if (!c || !c->hasKey || !e2eReady) {
    notifyPhone("ERR:contacto desconocido");
    return;
  }
  uint8_t aesKey[32];
  if (!e2e.deriveAesKey(myPriv, c->pubKey, aesKey)) {
    notifyPhone("ERR:clave");
    return;
  }
  uint8_t out[300];
  int n = e2e.encrypt(aesKey, (const uint8_t *)text.c_str(), text.length(), out,
                      sizeof(out));
  if (n < 0) {
    notifyPhone("ERR:cifrado");
    return;
  }

  // Asignar msgId (1..65535; 0 reservado para paquetes sin tracking).
  uint16_t msgId = ++_msgCounter;
  if (msgId == 0) msgId = ++_msgCounter;  // evitar 0 tras overflow

  // Pre-construir payload MQTT para almacenar en InflightTable (fallback).
  uint8_t mq[5 + 300];
  size_t mqn = MqttCodec::buildDataPayload(identity.getId(), TYPE_DATA, msgId,
                                           out, (size_t)n, mq, sizeof(mq));

  // Registrar en InflightTable antes de enviar (si la tabla esta llena, descartar).
  int slot = inflight.add(msgId, dstId, mq, mqn, (uint32_t)millis());
  if (slot < 0) {
    notifyPhone("ERR:tabla_llena");
    return;
  }

  // Enviar por LoRa con el msgId en el header.
  sendFrame(dstId, TYPE_DATA, msgId, out, (size_t)n);

  // Confirmar envio al telefono.
  notifyPhone("SENT:" + hex16(msgId) + ":" + hex16(dstId));

  lastEvent = "Yo->" + String(c->name.c_str()) + ": " + text;
  displayStatus();
}

// ==================== CONTACTOS EN NVS ====================
// Blob: [count][ id(2) | pubkey(32) | nameLen(1) | name ] x count
void saveContacts() {
  std::vector<uint8_t> b;
  b.push_back((uint8_t)contacts.count());
  for (int i = 0; i < contacts.count(); i++) {
    const Contact &c = contacts.get(i);
    b.push_back((c.id >> 8) & 0xFF);
    b.push_back(c.id & 0xFF);
    for (int j = 0; j < 32; j++) b.push_back(c.pubKey[j]);
    uint8_t nl = c.name.size() > 20 ? 20 : c.name.size();
    b.push_back(nl);
    for (int j = 0; j < nl; j++) b.push_back((uint8_t)c.name[j]);
  }
  prefs.putBytes("contacts", b.data(), b.size());
}

void loadContacts() {
  size_t len = prefs.getBytesLength("contacts");
  if (len == 0) return;
  std::vector<uint8_t> b(len);
  prefs.getBytes("contacts", b.data(), len);
  size_t pos = 0;
  if (pos >= b.size()) return;
  uint8_t count = b[pos++];
  for (uint8_t i = 0; i < count && pos + 35 <= b.size(); i++) {
    uint16_t id = ((uint16_t)b[pos] << 8) | b[pos + 1];
    pos += 2;
    uint8_t pub[32];
    memcpy(pub, &b[pos], 32);
    pos += 32;
    uint8_t nl = b[pos++];
    std::string nm;
    if (pos + nl <= b.size()) {
      nm.assign((char *)&b[pos], nl);
      pos += nl;
    }
    contacts.addOrUpdate(id, nm, pub);
  }
}

// ==================== COMANDOS ====================
void handleControlCommand(const String &line) {
  // Comandos con argumentos propios (no en ControlCommand): SETNAME, SEND, LIST.
  if (line.startsWith("SETNAME:")) {
    String nm = line.substring(8);
    nm.trim();
    identity.setName(std::string(nm.c_str()));
    prefs.putString("name", identity.getName().c_str());
    notifyPhone("NAME:" + String(identity.getName().c_str()));
    Serial.printf("Nombre: %s (aplica al reiniciar el advert BLE)\n",
                  identity.getName().c_str());
    displayStatus();
    return;
  }
  if (line.startsWith("SEND:")) {
    int colon = line.indexOf(':', 5);
    if (colon > 0) {
      uint16_t dst = (uint16_t)strtol(line.substring(5, colon).c_str(), nullptr, 16);
      sendToContact(dst, line.substring(colon + 1));
    }
    return;
  }
  // MSEND:<idHex>:<texto> — camino MQTT puro (sin sendFrame LoRa).
  // Util para verificar el transporte broker en Plan 03 sin antena LoRa.
  if (line.startsWith("MSEND:")) {
    int colon = line.indexOf(':', 6);
    if (colon < 0) {
      notifyPhone("ERR:formato MSEND");
      return;
    }
    if (colon > 0) {
      uint16_t dst = (uint16_t)strtol(line.substring(6, colon).c_str(), nullptr, 16);
      String text = line.substring(colon + 1);
      const Contact *c = contacts.find(dst);
      if (!c || !c->hasKey || !e2eReady) { notifyPhone("ERR:contacto desconocido"); return; }
      uint8_t aesKey[32];
      if (!e2e.deriveAesKey(myPriv, c->pubKey, aesKey)) { notifyPhone("ERR:clave"); return; }
      uint8_t out[300];
      int n = e2e.encrypt(aesKey, (const uint8_t *)text.c_str(), text.length(), out, sizeof(out));
      if (n < 0) { notifyPhone("ERR:cifrado"); return; }
      // msgId=0 es placeholder; la generacion de IDs se implementa en el plan 03-02.
      uint8_t mq[5 + 300];
      size_t mqn = MqttCodec::buildDataPayload(identity.getId(), TYPE_DATA, 0, out, (size_t)n, mq, sizeof(mq));
      if (mqn > 0) {
        bool ok = cloud.publishBlob(cloud.getInboxTopic(dst), mq, mqn);
        notifyPhone(ok ? "MSENT:" + hex16(dst) : "ERR:mqtt_pub");
      }
    }
    return;
  }
  if (line == "LIST") {
    String out = "CONTACTS:";
    for (int i = 0; i < contacts.count(); i++) {
      const Contact &c = contacts.get(i);
      out += hex16(c.id) + "=" + String(c.name.c_str());
      if (i < contacts.count() - 1) out += ",";
    }
    notifyPhone(out);
    return;
  }
  if (line == "WHOAMI") {
    if (!claimed) {
      claimed = true;
      prefs.putBool("claimed", true);
    }
    notifyPhone("ME:" + hex16(identity.getId()) + ":" +
                String(identity.getName().c_str()));
    displayStatus();
    return;
  }
  if (line.startsWith("SETWIFI:")) {
    // Nota: la pass queda en NVS en texto plano (aceptado - RESEARCH NVS).
    WifiCredentials cr = parseSetWifi(std::string(line.c_str()));
    if (cr.valid) {
      prefs.putString("wifi_ssid", cr.ssid.c_str());
      prefs.putString("wifi_pass", cr.pass.c_str());
      wifiSSID = String(cr.ssid.c_str());
      wifiPass  = String(cr.pass.c_str());
      WiFi.mode(WIFI_STA);
      WiFi.disconnect(false);
      WiFi.setAutoReconnect(true);
      WiFi.begin(wifiSSID.c_str(), wifiPass.c_str());
      wifiConnState = WIFI_CONNECTING;
      notifyPhone("WIFI:SET");
      Serial.printf("[WiFi] SETWIFI ssid='%s'\n", wifiSSID.c_str());
      displayStatus();
    } else {
      notifyPhone("ERR:SETWIFI invalido");
    }
    return;
  }
  if (line == "CLEARWIFI") {
    prefs.remove("wifi_ssid");
    prefs.remove("wifi_pass");
    WiFi.disconnect(true);
    wifiSSID = "";
    wifiPass  = "";
    wifiConnState = WIFI_NO_CREDS;
    notifyPhone("WIFI:sin_cred");
    Serial.println("[WiFi] CLEARWIFI: credenciales borradas.");
    displayStatus();
    return;
  }

  Command cmd = parseControlCommand(std::string(line.c_str()));
  switch (cmd.type) {
    case CMD_PAIR:
      pairingPin = String(cmd.arg.c_str());
      pairing.startPairing(cmd.arg);
      sendPairPacket(TYPE_PAIR_REQ, BROADCAST);
      Serial.printf("Modo emparejamiento PIN=%s pairId=%u\n", pairingPin.c_str(),
                    pairing.pendingPairId());
      displayStatus();
      break;
    case CMD_UNPAIR: {
      // UNPAIR:<idHex> elimina un contacto; UNPAIR solo cancela la sesion.
      if (cmd.arg.size() > 0) {
        uint16_t id = (uint16_t)strtol(cmd.arg.c_str(), nullptr, 16);
        contacts.remove(id);
        saveContacts();
        notifyPhone("UNPAIRED:" + hex16(id));
      }
      pairing.cancelPairing();
      displayStatus();
      break;
    }
    case CMD_UNLINK: {
      int n = esp_ble_get_bond_device_num();
      if (n > 0) {
        esp_ble_bond_dev_t *list =
            (esp_ble_bond_dev_t *)malloc(sizeof(esp_ble_bond_dev_t) * n);
        if (list) {
          esp_ble_get_bond_device_list(&n, list);
          for (int i = 0; i < n; i++) esp_ble_remove_bond_device(list[i].bd_addr);
          free(list);
        }
      }
      claimed = false;
      prefs.putBool("claimed", false);
      lastEvent = "";  // ya no hay dueño: limpiar pantalla
      Serial.println("Bonds BLE borrados.");
      displayStatus();
      break;
    }
    case CMD_STATUS:
      Serial.printf("STATUS id=%s name=%s contactos=%d pairing=%d\n",
                    hex16(identity.getId()).c_str(), identity.getName().c_str(),
                    contacts.count(), pairing.inPairingMode());
      notifyPhone("ME:" + hex16(identity.getId()) + ":" +
                  String(identity.getName().c_str()));
      notifyPhone("WIFI:" + wifiStateStr());
      break;
    default:
      Serial.println("Comando desconocido.");
      break;
  }
}

// ==================== BLE NOTIFY ====================
void notifyPhone(const String &s) {
  if (BLE_clients_connected > 0 && pTxCharacteristic) {
    pTxCharacteristic->setValue((uint8_t *)s.c_str(), s.length());
    pTxCharacteristic->notify();
  }
}

// ==================== OLED ====================
void displayPasskey(uint32_t passkey) {
  if (!displayReady) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("Enlace BLE - PIN:");
  display.setTextSize(2);
  display.setCursor(0, 22);
  char buf[8];
  snprintf(buf, sizeof(buf), "%06u", passkey);
  display.println(buf);
  display.setTextSize(1);
  display.setCursor(0, 50);
  display.println("Ingresa en el movil");
  display.display();
}

void displayPairing() {
  if (!displayReady) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("EMPAREJANDO");
  display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
  display.setTextSize(2);
  display.setCursor(0, 18);
  display.print("PIN ");
  display.println(pairingPin.length() ? pairingPin : String("----"));
  display.setTextSize(1);
  display.setCursor(0, 46);
  display.println("Buscando contacto...");
  display.display();
}

void displayStatus() {
  if (!displayReady) return;
  if (showingPasskey) return;
  if (pairing.inPairingMode()) { displayPairing(); return; }

  bool conn = BLE_clients_connected > 0;

  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  // Nombre propio + id
  display.print(identity.getName().c_str());
  display.setCursor(0, 12);
  display.print("ID:"); display.print(hex16(identity.getId()));
  display.print(" B:"); display.print(conn ? "1" : "-");
  display.print(" C:"); display.print(contacts.count());
  display.print(" W:");
  if (wifiConnState == WIFI_CONNECTED)     display.print("ok");
  else if (wifiConnState == WIFI_NO_CREDS) display.print("-");
  else                                     display.print("x");
  display.drawLine(0, 22, 128, 22, SSD1306_WHITE);

  display.setCursor(0, 28);
  if (!claimed) {
    // Sin telefono dueño: lista para vincular desde la app.
    display.println("Sin telefono.");
    display.setCursor(0, 40);
    display.println("Vincula desde la");
    display.setCursor(0, 50);
    display.println("app (BLE).");
  } else if (!conn) {
    display.println("Vinculado.");
    display.setCursor(0, 40);
    display.println("Telefono ausente.");
  } else {
    String e = lastEvent;
    if (e.length() > 63) e = e.substring(0, 63);
    display.println(e.length() ? e : String("Listo."));
  }
  display.display();
}
