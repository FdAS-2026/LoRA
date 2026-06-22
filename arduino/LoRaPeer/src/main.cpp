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
#include "MessageManager.h"
#include "ProtocolState.h"
#include "PeerConfig.h"
#include "CloudManager.h"
#include "HuffmanCodec.h"
#include "SecureCrypto.h"
#include "PairingManager.h"
#include "ControlCommand.h"
#include "secrets.h"
#include <string>
#include <vector>

// -------------------- PINOUT
const int LORA_MISO = 19;
const int LORA_SS   = 18;
const int LORA_SCK  = 5;
const int LORA_MOSI = 27;
const int LORA_RST  = 14;
const int LORA_IRQ  = 26;

const int OLED_SCL = 15;
const int OLED_SDA = 4;
const int OLED_RST = 16;

const long LORA_FREQ = 915E6;

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RST);

Preferences prefs;
MessageManager msgManager;
ProtocolState protocol(5000);
PeerConfig peerConfig;
CloudManager cloud;
HuffmanCodec huffman;
SecureCrypto secureCrypto;
PairingManager pairing;

// Banderas del primer byte del payload LoRa de datos.
const uint8_t PAYLOAD_RAW = 0;
const uint8_t PAYLOAD_HUFFMAN = 1;

// Tipos de trama LoRa.
const uint8_t TYPE_DATA = 0;
const uint8_t TYPE_ACK = 1;
const uint8_t TYPE_PAIR_REQ = 2;
const uint8_t TYPE_PAIR_ACK = 3;
const uint8_t BROADCAST_ADDR = 0xFF;

// -------------------- BLE UUIDs
#define SERVICE_UUID        "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_RX_UUID "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_TX_UUID "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_CTRL_UUID "6E400004-B5A3-F393-E0A9-E50E24DCCA9E"

// -------------------- ESTADO GLOBAL
bool displayReady = false;
int BLE_clients_connected = 0;
BLEServer* pServer = NULL;
BLECharacteristic* pTxCharacteristic = NULL;
String lastMsgSent = "";
uint32_t blePasskey = 0;        // passkey BLE a mostrar en la OLED
bool showingPasskey = false;

// ==================== FORWARD DECLARATIONS ====================
void displayStatus();
void displayMessage(const String &t);
void displayPasskey(uint32_t passkey);
void sendMessage(uint8_t to, uint8_t from, uint8_t type, uint16_t pairId, const String &msg);
void sendAck(uint8_t to, uint8_t from);
void sendPairPacket(uint8_t type, uint8_t to, uint16_t pairId);
void publishEncrypted(const String &msg);
String decodeLoraPayload(uint8_t type, const std::vector<uint8_t> &raw);
void handleControlCommand(const String &line);
void persistPairing();

// ==================== CLOUD CALLBACK ====================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String msg = "";
  for (unsigned int i = 0; i < length; i++) {
    msg += (char)payload[i];
  }
  Serial.print("Mensaje recibido desde HiveMQ Cloud: ");
  Serial.println(msg);
  
  // Guardamos el mensaje (asumimos que viene del broker como externo = peer 0 o peer id)
  // Lo enviamos por LoRa al otro peer
  sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), TYPE_DATA, pairing.pairId(), msg);
  lastMsgSent = msg;
  protocol.markMessageSent(millis());
  msgManager.addMessage(peerConfig.getPeerId(), msg, millis(), 0, false);
  displayStatus();
}

// ==================== BLE CALLBACKS ====================
class MyServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    BLE_clients_connected++;
    Serial.print("BLE: Cliente conectado. Total: "); Serial.println(BLE_clients_connected);
    displayStatus();
  };

  void onDisconnect(BLEServer* pServer) {
    if (BLE_clients_connected > 0) BLE_clients_connected--;
    Serial.print("BLE: Cliente desconectado. Total: "); Serial.println(BLE_clients_connected);
    displayStatus();
  }
};

class MyCharacteristicCallbacks: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    String rxValue = pCharacteristic->getValue().c_str();
    if (rxValue.length() > 0) {
      String msg = rxValue;
      msg.trim();
      if (msg.length() > 0) {
        Serial.print("BLE RX: "); Serial.println(msg);

        // Enviar por LoRa al peer (con el pairId de la red emparejada)
        sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), TYPE_DATA,
                    pairing.pairId(), msg);
        lastMsgSent = msg;
        protocol.markMessageSent(millis());
        msgManager.addMessage(peerConfig.getNodeId(), msg, millis(), 0, true);

        // Publicar en la nube (HiveMQ)
        publishEncrypted("BLE: " + msg);

        displayStatus();
      }
    }
  }
};

// Recibe comandos de control (PAIR/UNPAIR/UNLINK/STATUS) por una caracteristica
// dedicada, separada del chat.
class ControlCharacteristicCallbacks: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    String value = pCharacteristic->getValue().c_str();
    value.trim();
    if (value.length() > 0) {
      Serial.print("BLE CTRL: "); Serial.println(value);
      handleControlCommand(value);
    }
  }
};

// Muestra el passkey de bonding en la OLED y notifica el estado de la auth.
class MySecurityCallbacks: public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() { return 0; }
  void onPassKeyNotify(uint32_t pass_key) {
    blePasskey = pass_key;
    showingPasskey = true;
    Serial.print("BLE passkey: "); Serial.println(pass_key);
    displayPasskey(pass_key);
  }
  bool onConfirmPIN(uint32_t) { return true; }
  bool onSecurityRequest() { return true; }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) {
    showingPasskey = false;
    Serial.print("BLE bonding ");
    Serial.println(cmpl.success ? "exitoso" : "fallido");
    displayStatus();
  }
};

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(100);

  // OLED
  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    displayReady = false;
  } else {
    displayReady = true;
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // LoRa
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_SS);
  LoRa.setPins(LORA_SS, LORA_RST, LORA_IRQ);
  if (!LoRa.begin(LORA_FREQ)) {
    Serial.println("LoRa init failed.");
    displayMessage("LoRa FAILED");
    while (1) { delay(2000); }
  }

  // Auto-discovery LoRa
  prefs.begin("lora", false);
  uint8_t storedNode = prefs.getUChar("node_id", 0);
  uint8_t storedPeer = prefs.getUChar("peer_id", 0);

  displayMessage("Auto-detecting...");
  Serial.println("--- P2P LoRa + BLE + MQTT starting ---");

  unsigned long start = millis();
  bool discoveredPeer = false;
  uint8_t detectedPeerID = 0;
  
  while (millis() - start < 5000) {
    if (Serial.available()) {
      String s = Serial.readStringUntil('\n');
      if (peerConfig.parseSerialCommand(s)) {
        prefs.putUChar("node_id", peerConfig.getNodeId());
        prefs.putUChar("peer_id", peerConfig.getPeerId());
        goto config_done;
      }
    }
    
    int packetSize = LoRa.parsePacket();
    if (packetSize) {
      uint8_t to = LoRa.read();
      uint8_t from = LoRa.read();
      LoRa.read();
      String payload = "";
      while (LoRa.available()) payload += (char)LoRa.read();
      
      detectedPeerID = from;
      discoveredPeer = true;
      break;
    }
    delay(50);
  }

  if (discoveredPeer) {
    peerConfig.setFromDiscovery(detectedPeerID);
  } else {
    peerConfig.applyFallback(storedNode, storedPeer);
  }

  prefs.putUChar("node_id", peerConfig.getNodeId());
  prefs.putUChar("peer_id", peerConfig.getPeerId());

config_done:
  Serial.print("Node ID: "); Serial.println(peerConfig.getNodeId());
  Serial.print("Peer ID: "); Serial.println(peerConfig.getPeerId());

  // Restaurar el emparejamiento de placas guardado.
  pairing.loadState(prefs.getBool("paired", false),
                    prefs.getUShort("pair_id", 0),
                    prefs.getUChar("pair_peer", 0));
  if (pairing.isPaired()) {
    Serial.print("Emparejado con N"); Serial.print(pairing.peerId());
    Serial.print(" (pairId="); Serial.print(pairing.pairId()); Serial.println(")");
  }

  String mUser = (peerConfig.getNodeId() == 1) ? HIVEMQ_USER_NODE1 : HIVEMQ_USER_NODE2;
  String mPass = (peerConfig.getNodeId() == 1) ? HIVEMQ_PASS_NODE1 : HIVEMQ_PASS_NODE2;

  // Iniciar la configuración de HiveMQ Cloud (WiFi + MQTT)
  cloud.configure(WIFI_SSID, WIFI_PASSWORD, peerConfig.getNodeId(), mUser, mPass);
  cloud.setCallback(mqttCallback);
  cloud.begin();

  // Inicializar cifrado de produccion (RSA-2048 OAEP) con la clave publica.
  if (secureCrypto.begin(CLOUD_RSA_PUBLIC_KEY)) {
    Serial.println("SecureCrypto listo (RSA-2048 OAEP-SHA256).");
  } else {
    Serial.println("ERROR: no se pudo cargar la clave publica RSA.");
  }

  // ==================== INICIALIZAR BLE ====================
  String deviceName = "LoRA_N" + String(peerConfig.getNodeId());
  BLEDevice::init(deviceName.c_str());

  // Configurar poder y MTU
  BLEDevice::setPower(ESP_PWR_LVL_P7);

  // Seguridad: bonding con passkey mostrado en la OLED (Secure Connections).
  // El telefono ingresa el PIN de 6 digitos => enlace cifrado y autenticado.
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT);
  BLEDevice::setSecurityCallbacks(new MySecurityCallbacks());
  BLESecurity *pSecurity = new BLESecurity();
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_BOND);
  pSecurity->setCapability(ESP_IO_CAP_OUT);  // solo salida => muestra passkey
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pServer->createService(SERVICE_UUID);

  pTxCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_TX_UUID,
    BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
  );
  pTxCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED);
  pTxCharacteristic->addDescriptor(new BLE2902());

  BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_RX_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  pRxCharacteristic->setAccessPermissions(ESP_GATT_PERM_WRITE_ENCRYPTED);
  pRxCharacteristic->setCallbacks(new MyCharacteristicCallbacks());

  // Caracteristica de control (enlace/emparejamiento), tambien cifrada.
  BLECharacteristic *pCtrlCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_CTRL_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  pCtrlCharacteristic->setAccessPermissions(ESP_GATT_PERM_WRITE_ENCRYPTED);
  pCtrlCharacteristic->setCallbacks(new ControlCharacteristicCallbacks());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMaxPreferred(0x12);
  
  BLEDevice::startAdvertising();
  BLEDevice::setMTU(185);

  Serial.print("BLE initialized: "); Serial.println(deviceName);
  Serial.println("Waiting for connections...");
  displayStatus();
}

// ==================== LOOP ====================
void loop() {
  unsigned long currentMillis = millis();

  // Manejar reconexión y loop de la nube
  cloud.loop();

  // Recibir LoRa
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    uint8_t to = LoRa.read();
    uint8_t from = LoRa.read();
    uint8_t type = LoRa.read();
    uint8_t pidHi = LoRa.read();
    uint8_t pidLo = LoRa.read();
    uint16_t pktPairId = ((uint16_t)pidHi << 8) | pidLo;
    std::vector<uint8_t> rawPayload;
    while (LoRa.available()) rawPayload.push_back((uint8_t)LoRa.read());

    int rssi = LoRa.packetRssi();

    if (type == TYPE_PAIR_REQ || type == TYPE_PAIR_ACK) {
      // Handshake de emparejamiento (se procesa sin filtro de destino).
      PairAction action = pairing.onPairPacket(type, pktPairId, from);
      if (action != PAIR_NONE) {
        persistPairing();
        if (action == PAIR_SEND_ACK) {
          sendPairPacket(TYPE_PAIR_ACK, from, pairing.pairId());
        }
        Serial.print("Emparejado con N"); Serial.println(from);
        if (BLE_clients_connected > 0 && pTxCharacteristic != NULL) {
          String n = "PAIRED:N" + String(from);
          pTxCharacteristic->setValue((uint8_t *)n.c_str(), n.length());
          pTxCharacteristic->notify();
        }
        displayStatus();
      }
    } else if (to == peerConfig.getNodeId() && pairing.acceptData(pktPairId, from)) {
      String payload = decodeLoraPayload(type, rawPayload);
      if (type == TYPE_ACK) {
        unsigned long latency = protocol.markAckReceived(currentMillis);
        Serial.print("ACK in: "); Serial.print(latency); Serial.println("ms");
      } else {
        // Mensaje de datos
        Serial.print("RX LoRa from "); Serial.print(from);
        Serial.print(": "); Serial.println(payload);

        msgManager.addMessage(from, payload, currentMillis, rssi, false);

        // Enviar por BLE a todos los clientes conectados
        if (BLE_clients_connected > 0 && pTxCharacteristic != NULL) {
          String bleTx = String(from) + ": " + payload;
          pTxCharacteristic->setValue((uint8_t *)bleTx.c_str(), bleTx.length());
          pTxCharacteristic->notify();
          Serial.print("BLE TX notify: "); Serial.println(bleTx);
        }

        // Reenviar también a la nube en standby
        publishEncrypted("LoRa RX from N" + String(from) + ": " + payload);

        // Responder ACK por LoRa
        sendAck(from, peerConfig.getNodeId());
      }
      displayStatus();
    }
  }

  // Reemitir PAIR_REQ periodicamente mientras esta en modo emparejamiento.
  static unsigned long lastPairBeacon = 0;
  if (pairing.inPairingMode() && currentMillis - lastPairBeacon > 1000) {
    lastPairBeacon = currentMillis;
    sendPairPacket(TYPE_PAIR_REQ, BROADCAST_ADDR, pairing.pendingPairId());
  }

  // Heartbeat (solo si esta emparejado; evita ruido en redes ajenas)
  if (protocol.shouldSendHeartbeat(currentMillis)) {
    String hb = "HB";
    sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), TYPE_DATA,
                pairing.pairId(), hb);
    lastMsgSent = hb;
    protocol.markMessageSent(currentMillis);
  }

  delay(10);
}

// ==================== FUNCIONES ====================
// Trama LoRa: [to][from][type][pairId_hi][pairId_lo][payload...]
void sendMessage(uint8_t to, uint8_t from, uint8_t type, uint16_t pairId, const String &msg) {
  LoRa.beginPacket();
  LoRa.write(to);
  LoRa.write(from);
  LoRa.write(type);
  LoRa.write((pairId >> 8) & 0xFF);
  LoRa.write(pairId & 0xFF);

  if (type == TYPE_DATA) {
    // Mensaje de datos: comprimir con Huffman si reduce el tamano.
    // Asi caben mensajes mas largos en el payload limitado de LoRa.
    std::string text(msg.c_str());
    std::vector<uint8_t> comp = huffman.encode(text);
    if (!comp.empty() && comp.size() < text.size()) {
      LoRa.write(PAYLOAD_HUFFMAN);
      LoRa.write(comp.data(), comp.size());
    } else {
      LoRa.write(PAYLOAD_RAW);
      LoRa.write((const uint8_t *)text.data(), text.size());
    }
  } else {
    // ACK y control: texto plano.
    LoRa.print(msg);
  }
  LoRa.endPacket();
}

// Envia un paquete de handshake de emparejamiento (sin payload util).
void sendPairPacket(uint8_t type, uint8_t to, uint16_t pairId) {
  LoRa.beginPacket();
  LoRa.write(to);
  LoRa.write(peerConfig.getNodeId());
  LoRa.write(type);
  LoRa.write((pairId >> 8) & 0xFF);
  LoRa.write(pairId & 0xFF);
  LoRa.endPacket();
}

// Guarda el estado de emparejamiento en NVS.
void persistPairing() {
  prefs.putBool("paired", pairing.isPaired());
  prefs.putUShort("pair_id", pairing.pairId());
  prefs.putUChar("pair_peer", pairing.peerId());
}

// Procesa un comando de control recibido por BLE.
void handleControlCommand(const String &line) {
  Command cmd = parseControlCommand(std::string(line.c_str()));
  switch (cmd.type) {
    case CMD_PAIR:
      pairing.startPairing(cmd.arg);
      Serial.print("Modo emparejamiento, pairId="); Serial.println(pairing.pendingPairId());
      // Emite un primer PAIR_REQ inmediato.
      sendPairPacket(TYPE_PAIR_REQ, BROADCAST_ADDR, pairing.pendingPairId());
      displayStatus();
      break;
    case CMD_UNPAIR:
      pairing.unpair();
      persistPairing();
      Serial.println("Emparejamiento deshecho.");
      displayStatus();
      break;
    case CMD_UNLINK: {
      // Borra todos los bonds BLE de este dispositivo.
      int dev_num = esp_ble_get_bond_device_num();
      if (dev_num > 0) {
        esp_ble_bond_dev_t *list =
            (esp_ble_bond_dev_t *)malloc(sizeof(esp_ble_bond_dev_t) * dev_num);
        if (list) {
          esp_ble_get_bond_device_list(&dev_num, list);
          for (int i = 0; i < dev_num; i++) {
            esp_ble_remove_bond_device(list[i].bd_addr);
          }
          free(list);
        }
      }
      Serial.println("Bonds BLE borrados.");
      break;
    }
    case CMD_STATUS:
      Serial.print("STATUS paired="); Serial.print(pairing.isPaired());
      Serial.print(" peer="); Serial.println(pairing.peerId());
      break;
    default:
      Serial.println("Comando desconocido.");
      break;
  }
}

// Reconstruye el texto de un payload LoRa segun su tipo y bandera de compresion.
String decodeLoraPayload(uint8_t type, const std::vector<uint8_t> &raw) {
  if (type != 0 || raw.empty()) {
    return String(std::string(raw.begin(), raw.end()).c_str());
  }
  uint8_t flag = raw[0];
  std::vector<uint8_t> body(raw.begin() + 1, raw.end());
  if (flag == PAYLOAD_HUFFMAN) {
    std::string decoded = huffman.decode(body);
    return String(decoded.c_str());
  }
  return String(std::string(body.begin(), body.end()).c_str());
}

// Cifra el mensaje con la clave publica RSA-2048 (OAEP-SHA256) y lo publica en
// el broker en base64. Solo quien tenga la clave privada puede descifrarlo.
// Si la cripto no esta lista o el mensaje excede el limite, no se publica en
// claro: se omite para no filtrar el contenido.
void publishEncrypted(const String &msg) {
  if (!secureCrypto.isReady()) {
    Serial.println("SecureCrypto no inicializado: mensaje no publicado.");
    return;
  }
  String encrypted = secureCrypto.encryptBase64(msg);
  if (encrypted.length() == 0) {
    Serial.println("Fallo al cifrar (mensaje muy largo?): no publicado.");
    return;
  }
  cloud.publishMessage(encrypted);
}

void sendAck(uint8_t to, uint8_t from) {
  sendMessage(to, from, TYPE_ACK, pairing.pairId(), "ACK");
}

// Muestra el passkey de bonding BLE en grande para que el usuario lo lea.
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

void displayMessage(const String &t) {
  if (!displayReady) return;
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(2);
  display.println(t);
  display.display();
}

void displayStatus() {
  if (!displayReady) return;
  // Mientras se muestra el passkey de bonding, no lo pisamos.
  if (showingPasskey) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);

  // Header
  display.print("N"); display.print(peerConfig.getNodeId());
  display.print(" B:");
  if (BLE_clients_connected > 0) {
    display.print(BLE_clients_connected);
  } else {
    display.print("-");
  }
  display.print(" W:");
  if (cloud.isConnected()) {
    display.print("1");
  } else {
    display.print("0");
  }
  display.print(" ");
  // Estado de emparejamiento de placas.
  if (pairing.inPairingMode()) {
    display.println("PAIR..");
  } else if (pairing.isPaired()) {
    display.print("P"); display.println(pairing.peerId());
  } else if (protocol.isWaitingForAck()) {
    display.println("ACK");
  } else {
    display.println("ok");
  }

  display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
  
  // Mostrar últimos 4 mensajes
  int bufSize = msgManager.getSize();
  int startIdx = (msgManager.getHeadIndex() - 4 + bufSize) % bufSize;
  int line = 12;
  
  for (int i = 0; i < 4; i++) {
    int idx = (startIdx + i) % bufSize;
    Message m = msgManager.getMessage(idx);
    if (m.from != 0) {
      display.setCursor(0, line);
      if (m.isBLE) {
        display.print("B");
      } else {
        display.print("L");
      }
      display.print((m.from == peerConfig.getNodeId()) ? ">" : "<");
      display.print(m.from);
      display.print(": ");
      display.println(m.text);
      line += 10;
    }
  }
  
  display.drawLine(0, 53, 128, 53, SSD1306_WHITE);
  display.setCursor(0, 55);
  display.print("RSSI: ");
  
  Message lastM = msgManager.getMessage((msgManager.getHeadIndex() - 1 + bufSize) % bufSize);
  if (lastM.from != 0) {
    display.println(lastM.rssi);
  } else {
    display.println("--");
  }
  
  display.display();
}
