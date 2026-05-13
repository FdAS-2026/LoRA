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
#include "MessageManager.h"
#include "ProtocolState.h"
#include "PeerConfig.h"
#include "CloudManager.h"
#include "secrets.h"

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

// -------------------- BLE UUIDs
#define SERVICE_UUID        "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_RX_UUID "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_TX_UUID "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

// -------------------- ESTADO GLOBAL
bool displayReady = false;
int BLE_clients_connected = 0;
BLEServer* pServer = NULL;
BLECharacteristic* pTxCharacteristic = NULL;
String lastMsgSent = "";

// ==================== FORWARD DECLARATIONS ====================
void displayStatus();
void displayMessage(const String &t);
void sendMessage(uint8_t to, uint8_t from, uint8_t type, const String &msg);
void sendAck(uint8_t to, uint8_t from);

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
  sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), 0, msg);
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
        
        // Enviar por LoRa al peer
        sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), 0, msg);
        lastMsgSent = msg;
        protocol.markMessageSent(millis());
        msgManager.addMessage(peerConfig.getNodeId(), msg, millis(), 0, true);
        
        // Publicar en la nube (HiveMQ)
        cloud.publishMessage("BLE: " + msg);
        
        displayStatus();
      }
    }
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

  String mUser = (peerConfig.getNodeId() == 1) ? HIVEMQ_USER_NODE1 : HIVEMQ_USER_NODE2;
  String mPass = (peerConfig.getNodeId() == 1) ? HIVEMQ_PASS_NODE1 : HIVEMQ_PASS_NODE2;

  // Iniciar la configuración de HiveMQ Cloud (WiFi + MQTT)
  cloud.configure(WIFI_SSID, WIFI_PASSWORD, peerConfig.getNodeId(), mUser, mPass);
  cloud.setCallback(mqttCallback);
  cloud.begin();

  // ==================== INICIALIZAR BLE ====================
  String deviceName = "LoRA_N" + String(peerConfig.getNodeId());
  BLEDevice::init(deviceName.c_str());
  
  // Configurar poder y MTU
  BLEDevice::setPower(ESP_PWR_LVL_P7);
  
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pServer->createService(SERVICE_UUID);

  pTxCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_TX_UUID,
    BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
  );
  pTxCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ);
  pTxCharacteristic->addDescriptor(new BLE2902());

  BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_RX_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  pRxCharacteristic->setAccessPermissions(ESP_GATT_PERM_WRITE);
  pRxCharacteristic->setCallbacks(new MyCharacteristicCallbacks());

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
    String payload = "";
    while (LoRa.available()) payload += (char)LoRa.read();
    
    int rssi = LoRa.packetRssi();

    if (to == peerConfig.getNodeId()) {
      if (type == 1) {
        // ACK
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
        cloud.publishMessage("LoRa RX from N" + String(from) + ": " + payload);
        
        // Responder ACK por LoRa
        sendAck(from, peerConfig.getNodeId());
      }
      displayStatus();
    }
  }

  // Heartbeat
  if (protocol.shouldSendHeartbeat(currentMillis)) {
    String hb = "HB";
    sendMessage(peerConfig.getPeerId(), peerConfig.getNodeId(), 0, hb);
    lastMsgSent = hb;
    protocol.markMessageSent(currentMillis);
  }

  delay(10);
}

// ==================== FUNCIONES ====================
void sendMessage(uint8_t to, uint8_t from, uint8_t type, const String &msg) {
  LoRa.beginPacket();
  LoRa.write(to);
  LoRa.write(from);
  LoRa.write(type);
  LoRa.print(msg.substring(0, 50));
  LoRa.endPacket();
}

void sendAck(uint8_t to, uint8_t from) {
  sendMessage(to, from, 1, "ACK");
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
  if (protocol.isWaitingForAck()) {
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
