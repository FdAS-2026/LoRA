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

uint8_t myPriv[32], myPub[32];
bool e2eReady = false;

// Tipos y direcciones de trama LoRa: [dstHi][dstLo][srcHi][srcLo][type][payload]
const uint8_t TYPE_DATA = 0;
const uint8_t TYPE_PAIR_REQ = 2;
const uint8_t TYPE_PAIR_ACK = 3;
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
void sendFrame(uint16_t dst, uint8_t type, const uint8_t *payload, size_t len);
void sendPairPacket(uint8_t type, uint16_t dst);
void handleControlCommand(const String &line);
void sendToContact(uint16_t dstId, const String &text);
void saveContacts();
void loadContacts();

// ==================== HELPERS ====================
static String hex16(uint16_t v) {
  char b[5];
  snprintf(b, sizeof(b), "%04X", v);
  return String(b);
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

  Serial.println(e2eReady ? "E2ECrypto listo." : "E2ECrypto FALLO.");
  displayStatus();
}

// ==================== LOOP ====================
void loop() {
  // Diagnostico / control por serial (acceso fisico).
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) handleControlCommand(cmd);
  }

  // Recibir LoRa
  int pkt = LoRa.parsePacket();
  if (pkt >= 5) {
    uint16_t dst = ((uint16_t)LoRa.read() << 8) | LoRa.read();
    uint16_t src = ((uint16_t)LoRa.read() << 8) | LoRa.read();
    uint8_t type = LoRa.read();
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
      // Mensaje E2E de un contacto: descifrar con la clave compartida.
      const Contact *c = contacts.find(src);
      if (c && c->hasKey && e2eReady) {
        uint8_t aesKey[32];
        if (e2e.deriveAesKey(myPriv, c->pubKey, aesKey)) {
          uint8_t clear[256];
          int n = e2e.decrypt(aesKey, payload.data(), payload.size(), clear,
                              sizeof(clear));
          if (n >= 0) {
            String text((char *)clear, n);
            lastEvent = String(c->name.c_str()) + ": " + text;
            notifyPhone("MSG:" + hex16(src) + ":" + text);
            Serial.printf("MSG de %s: %s\n", c->name.c_str(), text.c_str());
            displayStatus();
          } else {
            DLOGF("[DIAG] fallo descifrado de %s\n", hex16(src).c_str());
          }
        }
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

  delay(10);
}

// ==================== ENVIO LoRa ====================
void sendFrame(uint16_t dst, uint8_t type, const uint8_t *payload, size_t len) {
  LoRa.beginPacket();
  LoRa.write((dst >> 8) & 0xFF);
  LoRa.write(dst & 0xFF);
  LoRa.write((identity.getId() >> 8) & 0xFF);
  LoRa.write(identity.getId() & 0xFF);
  LoRa.write(type);
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
  sendFrame(dst, type, p.data(), p.size());
}

// Cifra un texto para un contacto y lo envia por LoRa (E2E).
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
  sendFrame(dstId, TYPE_DATA, out, n);
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
  display.print(" BLE:"); display.print(conn ? "1" : "-");
  display.print(" C:"); display.print(contacts.count());
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
