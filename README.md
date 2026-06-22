Prueba P2P LoRa entre dos placas ESP32 + SX1276/SX1278 con BLE

Resumen
- Objetivo: comunicación P2P verdadera entre dos placas idénticas LoRa + BLE
- Ambas placas corren el MISMO código
- Ambas actúan como nodos LoRa (envío/recepción)
- Ambas exponen servidor BLE para conectar teléfono
- App Flutter personalizada incluida para mejor UX

## Archivos principales

- `arduino/LoRaPeer/LoRaPeer.ino` — Sketch P2P unificado (sube a AMBAS placas)
- `flutter_app/` — App Flutter para conectar desde teléfono
- `README.md` — Este archivo

Librerías requeridas
- "LoRa" por Sandeep Mistry
- "Adafruit SSD1306" + "Adafruit GFX"
- BLE incluido en ESP32

Configuración Wiring
- LORA_MISO (19) -> GPIO 19
- LORA_SS/CS (18) -> GPIO 18
- LORA_SCK (5) -> GPIO 5
- LORA_MOSI (27) -> GPIO 27
- LORA_RST (14) -> GPIO 14
- LORA_IRQ/DIO0 (26) -> GPIO 26
- OLED_SCL -> GPIO 15
- OLED_SDA -> GPIO 4
- OLED_RST -> GPIO 16
- VCC -> 3.3V, GND -> GND

Frecuencia LoRa
- 915E6 (Américas), 868E6 (Europa), 433E6 (ISM especial)

Instalación
1. **Sube el MISMO código `LoRaPeerP2P.ino` a ambas placas**
2. Ambas se auto-detectan: primera es node=1, segunda es node=2
3. Abre Monitor Serial a 115200 para ver logs

Uso
- **Comunicación LoRa P2P**: Automática cada 5s (heartbeat) + ACK
- **Conectar por Bluetooth**: 
  - Android: descarga app "Serial Bluetooth Terminal" o "nRF Connect"
  - Busca dispositivo "LoRA_N1" o "LoRA_N2"
  - Conecta y envía mensajes
  - Recibes respuestas en tiempo real
  
- **OLED muestra**:
  - `N1 BLE:1 ok` = Node 1, 1 cliente BLE conectado, ready
  - `L<2: Hello` = Mensaje LoRa recibido de Node 2 ("L" = LoRa, "<" = entrada)
  - `B>1: Hola` = Mensaje BLE enviado a Node 1 ("B" = BLE, ">" = salida)
  - RSSI del último mensaje

Flujo de datos
```
Teléfono ---BLE---> Placa1 ---LoRa---> Placa2 ---BLE---> Teléfono
                                          |
                                       ACK (automático)
```

Benchmark de latencia
- Serial Monitor muestra "ACK in: XXXms" para cada mensaje LoRa

## App Flutter

Para una experiencia mejor sin problemas de conexión BLE, usa la app Flutter incluida.

### Instalación rápida

```bash
cd flutter_app
flutter pub get
flutter run
```

### Características

- ✅ Escaneo automático de dispositivos LoRa
- ✅ Conexión BLE robusta
- ✅ Chat en tiempo real
- ✅ Historial de mensajes
- ✅ Indicadores visuales (📤 enviado, 📨 recibido)

### Uso

1. Abre la app
2. Presiona "Escanear"
3. Conecta a "LoRA_N1" o "LoRA_N2"
4. ¡Comienza a chatear!

Para más detalles, ver [flutter_app/README.md](flutter_app/README.md)

## Flujo de datos completo

```
Teléfono ---BLE---> Placa1 ---LoRa---> Placa2 ---BLE---> Teléfono
                                          |
                                       ACK (automático)
```

## Compresión Huffman y cifrado (issue #1)

### Compresión Huffman en LoRa

Los mensajes de datos se comprimen con un árbol de Huffman antes de enviarse por
LoRa, aprovechando mejor el payload limitado del radio. El primer byte del payload
indica si va comprimido (`1`) o en crudo (`0`); el emisor elige automáticamente la
opción más chica, así un mensaje corto nunca crece.

- Módulo: `arduino/LoRaPeer/lib/Compression/HuffmanCodec.{h,cpp}` (C++ puro)
- Buffer autodescriptivo: incluye la tabla de frecuencias, el receptor reconstruye
  el mismo árbol y decodifica.

### Cifrado clave pública/privada hacia el broker (RSA-2048, producción)

Todo lo que la placa publica en el broker se cifra con **RSA-2048 + OAEP
(SHA-256)** usando mbedtls (incluido en Arduino-ESP32). Se cifra con la **clave
pública** y se publica en **base64**; solo quien tenga la **clave privada** puede
descifrarlo. La placa nunca conoce la privada.

- Módulo: `arduino/LoRaPeer/lib/SecureCrypto/SecureCrypto.{h,cpp}`
- Generá tu par y pegá la pública en `secrets.h`; guardá la privada fuera del
  dispositivo:
  ```bash
  openssl genrsa -out priv.pem 2048
  openssl rsa -in priv.pem -pubout -out pub.pem   # -> CLOUD_RSA_PUBLIC_KEY
  ```
- Si la cripto no está lista o el mensaje excede el límite OAEP, el mensaje **no
  se publica en claro** (se omite) para no filtrar contenido.

### TLS del broker

La conexión MQTT valida el certificado del broker contra la CA raíz
**ISRG Root X1** (`secureClient.setCACert(...)` en `CloudManager`), evitando
ataques man-in-the-middle.

### Pruebas (TDD)

La compresión Huffman (lógica pura) se prueba sin hardware:

```bash
cd arduino/LoRaPeer
pio test -e native
```

El cifrado RSA-2048 usa mbedtls (solo en la placa). Su interoperabilidad se
verifica del lado de la app contra un vector generado con OpenSSL (mismo esquema
OAEP-SHA256): lo que cifra la placa, la app lo descifra.

## Enlace y emparejamiento

### Enlazar placa ↔ teléfono (BLE bonding)

El enlace BLE usa **bonding con Secure Connections**: la placa muestra un
**passkey de 6 dígitos en la OLED** y el teléfono lo ingresa. El enlace queda
cifrado y autenticado; las características de chat y control exigen un vínculo
cifrado (`ESP_GATT_PERM_*_ENCRYPTED`), así solo el teléfono enlazado controla la
placa.

- Para **desenlazar**, el teléfono envía `UNLINK` y la placa borra sus bonds
  (`esp_ble_remove_bond_device`).

### Emparejar dos placas (LoRa) con PIN

Dos placas se emparejan compartiendo un **PIN** enviado desde la app:

1. El teléfono manda `PAIR:<pin>` por BLE a ambas placas.
2. Cada una deriva el mismo `pairId` (FNV-1a del PIN) y emite `PAIR_REQ` por LoRa.
3. Al recibir un `PAIR_REQ`/`PAIR_ACK` con el `pairId` correcto, quedan
   emparejadas, guardan el nodo del peer en NVS y responden `PAIR_ACK`.
4. A partir de ahí, **solo aceptan datos del peer con ese `pairId`** (las tramas
   LoRa llevan el `pairId`), ignorando otras redes en rango. `UNPAIR` deshace el
   vínculo.

Lógica pura y testeable en `lib/Pairing/` (`PairingManager`, `ControlCommand`),
cubierta por `pio test -e native`.

## Próximos pasos (opcional)

- Añadir GPS a las placas para rastreo
- Integrar base de datos en la nube
- Soporte para múltiples nodos LoRa

