#ifndef SECRETS_H
#define SECRETS_H

// PLANTILLA de secrets.h — copiar a secrets.h y poner los valores reales.
// secrets.h esta gitignored (no se commitea). El CI copia esta plantilla para
// poder compilar sin credenciales reales.
//
//   cp src/secrets.example.h src/secrets.h
//
// Antes de la prueba de hardware: poner las credenciales REALES de HiveMQ
// (usuario/clave del broker) con ACL sobre el topic `lorapeer/#`.

#define WIFI_SSID "TU_RED_WIFI"
#define WIFI_PASSWORD "TU_CONTRASENA"

#define HIVEMQ_USER "PLACEHOLDER_USER"
#define HIVEMQ_PASS "PLACEHOLDER_PASS"
#define HIVEMQ_USER_NODE1 "PLACEHOLDER_USER1"
#define HIVEMQ_PASS_NODE1 "PLACEHOLDER_PASS1"
#define HIVEMQ_USER_NODE2 "PLACEHOLDER_USER2"
#define HIVEMQ_PASS_NODE2 "PLACEHOLDER_PASS2"

#endif
