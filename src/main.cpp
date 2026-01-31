#include <Arduino.h>
#include <SPIFFS.h>

#define MODEM_RX 18
#define MODEM_TX 19
#define MODEM_BAUD 57600

#define MQTT_HOST   "mqtt.zerolab.co.in"
#define MQTT_PORT   8883
#define MQTT_CLIENT "esp32_mc60_01"
#define MQTT_USER   "master_zero"
#define MQTT_PASS   "ZLP2yEngXa2yzrgI"
#define MQTT_TOPIC  "Status"
#define APN "VILESIM"


// ================= AT Helper =================
String atCmd(const String &cmd, uint32_t timeout = 5000) {
  while (Serial1.available()) Serial1.read();

  if (cmd.length()) {
    Serial.print(">>> ");
    Serial.println(cmd);
    Serial1.println(cmd);
  }

  String resp;
  uint32_t t = millis();

  while (millis() - t < timeout) {
    while (Serial1.available()) {
      char c = Serial1.read();
      resp += c;
      Serial.write(c);
    }
    delay(1);
  }

  return resp;
}

// ================= SPIFFS -> MC60 CERT WRITE =================
bool mc60WriteCertFromSPIFFS() {
  File f = SPIFFS.open("/ca.crt", "r");
  if (!f) {
    Serial.println("Certificate not found in SPIFFS");
    return false;
  }

  size_t certLen = f.size();
  Serial.print("SPIFFS Cert Length: ");
  Serial.println(certLen);

 atCmd("AT+QSECDEL=\"UFS:ca.crt\"");

String cmd = "AT+QSECWRITE=\"UFS:ca.crt\"," + String(certLen) + ",100";

  String resp = atCmd(cmd, 5000);

  if (resp.indexOf("CONNECT") == -1) {
    Serial.println("No CONNECT received");
    f.close();
    return false;
  }

  while (f.available()) {
    Serial1.write(f.read());
  }

  resp = atCmd("", 20000);
  f.close();

  if (resp.indexOf("OK") != -1) {
    Serial.println("Certificate write successful");
    // Cross-check: Read again content 
   String check = atCmd("AT+QSECREAD=\"UFS:ca.crt\"");
   return (check.indexOf("+QSECREAD:") != -1);
  }

  Serial.println("Certificate write failed");
  return false;
}

// ================= NETWORK =================
bool mc60Network() {
  atCmd("AT");
  atCmd("ATE0");
  atCmd("AT+CFUN=1");
  delay(2000);

  if (atCmd("AT+CPIN?").indexOf("READY") == -1) return false;
  if (atCmd("AT+CREG?").indexOf(",1") == -1 &&
      atCmd("AT+CREG?").indexOf(",5") == -1) return false;

  atCmd("AT+CGATT=1");
  atCmd("AT+QIDEACT");
  atCmd(String("AT+QIREGAPP=\"") + APN + "\",\"\",\"\"");
  if (atCmd("AT+QIACT").indexOf("OK") == -1) return false;

  // Verify local IP address 
  String ip = atCmd("AT+QILOCIP");
  Serial.print("Local IP: ");
  Serial.println(ip);

  // Verify time
  atCmd("AT+QLTS");


  
  return true;
}

// ================= MQTT SSL =================
bool mc60MQTTConnect() {
  // --- CLEANUP (harmless if not connected) ---
  atCmd("AT+QMTDISC=0", 1000);
  atCmd("AT+QMTCLOSE=0", 1000);

  atCmd("AT+QMTCFG=\"keepalive\",0,60");

  // --- WRITE CERT ---
  if (!mc60WriteCertFromSPIFFS()) {
    Serial.println("CERT WRITE FAILED");
    return false;
  }

  // --- SSL CONTEXT ID = 2 CONFIG ---
  atCmd("AT+QSSLCFG=\"cacert\",2,\"UFS:ca.crt\"");   // Root CA
  atCmd("AT+QSSLCFG=\"seclevel\",2,1");                     // Server authentication
  atCmd("AT+QSSLCFG=\"sslversion\",2,4");                   // TLS1.2
  atCmd("AT+QSSLCFG=\"ciphersuite\",2,\"0xFFFF\"");         // Default cipher
  
  atCmd("AT+QSSLCFG=\"ignorertctime\",1");                // Ignore RTC if time wrong
  atCmd("AT+QSSLCFG=\"sni\",2,1");                          // Enable SNI if broker uses domain

  // --- LINK SSL CONTEXT TO MQTT CLIENT 0 ---
  // Format: AT+QMTCFG="SSL",<client_id>,1,<ssl_ctx_id>
  atCmd("AT+QMTCFG=\"SSL\",0,1,2");

  // --- OPEN MQTT SSL SOCKET ---
  String openCmd = String("AT+QMTOPEN=0,\"") + MQTT_HOST + "\"," + MQTT_PORT;
  Serial.println(openCmd);
  Serial1.println(openCmd);

  uint32_t start = millis();
  String buf;
  int result = -1;

  while (millis() - start < 45000) {
    while (Serial1.available()) {
      char c = Serial1.read();
      buf += c;
      Serial.write(c);

      // Wait for complete URC line
      if (buf.indexOf("+QMTOPEN:") != -1 && (c == '\n' || c == '\r')) {

        int idx = buf.indexOf("+QMTOPEN: 0,");
        if (idx != -1 && buf.length() > idx + 13) {
          result = buf.charAt(idx + 12) - '0';
        }

        if (result == 0) {
          Serial.println("MQTT SSL TCP Connected");
          goto OPEN_DONE;
        } else if (result >= 1 && result <= 6) {
          Serial.println("MQTT SSL OPEN FAILED");
          return false;
        }
      }
    }
    delay(1);
  }

  if (result != 0) return false;

OPEN_DONE:
  delay(1000);

  // --- CONNECT MQTT SESSION ---
  String connCmd =
      String("AT+QMTCONN=0,\"") + MQTT_CLIENT + "\",\"" + MQTT_USER + "\",\"" + MQTT_PASS + "\"";

  String connResp = atCmd(connCmd, 20000);

  if (connResp.indexOf("+QMTCONN: 0,0,0") != -1) {
    Serial.println("MQTT SSL CONNECTED");
    // Format: AT+QMTSUB=<client_id>,<msg_id>,"topic",<qos>
    atCmd("AT+QMTSUB=0,1,\"" + String(MQTT_TOPIC) + "\",1", 5000);
    return true;
  }

  Serial.println("MQTT SSL LOGIN FAILED");
  return false;
}


// ================= PUBLISH =================
bool mc60Publish(const char *msg) {
  String pubCmd = String("AT+QMTPUB=0,0,0,1,\"") + MQTT_TOPIC + "\"";
  atCmd(pubCmd, 2000);

  Serial1.print(msg);
  Serial1.write(0x1A);

  return (atCmd("", 10000).indexOf("+QMTPUB: 0,0,0") != -1);
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  Serial1.begin(MODEM_BAUD, SERIAL_8N1, MODEM_RX, MODEM_TX);

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount Failed");
    while (1);
  }

  Serial.println("=== MC60 MQTT SSL with SPIFFS CERT ===");

  if (!mc60Network()) {
    Serial.println("NETWORK FAILED");
    while (1);
  }

  if (!mc60MQTTConnect()) {
    Serial.println("MQTT SSL FAILED");
    while (1);
  }

  Serial.println("MQTT SSL CONNECTED");
  mc60Publish("SSL is stable and alive");
  mc60Publish("HELLO");
}

// ================= LOOP =================
void loop() {
  while (Serial1.available())
    Serial.write(Serial1.read());
}
