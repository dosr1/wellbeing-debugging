# Reproduzierbare Frida-Analyse eines Android-Signers

Diese Anleitung beschreibt den bei der David-Lloyd-App erfolgreich verwendeten
Ablauf, um in einer eigenen beziehungsweise autorisiert untersuchten Android-APK
folgende Eigenschaften zu bestimmen, ohne Schlüssel oder Tokens auszugeben:

- Kanonisierung der signierten Request-Daten;
- Hash- und MAC-Verfahren;
- Verschlüsselungsalgorithmen und Provider;
- Key- und Ein-/Ausgabelängen;
- Android-Keystore-Zugriffe;
- Java-Aufrufpfade bis in den obfuskierten App-Code.

Die Anleitung ist für lokale Tests an eigenen Konten und Geräten gedacht. Sie
soll nicht zum Extrahieren fremder Schlüssel, Umgehen von Attestierung oder
Automatisieren nicht autorisierter Aktionen verwendet werden.

## Getesteter Versionsstand

| Komponente | Verwendete Version |
|---|---:|
| Host | macOS auf Apple Silicon/ARM64 |
| Python | 3.11.9 |
| Frida Python-Paket | 17.23.3 |
| Frida CLI | 17.23.3 |
| `frida-tools` | 14.11.0 |
| `frida-server` | 17.23.3, Android ARM64 |
| `frida-java-bridge` | 7.0.13 |
| `esbuild` | 0.28.2 |
| `buffer` | 6.0.3 |
| Node.js | 25.9.0 |
| npm | 11.12.1 |
| ADB | 37.0.1-15733141 |
| Android Emulator | 37.2.12.0 |
| untersuchter AVD | Android API 37, ARM64, Google Play Store |
| Magisk im API-37-AVD | 31.0 |
| `rootAVD` | Commit `0043bd2` des verwendeten Forks |

Host-Paket und `frida-server` müssen dieselbe Frida-Version haben. Ein
Versionsmix ist eine häufige Ursache für Verbindungs- und Protokollfehler.

Der API-37-AVD war für Frida-Java-Instrumentierung nicht stabil: Der
instrumentierte Prozess endete reproduzierbar mit einem nativen SIGSEGV in
`libart.so` während der Garbage Collection. Für neue Analysen ist deshalb ein
ARM64-AVD mit Android API 35 oder 36 vorzuziehen, sofern die Ziel-App dort
läuft. API 37 kann für statische Analyse und normale App-Ausführung weiterhin
verwendet werden.

## Vorbereitungen

Benötigt werden:

1. Android Studio mit einem ARM64-AVD;
2. ein zur App passendes System-Image, bei Bedarf mit Google Play Store;
3. Root im AVD, beispielsweise über `rootAVD` und Magisk;
4. ein `frida-server` für Android ARM64 in exakt der Host-Frida-Version;
5. ADB, Python, Node.js und npm;
6. die zu untersuchende APK und ein eigenes Testkonto.

ABI, Android-Version und Paket prüfen:

```bash
adb -s emulator-5554 shell getprop ro.product.cpu.abi
adb -s emulator-5554 shell getprop ro.build.version.sdk
adb -s emulator-5554 shell pm list packages | sort
```

Erwartetes ABI auf Apple-Silicon-AVDs:

```text
arm64-v8a
```

## AVD rooten

Beim Test wurde ein Google-Play-Store-AVD mit `rootAVD` gepatcht. Der Pfad zum
System-Image muss zum tatsächlich verwendeten AVD passen.

Beispiel für API 37:

```bash
git clone --depth 1 https://github.com/galihlasahido/rootAVD.git /private/tmp/rootAVD
cd /private/tmp/rootAVD

# Für API 37 wurde gezielt die mitgelieferte Magisk-Version 31 verwendet.
cp Magisk31.zip Magisk.zip

./rootAVD.sh \
  system-images/android-37.0/google_apis_playstore/arm64-v8a/ramdisk.img
```

Danach:

1. den AVD vollständig herunterfahren;
2. einen Cold Boot ohne Snapshot durchführen;
3. Magisk öffnen;
4. gegebenenfalls „Requires additional setup“ bestätigen;
5. den dadurch ausgelösten Neustart abwarten.

Cold Boot:

```bash
$ANDROID_SDK_ROOT/emulator/emulator @NAME_DES_AVD -no-snapshot-load
```

Root prüfen:

```bash
adb -s emulator-5554 shell 'command -v su; su -c id'
```

Erwartet wird unter anderem:

```text
uid=0(root) gid=0(root) context=u:r:magisk:s0
```

`rootAVD` legt ein Backup der ursprünglichen Ramdisk an. Bei einem nicht
bootenden Patch zuerst dieses Backup mit der `restore`-Option zurückspielen,
statt das AVD-Datenverzeichnis zu löschen.

## Frida auf dem Host installieren

Eine temporäre virtuelle Umgebung verhindert Konflikte mit anderen Projekten:

```bash
python3 -m venv /private/tmp/frida-venv
/private/tmp/frida-venv/bin/pip install \
  frida==17.23.3 \
  frida-tools==14.11.0
```

Version prüfen:

```bash
/private/tmp/frida-venv/bin/frida --version
```

## `frida-server` im Emulator starten

Den offiziellen Android-ARM64-Server derselben Frida-Version herunterladen,
entpacken und lokal als `frida-server` ablegen. Anschließend:

```bash
adb -s emulator-5554 push frida-server /data/local/tmp/frida-server

adb -s emulator-5554 shell \
  "su -c 'chmod 755 /data/local/tmp/frida-server; \
  nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"

adb -s emulator-5554 forward tcp:27042 tcp:27042
```

Verbindung prüfen:

```bash
/private/tmp/frida-venv/bin/frida-ps -H 127.0.0.1:27042
```

Wenn keine Prozesse erscheinen:

```bash
adb -s emulator-5554 shell 'su -c id'
adb -s emulator-5554 shell pidof frida-server
adb -s emulator-5554 forward --list
```

## JavaScript-Agent vorbereiten

Frida 17 wurde hier mit einem explizit importierten Java-Bridge-Modul verwendet:

```javascript
import Java from "frida-java-bridge";
```

Abhängigkeiten:

```bash
npm install --prefix /private/tmp/frida-agent \
  frida-java-bridge@7.0.13 \
  esbuild@0.28.2 \
  buffer@6.0.3
```

Agent bündeln:

```bash
cp tools/davidlloyd_signer_probe.js /private/tmp/frida-agent/probe.js

/private/tmp/frida-agent/node_modules/.bin/esbuild \
  /private/tmp/frida-agent/probe.js \
  --bundle \
  --platform=neutral \
  --format=iife \
  --outfile=/private/tmp/signer-probe.bundle.js
```

Die vollständige, datensparsame Vorlage liegt in:

- [`tools/davidlloyd_signer_probe.js`](tools/davidlloyd_signer_probe.js)
- [`tools/run_davidlloyd_signer_probe.py`](tools/run_davidlloyd_signer_probe.py)

Vor Wiederverwendung müssen Paketname, Prozessname und zielsystemspezifische
Stackfilter angepasst werden.

## Grundstruktur eines sicheren Hooks

Alle Java-Hooks werden innerhalb von `Java.perform()` installiert:

```javascript
Java.perform(function () {
  const Thread = Java.use("java.lang.Thread");

  function stack() {
    return Thread.currentThread()
      .getStackTrace()
      .map(frame => frame.toString())
      .filter(text => !text.startsWith("java."))
      .slice(0, 14);
  }

  send({ kind: "probe-ready", pid: Process.id });
});
```

Wichtige Regeln:

- immer die konkrete Overload-Signatur auswählen;
- die gespeicherte Original-Overload mit `.call(this, ...)` aufrufen;
- Rückgabewert unverändert zurückgeben;
- niemals Keybytes, Tokens, Passwörter oder vollständige Bodies senden;
- bei optionalen Klassen Hookfehler als Warnung melden, nicht den Agenten
  abbrechen lassen.

## 1. Kanonisierung bestimmen

Der stabilste Beobachtungspunkt ist häufig `javax.crypto.Mac`, weil direkt vor
der MAC-Bildung bereits die kanonisierte Eingabe vorliegt.

Zu hookende Methoden:

```text
Mac.init(Key)
Mac.update(byte[])
Mac.update(byte[], int, int)
Mac.doFinal()
```

Pro `Mac`-Instanz wird ein Zustand über `System.identityHashCode(instance)`
geführt. Jede `update()`-Eingabe wird als Bytefolge und Länge gesammelt. Bei
`doFinal()` werden nur folgende Metadaten ausgegeben:

- Gesamtlänge;
- Segmentlängen;
- Anzahl und Längen newline-separierter Komponenten;
- redigierte Form der druckbaren Zeichen;
- Algorithmus, Provider und Stacktrace;
- MAC-Ausgabelänge.

Kernmuster:

```javascript
const System = Java.use("java.lang.System");
const Mac = Java.use("javax.crypto.Mac");
const states = Object.create(null);

function id(instance) {
  return String(System.identityHashCode(instance));
}

const update = Mac.update.overload("[B");
update.implementation = function (input) {
  // Kopie nur für Längen und redigierte Struktur verwenden.
  remember(id(this), input);
  return update.call(this, input);
};

const finish = Mac.doFinal.overload();
finish.implementation = function () {
  const output = finish.call(this);
  emitSafeMacSummary(this, output.length);
  return output;
};
```

### Wichtiger Overload-Fall

Nicht gleichzeitig `Mac.doFinal(byte[])` vollständig auswerten, wenn die
Providerimplementierung intern daraus `update(byte[])` plus `doFinal()` macht.
Beim ersten Versuch wurden dadurch Eingaben doppelt gezählt. Für die
untersuchte App genügte:

- Daten in beiden `update`-Overloads sammeln;
- ausschließlich beim parameterlosen `doFinal()` abschließen.

Wenn eine andere Providerimplementierung das nicht tut, muss der
`doFinal(byte[])`-Hook gezielt angepasst werden, ohne denselben Vorgang zweimal
zu protokollieren.

### Sichere Strukturvorschau

Eine Vorschaufunktion sollte mindestens entfernen:

- JSON-Stringwerte;
- Query-Parameterwerte;
- lange Base64-/Token-artige Zeichenfolgen;
- längere Zahlenfolgen;
- Binärdaten.

Beispielausgabe:

```json
{
  "kind": "mac-final",
  "algorithm": "HmacSHA256",
  "provider": "AndroidOpenSSL",
  "inputLength": 99,
  "segmentLengths": [99],
  "components": [
    {"length": 4, "shape": "POST"},
    {"length": 16, "shape": "/example/path"},
    {"length": 16, "shape": "application/json"},
    {"length": 32, "shape": "<blob>"},
    {"length": 16, "shape": "<blob>"},
    {"length": 10, "shape": "<number>"}
  ],
  "outputLength": 32
}
```

## 2. Hashverfahren bestimmen

Hook:

```text
java.security.MessageDigest.digest(byte[])
```

Auszugeben sind nur:

- `getAlgorithm()`;
- Eingabelänge;
- redigierte Eingabeform;
- Ausgabelänge;
- Stacktrace.

Beispiel:

```javascript
const MessageDigest = Java.use("java.security.MessageDigest");
const digest = MessageDigest.digest.overload("[B");

digest.implementation = function (input) {
  const output = digest.call(this, input);
  const frames = stack();

  if (belongsToTargetApp(frames)) {
    send({
      kind: "message-digest",
      algorithm: this.getAlgorithm().toString(),
      inputLength: input.length,
      outputLength: output.length,
      stack: frames
    });
  }
  return output;
};
```

Ohne Stackfilter entstehen viele irrelevante SHA-/MD5-Aufrufe aus
Zertifikatsprüfung, WebView, Telemetrie und Bibliotheken. Zuerst breit messen,
danach auf die im Stack gefundenen App-Klassen einschränken.

## 3. Kryptoalgorithmen und Provider bestimmen

Für asymmetrische Ver- und Entschlüsselung:

```text
javax.crypto.Cipher.init(int, Key)
javax.crypto.Cipher.doFinal(byte[])
```

Bei `init()` erfassen:

- `getAlgorithm()` beziehungsweise Transformation;
- `getProvider().getName()`;
- Modus (`1` = encrypt, `2` = decrypt);
- Keyalgorithmus, Keyklasse und Keyformat;
- Stacktrace.

Bei `doFinal()` erfassen:

- Eingabelänge;
- Ausgabelänge;
- zuvor für dieselbe `Cipher`-Instanz gespeicherte Transformation;
- Stacktrace.

Keine Ciphertext- oder Plaintextbytes ausgeben.

Beispielstruktur:

```javascript
const Cipher = Java.use("javax.crypto.Cipher");
const init = Cipher.init.overload("int", "java.security.Key");

init.implementation = function (mode, key) {
  const result = init.call(this, mode, key);
  send({
    kind: "cipher-init",
    mode,
    transformation: this.getAlgorithm().toString(),
    provider: this.getProvider().getName().toString(),
    keyAlgorithm: key.getAlgorithm().toString(),
    keyFormat: key.getFormat() === null ? null : key.getFormat().toString(),
    stack: stack()
  });
  return result;
};
```

Ein Transformationsname wie
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` bestimmt nicht in jedem Provider
eindeutig den intern verwendeten MGF1-Digest. Dafür zusätzlich
`Cipher.getParameters()` beziehungsweise explizite `OAEPParameterSpec`-Hooks
prüfen oder beide bekannten Varianten lokal mit einem Testciphertext
verifizieren.

## 4. Key-Längen bestimmen

Für symmetrische HMAC-Keys:

```text
javax.crypto.spec.SecretKeySpec(byte[], String)
```

Sicherer Hook:

```javascript
const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
const init = SecretKeySpec.$init.overload("[B", "java.lang.String");

init.implementation = function (keyBytes, algorithm) {
  const result = init.call(this, keyBytes, algorithm);
  const name = algorithm === null ? "" : algorithm.toString();

  if (name.toLowerCase().includes("hmac")) {
    send({
      kind: "secret-key-spec",
      algorithm: name,
      keyLength: keyBytes === null ? null : keyBytes.length,
      stack: stack()
    });
  }
  return result;
};
```

Nur die Länge erfassen. `getEncoded()` nicht aufrufen und Keybytes weder in Hex
noch Base64 umwandeln.

Weitere nützliche Längen:

- RSA-Ciphertextlänge bei `Cipher.doFinal()`;
- entschlüsselte Ausgabelänge;
- MAC-Ausgabelänge;
- DER-Länge eines ohnehin öffentlichen Keys;
- kanonische Eingabelänge und Segmentlängen.

## 5. Android-Keystore-Zugriffe beobachten

Wichtigster Hook:

```text
java.security.KeyStore.getKey(String, char[])
```

Zu erfassen sind:

- `KeyStore.getType()`;
- Alias oder nur Aliaslänge beziehungsweise redigierte Aliasform;
- Keyalgorithmus;
- konkrete Keyklasse;
- `getFormat()`;
- Stacktrace.

```javascript
const KeyStore = Java.use("java.security.KeyStore");
const getKey = KeyStore.getKey.overload("java.lang.String", "[C");

getKey.implementation = function (alias, password) {
  const key = getKey.call(this, alias, password);
  const rawAlias = alias === null ? "" : alias.toString();

  send({
    kind: "keystore-get-key",
    storeType: this.getType().toString(),
    aliasShape: rawAlias.length <= 24 ? rawAlias : "<redacted-long-alias>",
    aliasLength: rawAlias.length,
    keyAlgorithm: key === null ? null : key.getAlgorithm().toString(),
    keyClass: key === null ? null : key.getClass().getName().toString(),
    keyFormat: key === null || key.getFormat() === null
      ? null
      : key.getFormat().toString(),
    stack: stack()
  });
  return key;
};
```

`keyFormat: null` ist bei nicht exportierbaren Android-Keystore-Private-Keys
erwartbar. Es beweist allein aber keine Hardwarebindung. Für TEE oder StrongBox
ist eine Android-Key-Attestation erforderlich. Ein Emulator-Key ist
softwarebasiert.

Je nach Ziel können zusätzlich beobachtet werden:

```text
KeyStore.containsAlias(String)
KeyStore.deleteEntry(String)
KeyStore.getCertificate(String)
KeyPairGenerator.initialize(...)
KeyPairGenerator.generateKeyPair()
```

Damit lässt sich der Lebenszyklus eines temporären Keys bestimmen, ohne ihn zu
exportieren.

## 6. Aufrufpfade ermitteln

Für jedes relevante Ereignis wird ein gekürzter Java-Stacktrace erzeugt:

```javascript
function stack() {
  const frames = Thread.currentThread().getStackTrace();
  const result = [];

  for (let i = 0; i < frames.length && result.length < 14; i++) {
    const text = frames[i].toString();
    if (!/^(java\.|javax\.|android\.|dalvik\.|sun\.)/.test(text)) {
      result.push(text);
    }
  }
  return result;
}
```

Die ersten nicht-systemeigenen Frames führen gewöhnlich zu:

- einem App-Interceptor;
- einem Repository beziehungsweise Key-Manager;
- einer obfuskierten Hilfsmethode;
- der Retrofit-/OkHttp-Schicht.

Diese Klassennamen anschließend statisch in JADX oder `dexdump` untersuchen.
So wurde beim Beispiel aus einem generischen HMAC-Aufruf der App-Interceptor
`T8.b`, die Kanonisierungsfunktion `ao.i.n` und die HMAC-Funktion `ao.i.E`
ermittelt.

## Python-Runner

Der vorhandene Runner verbindet sich über den weitergeleiteten TCP-Port,
startet die Ziel-App bei Bedarf und lädt den Agenten:

```python
manager = frida.get_device_manager()
device = manager.add_remote_device("127.0.0.1:27042")
pid = device.spawn([PACKAGE_NAME])
session = device.attach(pid)
script = session.create_script(bundle_source)
script.on("message", on_message)
script.load()
device.resume(pid)
```

Start mit der vorhandenen Vorlage:

```bash
DAVID_LLOYD_FRIDA_SCRIPT=/private/tmp/signer-probe.bundle.js \
  /private/tmp/frida-venv/bin/python \
  tools/run_davidlloyd_signer_probe.py
```

Für eine andere APK anpassen:

1. `PACKAGE_NAME` im Runner;
2. den erwarteten Prozess-/Anzeigenamen oder immer kontrolliert spawnen;
3. zielsystemspezifische Stackfilter im JavaScript;
4. optionale Netzwerkklassen;
5. erlaubte Aliasdarstellung und Redaktionsregeln.

## Empfohlener Analyseablauf

1. App ohne Frida starten und eine Baseline-Aktion prüfen.
2. App-Prozess beenden.
3. Frida zunächst nur mit `Mac`, `MessageDigest`, `Cipher`, `SecretKeySpec`
   und `KeyStore.getKey` starten.
4. Genau eine relevante App-Aktion ausführen.
5. Ereignisse nach Stacktrace gruppieren.
6. Irrelevante Bibliotheksaufrufe über Paket-/Klassenfilter ausschließen.
7. Gefundene App-Klassen statisch dekompilieren oder disassemblieren.
8. Kanonisierung und Key-Lebenszyklus statisch bestätigen.
9. Erst danach gezielte Hooks auf App-Klassen ergänzen.
10. Agent und Portweiterleitung nach der Analyse beenden.

Diese Reihenfolge reduziert Abstürze und verhindert, dass ein zu breiter Hook
unnötig viele sensible Daten oder irrelevante Kryptografieereignisse erfasst.

## Statische Bestätigung

Laufzeitbeobachtung zeigt, was tatsächlich ausgeführt wird. Die genaue Logik
sollte anschließend statisch bestätigt werden.

APK-Pfad des installierten Pakets:

```bash
adb -s emulator-5554 shell pm path com.example.app
adb -s emulator-5554 pull /data/app/.../base.apk /private/tmp/base.apk
```

Mit JADX dekompilieren oder die DEX-Dateien extrahieren:

```bash
mkdir -p /private/tmp/app-dex
unzip -jo /private/tmp/base.apk 'classes*.dex' -d /private/tmp/app-dex
```

Klasse mit `dexdump` suchen:

```bash
for dex_file in /private/tmp/app-dex/*.dex; do
  $ANDROID_SDK_ROOT/build-tools/36.0.0/dexdump -n "$dex_file" \
    | rg "Class descriptor.*'Lexample/Signer;'"
done
```

Bei statischer Ausgabe darauf achten, keine eingebetteten Secrets oder
produktiven Tokens in Terminalausgaben, Tickets oder Repositories zu kopieren.

## Typische Probleme

### `ClassNotFoundException` bei OkHttp

Die App kann OkHttp schattieren oder obfuskieren. Nicht von
`okhttp3.Request$Builder` als festem Klassennamen ausgehen. Zuerst die
Standard-Krypto-APIs hooken und über deren Stacktraces die tatsächlichen
Netzwerkklassen finden.

### Attach-Timeout

Ein bereits hängender Prozess lässt sich teilweise nicht pausieren. App-Prozess
beenden und kontrolliert über Frida neu spawnen:

```bash
adb -s emulator-5554 shell am force-stop com.example.app
```

### Prozess endet, `crash=false`

Frida meldet beim nativen Prozessende möglicherweise nur
`process-terminated`. Androids tatsächliche Exit-Ursache prüfen:

```bash
adb -s emulator-5554 shell dumpsys activity exit-info com.example.app
adb -s emulator-5554 logcat -d -b crash -v threadtime
```

### SIGSEGV in `libart.so`

Beim getesteten Android-17-Preview-Image trat ein Nullpointer-SIGSEGV im
ART-Garbage-Collector auf. Das war ein Instrumentierungsproblem, keine
Anwendungsentscheidung. Abhilfe:

- API 35 oder 36 verwenden;
- Hookumfang reduzieren;
- App kontrolliert spawnen;
- nicht mehrere überlappende Overloads desselben Vorgangs hooken;
- Frida-Host und Serverversion exakt abgleichen.

### App startet nach einem Crash automatisch neu

Der neue Prozess ist nicht mehr an die alte Frida-Session gebunden. PID und
Android-Exit-Info prüfen; nicht davon ausgehen, dass eine anschließend
ausgeführte Aktion noch instrumentiert wurde.

## Analyse sauber beenden

Runner mit `Ctrl-C` beenden. Danach:

```bash
adb -s emulator-5554 shell "su -c 'pkill frida-server'"
adb -s emulator-5554 forward --remove tcp:27042
```

Kontrolle:

```bash
adb -s emulator-5554 shell pidof frida-server
adb -s emulator-5554 forward --list
```

Temporäre Host-Artefakte können anschließend entfernt werden. Das gerootete
AVD und die App-Daten bleiben davon unberührt.

## Rolle von Proxyman

Frida ersetzt einen HTTP-Proxy nicht vollständig:

- Proxyman zeigt URLs, Header, Bodies, Responses, Statuscodes und Retryfolge.
- Frida zeigt Kanonisierung, Hashes, Kryptoalgorithmen, Key-Längen, Keystore und
  interne Aufrufpfade.
- Statische Analyse bestätigt die genaue Implementierung.

Für eine neue APK ist die Kombination aus einem redigierten Proxy-Mitschnitt,
datensparsamen Frida-Hooks und anschließender statischer APK-Analyse am
effizientesten. Wenn Endpunkte und Bodies bereits bekannt sind, kann Proxyman
entfallen; für die interne Signerlogik bleibt Frida die wichtigere Quelle.
