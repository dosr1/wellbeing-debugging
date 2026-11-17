# Reproduzierbarer Android-HTTP(S)-Mitschnitt mit Proxyman

Diese Anleitung beschreibt einen wiederverwendbaren Ablauf, um den
HTTP(S)-Verkehr einer eigenen oder ausdrücklich autorisiert untersuchten
Android-App in einem Emulator mit Proxyman aufzuzeichnen. Sie ist bewusst
projektneutral gehalten. Beispiel-Domains wie `api.example.com` müssen durch
die Domains des jeweiligen Projekts ersetzt werden.

Ein Mitschnitt kann Zugangstoken, Sitzungs-Cookies, Passwörter, persönliche
Daten und Gerätekennungen enthalten. Eine gespeicherte Proxyman-Session ist
daher wie ein Geheimnis zu behandeln: nicht in Git einchecken, nicht ungeprüft
teilen und nach der Analyse geschützt löschen oder archivieren.

## Referenzumgebung

Die folgenden Versionen wurden in der Ausgangsumgebung verwendet:

| Komponente | Version beziehungsweise Konfiguration |
|---|---|
| macOS | Apple-Silicon-Mac |
| Proxyman | 26.0.1, Build 260001 |
| Android Platform Tools / ADB | 37.0.1-15733141 |
| Android Emulator | 37.2.12.0 |
| untersuchter AVD | Android API 37, ARM64, Google Play Store |

Die Methodik funktioniert auch mit anderen aktuellen Versionen. Bei einem neu
angelegten Analyse-AVD ist ein stabiles Google-APIs-Image oft einfacher als ein
Play-Store-Image: Es lässt sich typischerweise leichter rooten und entspricht
dem von Proxyman dokumentierten automatischen Emulator-Ablauf besser.

## Was ein HTTPS-Proxy sehen kann

Ohne TLS-Entschlüsselung sieht Proxyman im Wesentlichen Zielhost, Port,
Verbindungszeitpunkt und `CONNECT`-Verbindungen. Mit installiertem und von der
App akzeptiertem Proxyman-CA-Zertifikat sieht es zusätzlich:

- HTTP-Methode, Pfad und Query-Parameter;
- Request- und Response-Header;
- Request- und Response-Body;
- Statuscode, Timing, Weiterleitungen und Wiederholungen.

Das reicht nicht in jedem Fall. Eine App kann den Systemproxy umgehen, QUIC
über UDP verwenden, Zertifikat-Pinning einsetzen, Mutual TLS verlangen oder
Payloads bereits auf Anwendungsebene verschlüsseln. Diese Fälle werden weiter
unten getrennt behandelt.

## 1. Analyse-AVD vorbereiten

Für reproduzierbare Untersuchungen einen eigenen AVD verwenden. Er sollte keine
privaten Konten oder Daten enthalten, die für den Test nicht benötigt werden.

AVDs anzeigen und Emulator starten:

```bash
$ANDROID_HOME/emulator/emulator -list-avds
$ANDROID_HOME/emulator/emulator @NAME_DES_AVD
```

Falls `ANDROID_HOME` nicht gesetzt ist, liegen die Programme auf macOS meist
hier:

```bash
/Users/NAME/Library/Android/sdk/emulator/emulator
/Users/NAME/Library/Android/sdk/platform-tools/adb
```

Nach dem Boot prüfen:

```bash
adb devices
adb shell getprop sys.boot_completed
adb shell getprop ro.build.version.release
adb shell getprop ro.product.cpu.abi
```

Erwartet werden ein Gerät im Zustand `device`, `sys.boot_completed=1` und die
zum System-Image passende ABI, auf Apple Silicon üblicherweise `arm64-v8a`.

### Typische AVD-Hürden

**Nicht genug Speicherplatz für die Userdata-Partition**

Die konfigurierte AVD-Datenträgergröße ist größer als der freie Platz. In
Android Studio unter **Device Manager → Edit → Show Advanced Settings** die
interne Speichergröße reduzieren oder ausreichend Speicher auf dem Mac
freigeben. Bestehende AVD-Daten nur löschen, wenn ein Zurücksetzen wirklich
beabsichtigt ist.

**AVD bootet, ADB zeigt aber `offline`**

Den Boot vollständig abwarten und zuerst `adb reconnect` versuchen. Bei
mehreren Emulatoren jedes Kommando mit `-s emulator-PORT` eindeutig einem
Gerät zuordnen.

**Root beziehungsweise System-CA wird benötigt**

Für die erste Runde ist Root nicht nötig. Erst wenn die Ziel-App einer
benutzerinstallierten CA nicht vertraut, ist ein separater rootbarer Test-AVD
sinnvoll. Play-Store-Images sind absichtlich stärker gesperrt als
Google-APIs/AOSP-Images.

## 2. Proxyman vorbereiten

1. Proxyman starten.
2. Prüfen, dass die Aufzeichnung nicht pausiert ist.
3. Alte Requests löschen oder eine neue leere Session beginnen.
4. Noch nicht global `*` für SSL Proxying aktivieren.
5. VPNs auf Mac und Emulator für den Test deaktivieren, sofern sie nicht Teil
   des untersuchten Ablaufs sind.

Proxyman lauscht standardmäßig auf Port `9090`. Der aktuelle Port ist in den
Proxyman-Einstellungen beziehungsweise im Zertifikatsdialog zu prüfen, statt
ihn blind zu übernehmen.

## 3. Emulator mit Proxyman verbinden

### Bevorzugt: Proxymans automatischer Emulator-Ablauf

In Proxyman:

1. **Certificate → Install Certificate on Android → Emulators** öffnen.
2. Den gewünschten laufenden Emulator auswählen.
3. Den angebotenen Installations- beziehungsweise Override-Ablauf ausführen.
4. Danach im Android-Browser eine HTTPS-Seite öffnen und in Proxyman prüfen,
   ob sie erscheint und entschlüsselt wird.

Aktuelle Proxyman-Versionen können Proxy und Systemzertifikat für unterstützte
Emulatoren automatisch konfigurieren. Vor dem Beenden von Proxyman oder dem
Emulator **Revert All Changes** ausführen. Andernfalls kann im AVD ein
Proxy-Eintrag zurückbleiben und der Emulator beim nächsten Start scheinbar
keinen Internetzugang haben.

Offizielle Anleitung:
[Automatic Script for Android Emulator](https://docs.proxyman.com/debug-devices/android-device/automatic-script-for-android-emulator)

### Fallback: Proxy manuell setzen

Vom Android-Standardemulator zeigt `10.0.2.2` auf den Host-Mac. Den Proxy kann
man daher für einen lokalen Proxyman-Port `9090` so setzen:

```bash
adb shell settings put global http_proxy 10.0.2.2:9090
adb shell settings get global http_proxy
```

Bei mehreren AVDs:

```bash
adb -s emulator-5554 shell settings put global http_proxy 10.0.2.2:9090
```

Für ein physisches Android-Gerät ist `10.0.2.2` falsch. Dort werden die
LAN-IP-Adresse des Macs und derselbe Proxy-Port eingetragen; Mac und Gerät
müssen einander im Netzwerk erreichen können.

Manuellen Proxy später entfernen:

```bash
adb shell settings put global http_proxy :0
adb shell settings get global http_proxy
```

Falls Android den leeren Eintrag nicht sauber übernimmt:

```bash
adb shell settings delete global http_proxy
```

## 4. Proxyman-Zertifikat installieren

Im Android-Browser eine der von Proxyman angegebenen lokalen Seiten öffnen:

```text
http://proxy.man/ssl
http://cert.proxyman.io
```

Das Zertifikat herunterladen. Ab Android 11 wird eine heruntergeladene CA
häufig nicht direkt durch Antippen installiert. Stattdessen ungefähr folgenden
Systempfad verwenden; die Bezeichnungen unterscheiden sich je nach Hersteller
und Android-Version:

```text
Settings
  → Security
  → Encryption & credentials
  → Install a certificate
  → CA certificate
```

Die Warnung bestätigen und die heruntergeladene Proxyman-CA auswählen. Danach
unter **Trusted credentials → User** prüfen, ob sie vorhanden ist.

Offizielle Anleitung:
[Android Device & Emulator](https://docs.proxyman.com/debug-devices/android-device)

### Benutzer-CA versus System-CA

Seit Android 7 vertrauen Apps benutzerinstallierten CAs nicht automatisch.
Deshalb kann der Android-Browser korrekt entschlüsselt werden, während die
eigentliche App weiterhin TLS-Fehler meldet.

Für die eigene App ist die sauberste Lösung ein Debug-Build, der die
benutzerinstallierte CA über eine `network_security_config` ausschließlich in
Debug-Konfigurationen akzeptiert. Produktions-Builds sollten dadurch nicht
gelockert werden.

Bei einer autorisiert untersuchten fremden APK kann ein rootbarer Test-AVD und
eine temporäre System-CA erforderlich sein. Dafür zuerst Proxymans automatischen
Emulator-Ablauf verwenden. Manuelles Kopieren nach
`/system/etc/security/cacerts` ist auf neueren Android-Versionen wegen
read-only-Partitionen und des Conscrypt-APEX fragil und nicht als
versionsübergreifendes Standardverfahren geeignet.

Eine akzeptierte CA löst kein Zertifikat-Pinning. Pinning vergleicht zusätzlich
Zertifikat oder Public Key und muss separat diagnostiziert werden.

## 5. Erst die beteiligten Hosts entdecken

Bevor TLS für Domains freigeschaltet wird, einmal nur den groben Ablauf
durchführen:

1. Aufzeichnung leeren und starten.
2. App vollständig beenden und neu öffnen.
3. Login-Seite aufrufen, aber noch keine echten Daten eingeben, wenn das für
   die Host-Erkennung nicht nötig ist.
4. Die zu untersuchende Funktion bis kurz vor der finalen Aktion öffnen.
5. In Proxyman alle sichtbaren Hosts beziehungsweise `CONNECT`-Ziele notieren.

Hosts anschließend nach Rolle gruppieren:

| Rolle | Beispiel | Meist relevant? |
|---|---|---:|
| API | `api.example.com` | ja |
| Login / IdP | `login.example-id.com` | ja |
| WebView / Frontend | `app.example.com` | möglicherweise |
| CDN | `cdn.example.com` | nur bei benötigten Payloads |
| Telemetrie | `analytics.vendor.com` | normalerweise nein |
| Crash-Reporting | `crash.vendor.com` | normalerweise nein |

Diese Entdeckungsrunde verhindert, dass man vorschnell nur die API-Domain
freischaltet und dadurch Token-Austausch, Redirects oder dynamische
Konfigurationsaufrufe übersieht.

## 6. SSL Proxying gezielt aktivieren

In Proxyman einen relevanten Host oder Request rechtsklicken und **Enable SSL
Proxying** wählen. Alternativ die Include-Liste in den SSL-Proxying-Einstellungen
pflegen.

Sinnvolle Muster sind beispielsweise:

```text
api.example.com
*.api.example.com
*.example-id.com
```

Globale Muster wie `*` nur kurzfristig zur Diagnose verwenden. Sie erfassen
unnötig private Daten, machen die Session unübersichtlich und können bei viel
Verkehr erheblich Arbeitsspeicher verbrauchen.

Offizielle Hinweise:

- [SSL Proxying](https://docs.proxyman.com/basic-features/ssl-proxying)
- [Allow List](https://docs.proxyman.com/advanced-features/whitelist)
- [Bypass Proxy List](https://docs.proxyman.com/basic-features/bypass-proxy-list)

### Wenn nur zwei SSL-Proxy-Regeln möglich sind

Die Regeln auf die beiden Sicherheitsgrenzen konzentrieren:

```text
*.api.example.com
*.example-id.com
```

Die erste Regel deckt die fachliche API ab, die zweite den Login- und
Token-Austausch. Telemetrie, Bilder und Crash-Reporting nicht entschlüsseln.
Falls API und Login unter derselben registrierbaren Domain liegen, kann ein
passendes gemeinsames Wildcard-Muster eine Regel sparen. Ein zu breites Muster
wie `*.com` ist weder sicher noch praktisch.

## 7. Verbindung vor dem eigentlichen Test verifizieren

Zuerst im Android-Browser eine normale HTTPS-Seite öffnen. Danach einen harmlosen
App-Aufruf auslösen, zum Beispiel Konfiguration oder Profildaten laden.

Für einen brauchbaren Zustand müssen drei Dinge gleichzeitig stimmen:

1. Der Host erscheint in Proxyman.
2. Der relevante Request zeigt entschlüsselte Header und Body statt nur
   `CONNECT` oder TLS-Fehler.
3. Die App funktioniert weiterhin normal.

Erst danach den Login- und Aktionsablauf aufzeichnen. Andernfalls erzeugt man
eine lange, aber diagnostisch wertlose Session.

## 8. Sauberen Login-und-Aktions-Mitschnitt erstellen

### Vor dem Start

- Prüfen, ob die App bereits angemeldet ist.
- Klären, ob ein neuer Login andere Gerätesitzungen beendet.
- Proxyman-Aufzeichnung aktivieren.
- Session leeren.
- Uhrzeit und Zeitzone von Mac und Emulator prüfen.
- Nur notwendige SSL-Proxy-Domains aktiv lassen.
- App per Android-Einstellungen oder `adb shell am force-stop PAKETNAME`
  vollständig beenden.

Wenn die App nur eine aktive Gerätesitzung zulässt, kann der Emulator-Login eine
Sitzung auf dem realen Telefon ungültig machen. Das ist kein Proxyfehler und
sollte vor dem Test eingeplant werden.

### Aufzeichnungssequenz

1. Aufzeichnung starten beziehungsweise kontrollieren, dass sie läuft.
2. App öffnen.
3. Einmal anmelden.
4. Warten, bis die Startansicht vollständig geladen ist.
5. Genau eine fachliche Aktion ausführen.
6. Auf die sichtbare Bestätigung oder Fehlermeldung warten.
7. Keine weiteren Ansichten öffnen.
8. Aufzeichnung sofort pausieren.
9. Session unter einem eindeutigen Namen speichern.

Ein nützliches Namensschema ist:

```text
YYYY-MM-DD_app-version_android-version_szenario.proxymansessionv2
```

Beispiel:

```text
2026-10-11_152.1.0_api37_login-one-action.proxymansessionv2
```

Zusätzlich eine kurze Textnotiz anlegen:

```text
App-Version:
Android-Version / AVD:
Proxyman-Version:
Startzeit:
Endzeit:
SSL-Proxy-Regeln:
Ausgeführte Schritte:
Sichtbares Ergebnis:
Besonderheiten:
```

So bleibt der Mitschnitt später interpretierbar, auch wenn UI und API sich
geändert haben.

## 9. Relevante Requests identifizieren

Zuerst nach der API-Domain filtern, dann zeitlich vom sichtbaren UI-Ereignis
rückwärts arbeiten. Für jeden Kandidaten notieren:

| Feld | Zweck |
|---|---|
| Zeitpunkt | Zuordnung zur UI-Aktion |
| Methode und vollständiger Pfad | Endpunktidentifikation |
| Query-Parameter | Pagination, Filter, IDs |
| Headernamen | Authentisierung und Signaturprotokoll |
| Body-Schema | fachliche Eingabe |
| Statuscode | Erfolg, Retry oder Ablehnung |
| Response-Schema | IDs, Status und Folgeaktionen |
| vorheriger Request | Token-, Key- oder Konfigurationsabhängigkeit |
| nachfolgender Request | Bestätigung, Polling oder UI-Refresh |

Nicht nur den finalen `POST` betrachten. Häufig besteht ein Ablauf aus:

```text
Login
  → Token-Austausch
  → Gerätekonfiguration oder Schlüsselabruf
  → Verfügbarkeitsabfrage
  → fachlicher POST
  → Bestätigungs-GET oder Status-Polling
```

Bei signierten APIs außerdem vergleichen:

- Ändert sich die Signatur bei identischem Body?
- Gibt es Timestamp, Nonce oder Request-ID?
- Gehören Pfad, Query oder Body erkennbar zur Signatur?
- Wird vorher ein kurzlebiger Schlüssel abgerufen?
- Erfolgt nach `401`, `403` oder einer Signaturfehlermeldung ein Retry?

Ein Proxy zeigt die übertragenen Werte, beweist aber nicht, wie die App sie
intern berechnet. Für Kanonisierung, Hashverfahren und Keystore-Zugriffe ist
eine Laufzeitanalyse wie in
[`FRIDA_ANDROID_CRYPTO_ANALYSIS.md`](./FRIDA_ANDROID_CRYPTO_ANALYSIS.md)
geeigneter.

## 10. Session speichern, exportieren und redigieren

Das native `.proxymansessionv2`-Format erhält die meisten Proxyman-Details und
ist die beste Arbeitskopie. Für Werkzeuge außerhalb Proxymans kann zusätzlich
ein HAR- oder cURL-Export sinnvoll sein. Exportierte cURL-Befehle niemals blind
ausführen: Sie können schreibende Requests, gültige Tokens und Cookies
enthalten.

Vor dem Teilen oder Einchecken mindestens folgende Werte entfernen oder durch
eindeutige Platzhalter ersetzen:

- `Authorization`, Access-, Refresh- und ID-Tokens;
- `Cookie` und `Set-Cookie`;
- Benutzername, Passwort, E-Mail-Adresse und Telefonnummer;
- Mitglieds-, Kunden-, Buchungs- und Geräte-IDs;
- Session-, Installations-, Advertising- und Push-Token;
- API-Keys, HMAC-Schlüssel und andere Secret-Materialien;
- signierte URLs und einmalig verwendbare Codes;
- Request- und Response-Bodies mit personenbezogenen Daten.

Headernamen und JSON-Feldnamen können in einer technischen Notiz meistens
erhalten bleiben. Bei Tokenformaten nicht nur Anfang und Ende maskieren, wenn
der verbleibende Teil weiterhin nutzbare oder personenbezogene Daten enthält.

Empfohlenes Ablagemuster:

```text
captures/
  private/     # ignoriert, Originale; nicht committen
  redacted/    # geprüfte, bereinigte Beispiele
  notes/       # Ablauf, Versionen und Schlussfolgerungen
```

Passende `.gitignore`-Regeln:

```gitignore
captures/private/
*.proxymansessionv2
*.har
```

Wenn absichtlich eine bereinigte HAR-Datei versioniert werden soll, sollte sie
explizit und nach manueller Prüfung freigegeben werden, statt alle HAR-Dateien
pauschal zu erlauben.

## 11. Fehlersuche

### Gar kein Verkehr sichtbar

Prüfen:

```bash
adb shell settings get global http_proxy
```

Danach:

- Läuft Proxyman und ist die Aufzeichnung aktiv?
- Stimmt der Port?
- Zeigt der Emulator auf `10.0.2.2`, nicht auf `127.0.0.1`?
- Blockiert eine macOS-Firewall die Verbindung?
- Ist ein VPN oder privates DNS aktiv?
- Verwendet die App einen eigenen Netzwerkstack oder direkte Sockets?

`127.0.0.1` im Emulator bezeichnet den Emulator selbst, nicht den Mac.

### Hosts erscheinen, aber nur als `CONNECT`

Der Proxy funktioniert, TLS wird für diese Domain aber nicht entschlüsselt.

1. Domain in die SSL-Proxying-Include-Liste aufnehmen.
2. Zertifikat im Emulator prüfen.
3. Browser-Test durchführen.
4. App vollständig neu starten, damit alte Verbindungen geschlossen werden.

### Browser funktioniert, App nicht

Wahrscheinliche Ursachen:

- Die App vertraut benutzerinstallierten CAs nicht.
- Die App verwendet Zertifikat-Pinning.
- Die App nutzt einen nativen Netzwerkstack mit eigenem Trust Store.
- Mutual TLS verlangt ein Clientzertifikat.

Bei der eigenen App einen Debug-Build mit Debug-Trust-Konfiguration und
diagnostisch deaktiviertem Pinning verwenden. Bei einer fremden APK nur im
ausdrücklich autorisierten Testumfang fortfahren. Eine System-CA kann fehlendes
CA-Vertrauen lösen, aber kein Pinning.

### `SSL Handshake Failed`, Zertifikatsfehler oder sofortiger App-Abbruch

Zeit und Zeitzone prüfen:

```bash
adb shell date
date
```

Danach Zertifikatsgültigkeit, Zielhostname und Proxyregel kontrollieren. Wenn der
Fehler nur bei der Ziel-App auftritt, ist Pinning oder ein eigener Trust Store
wahrscheinlicher als ein allgemein defektes Proxyman-Zertifikat.

### Manche Requests fehlen trotz funktionierendem HTTPS

Mögliche Ursachen:

- HTTP/3 beziehungsweise QUIC verwendet UDP/443 und umgeht den klassischen
  TCP-HTTP-Proxy;
- ein Teil der App läuft in WebView oder einem separaten Prozess;
- der Netzwerkstack respektiert den Android-Systemproxy nicht;
- die Domain steht in Proxymans Bypass-Liste;
- eine bereits offene Verbindung wurde vor Beginn der Aufnahme aufgebaut.

Für die eigene App in einem Debug-Build QUIC vorübergehend deaktivieren oder
HTTP/2 erzwingen. Alternativ die App vor der Aufnahme vollständig beenden und
neu starten. Netzwerkblockaden nur in einer kontrollierten Testumgebung
verwenden, da sie andere Apps und Systemdienste beeinflussen können.

### Requests sind sichtbar, der Body bleibt unverständlich

Prüfen, ob es sich um eines der folgenden Formate handelt:

- gzip, Brotli oder eine andere Content-Encoding-Kompression;
- Protocol Buffers, CBOR oder MessagePack;
- Datei-Upload beziehungsweise Multipart;
- anwendungsspezifisch verschlüsselte Payload;
- Streaming- oder WebSocket-Verkehr.

`Content-Type`, `Content-Encoding` und die ersten Bytes des Payloads geben meist
einen Hinweis. TLS-Entschlüsselung entschlüsselt keine zusätzliche
Anwendungsverschlüsselung.

### App funktioniert mit Proxy deutlich anders

Mögliche Erklärungen sind andere Feature-Flags, Retry-Verhalten durch höhere
Latenz, fehlgeschlagene Telemetrie oder eine aktive Proxyerkennung. Einen
Kontrolllauf ohne TLS-Entschlüsselung und einen zweiten Lauf ganz ohne Proxy
vergleichen.

### App stürzt bei der finalen Aktion ab

Zuerst trennen, ob der Serverrequest noch gesendet wurde:

1. Zeitpunkt des UI-Absturzes notieren.
2. Letzten Request und dessen Response in Proxyman prüfen.
3. Parallel Android-Exit-Info und Logcat ansehen.

```bash
adb shell dumpsys activity exit-info PAKETNAME
adb logcat -d -t 500
```

Ein sichtbarer erfolgreicher Serverrequest mit anschließendem Prozessabsturz
weist eher auf ein lokales App-/Runtime-Problem hin. Fehlt der Request komplett,
liegt der Fehler wahrscheinlich vor oder während seiner Erzeugung.

### Nach Proxyman hat der Emulator kein Internet mehr

Wahrscheinlich ist der Proxy noch gesetzt, obwohl Proxyman nicht mehr lauscht.

```bash
adb shell settings get global http_proxy
adb shell settings put global http_proxy :0
```

Beim automatischen Proxyman-Ablauf zusätzlich **Revert All Changes** verwenden.

### Proxyman wird langsam oder verbraucht viel RAM

- kein globales SSL-Muster `*` verwenden;
- Telemetrie- und CDN-Domains ausschließen;
- vor jedem Szenario eine neue leere Session beginnen;
- unmittelbar nach dem relevanten Ablauf pausieren;
- große Response-Bodies nicht unnötig aufzeichnen.

Siehe auch:
[Proxyman consumes too much RAM](https://docs.proxyman.com/troubleshooting/proxyman-consumes-too-much-ram-and-unresponsive)

## 12. Vergleich zweier Mitschnitte

Für dynamische Signaturen oder kurzlebige Tokens sind mindestens zwei kleine,
kontrollierte Aufzeichnungen nützlicher als eine sehr große:

1. identische Aktion mit identischer fachlicher Eingabe;
2. gleiche Aktion mit genau einem geänderten Feld;
3. optional gleicher Request nach App-Neustart oder erneuter Anmeldung.

Vergleichsmatrix:

| Feld | Lauf A | Lauf B | Interpretation |
|---|---|---|---|
| Methode/Pfad | | | stabil? |
| Query | | | signaturrelevant? |
| Body | | | deterministisch? |
| Timestamp/Nonce | | | pro Request neu? |
| Authorization | | | Sessionwechsel? |
| Signatur | | | gleiche Eingabe, anderer MAC? |
| Key-Abruf vorher | | | pro Session oder pro Request? |
| Status/Response | | | Retry oder Erfolg? |

Nur eine Variable pro Vergleich ändern. Sonst lässt sich nicht unterscheiden,
welches Feld eine abweichende Signatur oder Serverantwort ausgelöst hat.

## 13. Aufräumen

Nach der Untersuchung:

1. Session speichern und Aufzeichnung pausieren.
2. Bei Proxymans Emulator-Automatik **Revert All Changes** ausführen.
3. Manuell gesetzten Proxy löschen.
4. App-Testkonto bei Bedarf abmelden.
5. Temporäre Zertifikate entfernen, wenn der AVD anderweitig genutzt wird.
6. Sensitive Exporte aus Downloads in den vorgesehenen geschützten Ordner
   verschieben.
7. Prüfen, dass keine Sessiondateien in Git vorgemerkt sind.

```bash
adb shell settings put global http_proxy :0
git status --short
```

Ein dedizierter Analyse-AVD kann anschließend per Snapshot konserviert werden.
Ein AVD mit installierter Analyse-CA sollte nicht als normaler Alltags-Emulator
behandelt werden.

## Kompakte Checkliste für ein neues Projekt

### Einmalige Einrichtung

- [ ] separaten AVD anlegen;
- [ ] Versionen von App, Android, Emulator, ADB und Proxyman notieren;
- [ ] Proxyverbindung mit Android-Browser prüfen;
- [ ] Proxyman-CA installieren;
- [ ] bei Bedarf Debug-Trust oder autorisierten System-CA-Ablauf vorbereiten;
- [ ] private Capture-Dateien per `.gitignore` ausschließen.

### Pro Szenario

- [ ] aktive Sessions und mögliche Geräteabmeldung bedenken;
- [ ] Hosts in einer Entdeckungsrunde ermitteln;
- [ ] nur API- und Login-Domains für SSL Proxying freischalten;
- [ ] Session leeren und Aufnahme aktivieren;
- [ ] App vollständig neu starten;
- [ ] genau einen Login-/Aktionsablauf ausführen;
- [ ] sofort pausieren und eindeutig speichern;
- [ ] Ablaufnotiz und sichtbares Ergebnis ergänzen;
- [ ] vor dem Teilen alle Secrets und personenbezogenen Daten redigieren.

### Abschluss

- [ ] Proxy beziehungsweise Proxyman-Overrides zurücksetzen;
- [ ] Internetzugang des AVD prüfen;
- [ ] Originalsession geschützt ablegen;
- [ ] nur redigierte Erkenntnisse dokumentieren;
- [ ] Git-Status auf versehentliche Captures prüfen.

## Offizielle Proxyman-Referenzen

- [Android Device & Emulator](https://docs.proxyman.com/debug-devices/android-device)
- [Automatic Script for Android Emulator](https://docs.proxyman.com/debug-devices/android-device/automatic-script-for-android-emulator)
- [SSL Proxying](https://docs.proxyman.com/basic-features/ssl-proxying)
- [Allow List](https://docs.proxyman.com/advanced-features/whitelist)
- [Bypass Proxy List](https://docs.proxyman.com/basic-features/bypass-proxy-list)
- [Regex](https://docs.proxyman.com/basic-features/regex)
