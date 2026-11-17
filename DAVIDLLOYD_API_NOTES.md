# David-Lloyd-API: technische Notizen

Stand: 9. Oktober 2026

Dieses Dokument fasst die bei der Analyse der David-Lloyd-iOS-App beobachteten
API-Abläufe zusammen. Es ist eine Arbeitsgrundlage für eine spätere
Implementierung und keine offizielle API-Dokumentation.

## Sicherheitsregeln

- Access-, Refresh-, ID- und Firebase-App-Check-Tokens niemals in Git,
  Tickets, Chats oder Logs übernehmen.
- Ebenso zu schützen sind `sessionToken`, Authorization Codes, Cookies,
  Gerätekennungen, kodierte Kontakt-IDs und entschlüsselte HMAC-Schlüssel.
- Ein veröffentlichter Refresh-Token muss widerrufen beziehungsweise durch eine
  vollständig neue Sitzung ersetzt werden. Er kann langfristig neue
  Access-Tokens ausstellen.
- Die in diesem Dokument verwendeten IDs und Werte sind Platzhalter oder
  nicht geheime technische Beispielwerte.
- Die beschriebenen privaten Mobile-API-Endpunkte nur im Rahmen der
  Nutzungsbedingungen und mit einem eigenen, autorisierten Konto verwenden.

## Systeme und Basis-URLs

| Aufgabe | Basis-URL |
|---|---|
| Kurs- und Buchungs-API | `https://mobile-app-back.davidlloyd.co.uk` |
| OAuth/OIDC | `https://digitalmanager.davidlloyd.co.uk/oauth2/default` |

Die beobachtete mobile Anwendung verwendete einen `GrabNGo`-User-Agent und für
OAuth die Bibliothek `okta-oidc-ios`. Versionswerte sollten nicht als stabiler
Bestandteil des Protokolls betrachtet werden.

## OAuth/OpenID Connect

### Discovery

Die Discovery-Daten liegen unter:

```text
GET /oauth2/default/.well-known/openid-configuration
```

Relevante veröffentlichte Endpunkte:

| Zweck | Endpoint |
|---|---|
| Autorisierung | `/oauth2/default/v1/authorize` |
| Token | `/oauth2/default/v1/token` |
| UserInfo | `/oauth2/default/v1/userinfo` |
| Signaturschlüssel | `/oauth2/default/v1/keys` |
| Introspection | `/oauth2/default/v1/introspect` |
| Widerruf | `/oauth2/default/v1/revoke` |
| Logout | `/oauth2/default/v1/logout` |
| Device Authorization | `/oauth2/default/v1/device/authorize` |

Unterstützt werden unter anderem `authorization_code`, `refresh_token`, PKCE
mit `S256` und der Scope `offline_access`. Der beobachtete Mobile-Client ist ein
Public Client und benötigt beim Refresh kein Client-Secret.

Die in der Discovery genannten Algorithmen wie `HS256` für signierte
OpenID-Request-Objects sind nicht mit dem proprietären API-Header
`X-Signature` gleichzusetzen.

### Erstanmeldung mit Authorization Code und PKCE

Beobachteter Ablauf:

```text
Okta-Anmeldung
    -> kurzlebiger sessionToken

GET /oauth2/default/v1/authorize
    sessionToken=<one-time-session-token>
    response_type=code
    code_challenge_method=S256
    code_challenge=<base64url(SHA256(code_verifier))>
    scope=openid profile offline_access
    redirect_uri=uk.co.davidlloyd.mobile-app:/login
    client_id=<mobile-client-id>
    nonce=<random>
    state=<random>

302 uk.co.davidlloyd.mobile-app:/login?code=<authorization-code>&state=<state>

POST /oauth2/default/v1/token
    grant_type=authorization_code
    client_id=<mobile-client-id>
    redirect_uri=uk.co.davidlloyd.mobile-app:/login
    code=<authorization-code>
    code_verifier=<original-pkce-verifier>

    -> access_token, refresh_token, id_token
```

Der der OAuth-Autorisierung vorausgehende native Okta-Login wurde inzwischen
ebenfalls vollständig bestätigt:

```http
POST https://davidlloyd.okta.com/api/v1/authn
Accept: application/json
Content-Type: application/json
User-Agent: okta-auth-swift/2.4.6 iOS/<version> Device/<model>

{
  "username": "<member-login>",
  "password": "<password>",
  "options": {
    "multiOptionalFactorEnroll": true,
    "warnBeforePasswordExpired": true
  }
}
```

Bei erfolgreicher primärer Anmeldung antwortet Okta mit `status: SUCCESS`,
einem kurzlebigen `sessionToken` und eingebetteten Benutzerprofildaten. Der
`sessionToken` wird anschließend einmalig als Query-Parameter des
`/oauth2/default/v1/authorize`-Requests verwendet. Die native Okta-Org-Domain
und die Custom Domain `digitalmanager.davidlloyd.co.uk` gehören damit zum
gleichen Authentifizierungsablauf; sie sind nicht Teil des HMAC-Signers.

Benutzername, Passwort, `sessionToken` und eingebettete Profildaten dürfen
weder protokolliert noch in Captures oder Fehlermeldungen persistiert werden.

Der Austausch des Authorization Codes wurde nicht vollständig mit seinem
`code_verifier` aufgezeichnet, entspricht aber dem durch Discovery und
Authorize-Request bestätigten PKCE-Ablauf.

Der lokale Login-Assistent in `app.py` implementiert diesen Ablauf inzwischen
ohne Browser- oder Copy/Paste-Schritt: Nach der Primäranmeldung sendet er den
einmaligen `sessionToken` an `/v1/authorize`, folgt dem Redirect nicht und
liest den Authorization Code ausschließlich aus dessen `Location`-Header. Vor
dem Token-Tausch prüft er die registrierte Rückgabe-URI exakt sowie den PKCE-
State. Kennwort, `sessionToken`, Redirect-URL, Code und Tokens bleiben dabei
flüchtig und werden nicht protokolliert. MFA bleibt ein expliziter Abbruch; sie
wird nicht automatisiert.

### Access-Token

Bestätigte Eigenschaften:

- JWT, bei den Beobachtungen mit `RS256` signiert.
- Gültigkeit exakt 3.600 Sekunden.
- Wird als unveränderter Wert im Header `x-auth-token` gesendet; kein
  `Bearer `-Präfix.
- Enthält unter anderem `iat`, `exp`, `auth_time`, `contactId`, Rolle und
  Gruppen.
- `auth_time` bleibt bei einem Refresh unverändert, während `iat`, `exp` und
  `jti` neu ausgestellt werden.
- Der Scope enthielt `openid`, `profile` und `offline_access`.

Der JWT-Payload darf für nicht sicherheitskritische Hilfsinformationen wie
`exp` oder die Ableitung einer kodierten Kontakt-ID gelesen werden. Die
ungeprüfte Payload darf nicht als Autorisierungsentscheidung verwendet werden.

### Refresh-Token

Bestätigter Request:

```http
POST https://digitalmanager.davidlloyd.co.uk/oauth2/default/v1/token
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

refresh_token=<REFRESH_TOKEN>&
client_id=<MOBILE_CLIENT_ID>&
grant_type=refresh_token
```

Bestätigte Response-Felder:

```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "<ACCESS_TOKEN>",
  "scope": "offline_access openid profile",
  "refresh_token": "<CURRENT_OR_ROTATED_REFRESH_TOKEN>",
  "id_token": "<ID_TOKEN>"
}
```

Implementierungsregeln:

1. Access-Token etwa 60 Sekunden vor `exp` erneuern.
2. Bei einem unerwarteten HTTP 401 genau einmal refreshen und den ursprünglichen
   Request genau einmal wiederholen.
3. Sowohl neuen Access-Token als auch den möglicherweise rotierten
   Refresh-Token verschlüsselt persistieren.
4. Refresh-Tokens niemals loggen oder in Fehlermeldungen aufnehmen.
5. Parallele Refreshes vermeiden, falls später mehrere Worker unterstützt
   werden.

Dieser Ablauf ist im aktuellen David-Lloyd-Provider implementiert. Die Tokens
liegen verschlüsselt in `ProviderConnection.credentials_encrypted`.

## Geräte- und Sitzungsregistrierung

Nach einem Token-Refresh wurde folgender signierter Aufruf beobachtet:

```http
POST /register-device
X-Timestamp: <unix-seconds>
X-Signature: <dynamic-signature>
X-Device-Id: <DEVICE_ID>
x-auth-token: <ACCESS_TOKEN>
Content-Type: application/json

{"isNewLogin":false}
```

Response: HTTP 200 ohne Body.

Dieser Endpoint stellt keinen neuen Access-Token aus. Der frische Access-Token
war bereits im Request vorhanden. `isNewLogin: false` bestätigt eine bestehende
Sitzung.

### Kontrollierter signierter Ablauf aus derselben Sitzung

Ein zusammengehöriger erfolgreicher Ablauf bestätigte drei signierte Requests
mit demselben Access-Token, derselben Device-ID und demselben
Public-Key-Präfix. Sensible Werte und konkrete Referenzen sind hier bewusst
weggelassen:

```text
T + 0 Sekunden
POST /register-device
Body: {"isNewLogin":false}

T + 16 Sekunden
POST /clubs/{siteId}/classes/sessions/{courseInstanceId}/hold
Body: {"contactId":"<encoded>","courseId":<id>,"purchaseId":<id>}

T + 17 Sekunden
POST /members/me/purchases/{purchaseId}/prepare-for-payment?adyenDecomV2=true
Body: {"revenueStream":"CLASS","useDirectDebit":false,"locale":"en_GB"}
```

Alle drei Signaturen hatten das Format `v1 <public-key-prefix>:<base64-mac>`
mit einem 32 Byte langen Base64-dekodierten MAC. `hold` und
`prepare-for-payment` enthielten zusätzlich
`X-Safe-Cache-Control-Client: true`; `register-device` nicht. `hold` wurde
akzeptiert und lieferte eine aktive, kostenlose Reservierung; der unmittelbar
folgende Prepare-Aufruf wurde ebenfalls mit einer gültigen Signatur gesendet.

Dieser Ablauf ist ein geeigneter späterer Integrationstest für einen
autorisierten Signer. Er legt die Kanonisierung jedoch nicht offen, weil sich
Timestamp, Pfad und Body zwischen den Requests gleichzeitig ändern. Bekannte
Request/MAC-Paare erlauben bei HMAC weder die Rückgewinnung des Schlüssels noch
eine eindeutige Bestimmung der signierten Eingabe.

### Frischer Login auf einem bereits registrierten Gerät

Eine vollständige, redigierte Aufzeichnung eines erneuten Logins auf demselben
Gerät zeigte diese Reihenfolge:

```text
GET  /.well-known/openid-configuration
GET  /v1/authorize              (PKCE, sessionToken)
POST /v1/token                  (Authorization Code + code_verifier)
POST /login/enroll-phone        (signiert, noch ohne x-auth-token)
POST /register-device           (signiert, mit x-auth-token; T + 3 Sekunden)
GET  /members/me                (nicht signiert, mit x-auth-token)
GET  /clubs/{siteId}            (nicht signiert)
PUT  /handsets/{handsetId}      (signiert, mit x-auth-token; T + 4 Sekunden)
```

Die drei signierten Requests verwendeten dieselbe Device-ID, dasselbe
Public-Key-Präfix und jeweils einen 32 Byte langen MAC. Die Bodies enthielten
jeweils nur die für den Endpoint notwendigen Felder: Telefonnummer,
`isNewLogin` beziehungsweise Plattform und Push-Service-ID.

Wichtige Folgerungen:

- Eine neue OAuth-Sitzung auf einem bereits registrierten Gerät ist keine neue
  Geräte- oder HMAC-Key-Provisionierung; `/hmac/key` wurde in dieser Kette nicht
  beobachtet.
- Der Signer ist bereits für `/login/enroll-phone` verfügbar, obwohl dieser
  Request keinen `x-auth-token` enthält. Ein Access-Token ist daher nicht
  universell notwendiger Signer-Input.
- Das Public-Key-Präfix identifiziert wahrscheinlich das längerlebige
  RSA-Schlüsselpaar, nicht eindeutig einen einzelnen kurzlebigen HMAC-Key.
- Read-only-Endpunkte wie `/members/me` benötigen in derselben Sitzung keine
  dynamische Signatur.

`PUT /handsets/{handset-id}` mit `push-service-id` und `platform: ios` gehört
zur Push-Registrierung und ist für Kursbuchungen nicht erforderlich.

## HMAC-Key-Provisionierung und `X-Signature`

### Bestätigter Key-Request

```http
POST /hmac/key
X-Firebase-AppCheck: <FIREBASE_APP_CHECK_TOKEN>
X-Device-Id: <DEVICE_ID>
Content-Type: application/json

{"publicKey":"<BASE64_DER_RSA_PUBLIC_KEY>"}
```

Beobachtete Response-Struktur:

```json
{
  "key": "<RSA_ENCRYPTED_HMAC_KEY>",
  "expirationTimestamp": 1791540093
}
```

Bestätigte beziehungsweise stark gestützte Schlussfolgerungen:

- Der Client erzeugt ein RSA-Schlüsselpaar und übermittelt den Public Key.
- Der beobachtete Public Key war ein 2048-Bit-RSA-Key im Base64-kodierten
  DER-Format.
- Der Server liefert keinen direkt verwendbaren HMAC-Key, sondern einen mit
  diesem Public Key verschlüsselten Wert.
- Zum Entschlüsseln ist der zugehörige private RSA-Key erforderlich. Für die
  Android-App 152.1.0 ist inzwischen bestätigt, dass sie ihn unter dem Alias
  `ephemeral_hmac_rsakey` im `AndroidKeyStore` erzeugt. Der Key ist nicht
  exportierbar und wird nach dem Entschlüsseln des HMAC-Keys wieder gelöscht.
  `AndroidKeyStore` allein beweist jedoch keine Hardwarebindung; auf dem
  Emulator ist der Key zwangsläufig softwarebasiert. Auf einem physischen
  Android-Gerät wäre für einen Nachweis von TEE/StrongBox eine Key-Attestation
  erforderlich. „Secure Enclave“ ist die entsprechende Apple-Technik und aus
  der Android-App nicht ableitbar.
- Für HMAC-Keys wurden unterschiedliche Laufzeiten beobachtet: einmal exakt 75
  Minuten und bei einer späteren Rotation exakt 135 Minuten. Maßgeblich ist
  ausschließlich `expirationTimestamp`; eine feste Laufzeit darf nicht
  angenommen werden.
- Der Firebase-App-Check-Token war ungefähr eine Stunde gültig und wurde über
  eine Geräteattestierung ausgestellt.
- Android 152.1.0 verwendet
  `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. Der Base64-dekodierte
  256-Byte-Ciphertext wird mit dem temporären Android-Keystore-Key entschlüsselt
  und ergab im Laufzeit-Trace einen 44 Byte langen HMAC-Key. Der RSA-Cipher kam
  vom Provider `AndroidKeyStoreBCWorkaround`; HMAC-SHA256 wurde vom Provider
  `AndroidOpenSSL` ausgeführt. Die entschlüsselten 44 Bytes werden ohne weitere
  Dekodierung direkt an `SecretKeySpec("HmacSHA256")` übergeben.
- Nicht abschließend bestimmt ist nur der vom Android-Provider intern gewählte
  MGF1-Digest: Der Transformationsname legt SHA-256 für OAEP fest, unterscheidet
  aber providerabhängig nicht sicher zwischen MGF1-SHA-1 und MGF1-SHA-256. Das
  Python-Modul akzeptiert beim lokalen Entschlüsseln deshalb gezielt beide
  Varianten; die erste erfolgreiche Variante liefert den Key.

### Beobachtetes Signaturformat

```text
X-Timestamp: <unix-seconds>
X-Signature: v1 <PUBLIC_KEY_PREFIX>:<BASE64_MAC>
```

Der mittlere Teil entsprach dem Anfang des beim Key-Request übertragenen
Public Keys. Der Base64-dekodierte MAC ist 32 Byte lang. Die statische und
dynamische Android-Analyse bestätigt `HmacSHA256`.

Zwei POST-Requests mit demselben Timestamp, aber unterschiedlichen Pfaden und
Bodies hatten verschiedene Signaturen. Die Signatur bindet daher mindestens
weitere Requestbestandteile ein. Wahrscheinliche Eingaben sind:

- HTTP-Methode;
- Request-Pfad, eventuell inklusive Query-String;
- `X-Timestamp`;
- exakte Body-Bytes.

Für Android 152.1.0 sind Reihenfolge, Body-Behandlung, HMAC-Algorithmus und
RSA-Padding inzwischen bestimmt; siehe den folgenden Abschnitt. Noch unbekannt
sind vor allem das zulässige Zeitfenster, der genaue Replay-Schutz und ob andere
Client-Versionen dieselbe Kanonisierung verwenden.

### Bestätigter Android-Signer in App 152.1.0

Die statische Analyse des tatsächlich installierten APKs und ein
datensparsamer Laufzeit-Trace bestätigen folgenden Ablauf:

1. Der Interceptor `T8.b` serialisiert den Request-Body einmal zu exakten
   Bytes. Er berechnet darüber den kleingeschriebenen hexadezimalen MD5-Wert
   und setzt anschließend einen neuen Body aus denselben Bytes ein. Es findet
   also keine semantische JSON-Kanonisierung statt.
2. `ao.i.n` erzeugt die zu signierende Zeichenfolge. Die Methode wird mit
   `Locale.ROOT` großgeschrieben. Nicht vorhandene optionale Werte werden ganz
   ausgelassen, nicht als leere Zeile eingefügt.
3. `ao.i.E` bildet `HmacSHA256` über die UTF-8-Bytes dieser Zeichenfolge und
   kodiert den 32-Byte-MAC mit Android-Base64 ohne Zeilenumbrüche.

Für einen JSON-POST ist die kanonische Eingabe damit exakt:

```text
UPPERCASE_METHOD
PATH_OPTIONALLY_WITH_QUERY
CONTENT_TYPE
LOWERCASE_HEX_MD5_OF_EXACT_BODY_BYTES
DEVICE_ID
UNIX_TIMESTAMP_SECONDS
```

Host und Scheme werden nicht aufgenommen. Besteht eine Query, hängt der
Interceptor sie mit `?` an den Pfad an. Bei einem Request ohne Body fehlen
Content-Type und Body-MD5 als Listenelemente; es entstehen dafür keine zwei
zusätzlichen Leerzeilen.

Der Header wird in dieser Form aufgebaut:

```text
X-Signature: v1 <12-ZEICHEN-KEY-ID>:<BASE64_HMAC_SHA256>
X-Timestamp: <UNIX_SECONDS>
X-Device-Id: <DEVICE_ID>
```

Die zwölf Zeichen entsprechen in den Mitschnitten dem Präfix des
Base64-kodierten öffentlichen RSA-Keys.

Die HMAC-Key-Provisionierung läuft getrennt davon:

- `ao.i.D` erzeugt das temporäre RSA-Schlüsselpaar im `AndroidKeyStore` unter
  `ephemeral_hmac_rsakey`.
- `/hmac/key` erhält nur den öffentlichen Key und wird selbst nicht mit diesem
  neuen HMAC-Key signiert.
- `hb.n3` entschlüsselt das Response-Feld `key` mit
  `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
- Die entschlüsselten Bytes werden als HMAC-Key im laufenden App-Zustand
  gehalten; unmittelbar danach löscht `hb.n3` den RSA-Keystore-Eintrag.

Damit liegt kein dauerhaft aus dem APK extrahierbarer privater RSA-Key vor.
Ein Emulator kann die Signatur dennoch innerhalb der laufenden, autorisierten
App erzeugen; eine externe Python-Implementierung benötigt weiterhin den
jeweils aktuellen entschlüsselten HMAC-Key oder eine lokale Signierbrücke zur
App.

Ein Frida-Java-Bridge-Test auf dem verwendeten Android-17-Preview-AVD war nicht
stabil: Der instrumentierte Prozess endete nach neun Sekunden mit einem
SIGSEGV in `libart.so` während der Garbage Collection. Android klassifizierte
dies als nativen App-Crash; die anschließend automatisch neu gestartete,
nicht instrumentierte App funktionierte. Für weitere Untersuchungen sind daher
statische Analyse oder ein stabileres Android-API-Level vorzuziehen.

### Android-Buchungsmitschnitt

Ein redigierter Mitschnitt der Android-App 152.1.0 auf einem Emulator zeigte
39 Requests an die Buchungs-API. Signiert waren ausschließlich die drei
schreibenden Requests des beobachteten Buchungsablaufs:

```text
POST /purchases                                      -> 201
POST /clubs/{siteId}/classes/sessions/{sessionId}/hold -> 200
POST /members/me/purchases/{purchaseId}/prepare-for-payment -> 200
```

Alle drei enthielten `X-Signature` und `X-Timestamp`, verwendeten dasselbe
Public-Key-Präfix und einen 44 Zeichen langen Base64-MAC, entsprechend 32
dekodierten Bytes. Die zahlreichen GET-Requests vor und nach der Buchung
enthielten keine `X-Signature`.

In dieser Session wurde `/hmac/key` nicht aufgerufen. Der für die Signaturen
benötigte HMAC-Key war daher bereits provisioniert beziehungsweise lokal
gecacht. Der Mitschnitt bestätigt den signierten Android-Buchungsablauf, kann
aber allein weder die Ablage des privaten RSA-Keys noch dessen mögliche
Hardwarebindung nachweisen.

Ein späterer vollständiger Android-Mitschnitt vom ausgeloggten Zustand bis zur
Buchung erfasste zusätzlich Login und automatische Key-Rotation:

```text
POST /login/enroll-phone                    (signiert, ohne Auth-Token)
POST davidlloyd.okta.com/api/v1/authn
GET  /.well-known/openid-configuration
GET  /v1/authorize                          -> 302
POST /v1/token                              -> 200
POST /register-device                       (signiert, mit Auth-Token)
PUT  /handsets/{handsetId}                  (signiert, mit Auth-Token)
POST /.../hold                              (alter HMAC-Key) -> 403
POST /hmac/key                              (nicht signiert) -> 200
POST /.../hold                              (neuer HMAC-Key) -> 200
POST /.../prepare-for-payment               (signiert) -> 200
```

Der Android-Request an `/hmac/key` enthielt weder `X-Signature` noch
`X-Firebase-AppCheck` oder einen Auth-Token. Neben den üblichen Transport- und
Tracing-Headern wurden `X-Device-Id`, `X-Request-Id` und `X-Session-Id`
gesendet; der JSON-Body enthielt ausschließlich `publicKey`. Die Response
enthielt `key` und `expirationTimestamp`.

Der Public Key war erneut ein parsebarer RSA-2048-Key. Das verschlüsselte
`key`-Feld dekodierte zu 256 Byte. Das zwölf Zeichen lange Präfix in
`X-Signature` entsprach dem Anfang dieses Base64-Public-Keys.

Die beiden `hold`-Versuche hatten identische Methode, URI, Body-Bytes,
Auth-Token und Device-ID. Beim Retry waren Timestamp und MAC geändert, das
Public-Key-Präfix blieb gleich. Damit ist für Android bestätigt: Zeitlich vor
einer erneuten HMAC-Key-Antwort können signierte Requests auftreten, sie
verwenden dann den bereits lokal gespeicherten alten HMAC-Key. Der eigentliche
Key-Provisionierungsrequest ist nicht signiert.

### Beobachtete Verdrängung einer parallelen Geräte-Sitzung

Nach einer Anmeldung im Android-Emulator meldete die parallel verwendete
David-Lloyd-App auf dem physischen Telefon, dass das Konto auf einem anderen
Gerät angemeldet worden sei, und beendete dort die Sitzung. Dies spricht für
eine serverseitige Beschränkung auf ein aktives registriertes Gerät oder eine
aktive Geräte-Sitzung pro Konto.

Noch nicht bestimmt ist, welcher Schritt die bestehende Sitzung verdrängt.
Kandidaten sind `/login/enroll-phone`, der OAuth-Token-Austausch,
`/register-device` oder die anschließende Handset-Registrierung. Daher darf aus
der Beobachtung noch nicht geschlossen werden, dass bereits ein normaler
Token-Refresh auf demselben Gerät andere Sitzungen beendet.

Für eine Automatisierung bedeutet dies: Ein dauerhaft angemeldeter Emulator
würde wahrscheinlich mit der normalen Telefon-App konkurrieren. Robuster wäre
entweder ein einziges dediziertes Gerät für die Automatisierung oder eine
Automation des ohnehin aktiv verwendeten Geräts.

### Bestätigte HMAC-Key-Rotation während eines `hold`

Ein kontrollierter Mitschnitt erfasste die automatische Erneuerung eines
abgelaufenen HMAC-Keys:

```text
POST /purchases                         (signiert)
POST /.../hold                          (alter Key; abgelehnt)
POST /hmac/key                          (App Check + Public Key)
POST /.../hold                          (neuer Key; akzeptiert)
POST /.../prepare-for-payment?...       (neuer Key; akzeptiert)
```

Die beiden `hold`-Requests waren hinsichtlich HTTP-Methode, vollständigem Pfad,
Timestamp, Access-Token, Device-ID und exakten Body-Bytes identisch. Auch das
Public-Key-Präfix im `X-Signature`-Header blieb gleich. Ausschließlich der
Base64-MAC änderte sich nach der Key-Provisionierung. Daraus folgt:

- Das Präfix identifiziert das längerlebige RSA-Schlüsselpaar und nicht die
  Version des HMAC-Keys.
- Ein Retry nach Key-Erneuerung kann denselben noch frischen Timestamp und
  dieselben Body-Bytes erneut signieren.
- Die Anwendung muss den Response-Body unverändert für den Retry vorhalten;
  erneute unabhängige JSON-Serialisierung ist zu vermeiden.
- Der Client signiert auch `POST /purchases`, obwohl ein früherer Live-Test
  gezeigt hatte, dass der Server diesen Endpoint auch unsigniert akzeptierte.

Der direkt folgende `prepare-for-payment`-Request verwendete denselben
Timestamp, denselben Access-Token, dieselbe Device-ID und dasselbe
Public-Key-Präfix wie die beiden `hold`-Versuche. Sein kompakter JSON-Body
hatte die beobachtete Feldreihenfolge `locale`, `revenueStream`,
`useDirectDebit`. Die erfolgreiche Response bestätigte `needsPayment: false`,
einen Gesamtpreis von null Euro und eine Purchase-Gültigkeit von 15 Minuten.
Die endgültige Buchungsbestätigung muss weiterhin separat über die
Buchungsliste geprüft werden.

Der Public Key dieser Rotation war ein erfolgreich als RSA parsebarer
Base64-DER-Key mit 293 DER-Bytes und 2048 Bit. Das `key`-Feld der Response war
Base64-kodiert und dekodierte zu exakt 256 Byte, passend zu einem einzelnen
RSA-2048-Ciphertextblock. Die neue `expirationTimestamp` lag exakt 8.100
Sekunden beziehungsweise 135 Minuten nach dem Timestamp des fehlgeschlagenen
und wiederholten `hold`-Requests.

Der Mitschnitt bestimmt das RSA-Padding weiterhin nicht und enthält nur den
verschlüsselten, nicht den verwendbaren HMAC-Key.

### Warum keine statische Signatur funktioniert

Eine aufgezeichnete `X-Signature` kann nicht in einer Provider-Verbindung
gespeichert und wiederverwendet werden:

- jeder Request erhält einen neuen Timestamp;
- `purchaseId`, Kursinstanz und Body ändern sich;
- unterschiedliche Endpoints benötigen unterschiedliche Signaturen;
- der HMAC-Key läuft ab;
- serverseitiger Replay-Schutz ist wahrscheinlich.

Aus Request und MAC kann der geheime HMAC-Key aufgrund der Eigenschaften von
HMAC nicht zurückgerechnet werden. Auch viele weitere cURL-Beispiele lösen
dieses Problem nicht.

### Praktische Voraussetzung für einen Signer

Für eine zulässige vollständige Implementierung wird mindestens eines davon
benötigt:

- offizielle Dokumentation oder ein David-Lloyd-SDK;
- ein offizieller Server-to-Server-Zugang;
- autorisierter Client-Quellcode mit Kanonisierung, Key-Entschlüsselung und
  Signaturbildung;
- ein legitimer dynamischer Signierdienst, der Methode, Pfad und exakte
  Body-Bytes signiert.

AppCheck- oder Attestierungsprüfungen sollen nicht durch wiederverwendete
aufgezeichnete Tokens umgangen werden.

Empfohlene interne Schnittstelle:

```python
class DavidLloydRequestSigner:
    def sign(
        self,
        method: str,
        path: str,
        body: bytes,
    ) -> dict[str, str]:
        return {
            "X-Timestamp": "<unix-seconds>",
            "X-Signature": "v1 <key-id>:<base64-mac>",
        }
```

Die tatsächlich gesendeten Body-Bytes müssen exakt den signierten Bytes
entsprechen. Dafür sollte JSON einmal deterministisch serialisiert und sowohl
für Signatur als auch HTTP-Body wiederverwendet werden.

## Kurs- und Buchungs-API

### Verbindungstest und bestehende Buchungen

```http
GET /members/me/bookings?include-others-i-can-book-for=1
x-auth-token: <ACCESS_TOKEN>
X-Device-Id: <DEVICE_ID>
```

Wichtige Felder:

- `details.courseTemplateId`: stabile Kursvorlage;
- `details.courseInstanceId`: konkrete Instanz;
- `bookingReference`: Provider-Buchungsreferenz;
- `encodedBookingReference`: kodierte Referenz, unter anderem für
  stationsbezogene Abfragen;
- `status`: beobachtet wurden `confirmed` und `cancelled`;
- `bookedMemberEncodedContactId`: kodierte zu buchende Person;
- `siteId`, `date`, `startTime`.

Für Idempotenz gilt eine Buchung nur dann als vorhanden, wenn dieselbe
`courseInstanceId` den Status `confirmed` besitzt. Ein `cancelled`-Eintrag darf
eine erneute Buchung nicht verhindern.

### Kursvorlage und konkrete Termine

```http
GET /clubs/{siteId}/sessions/templates/{courseTemplateId}
```

Die Response enthält unter anderem:

- `templates`: Metadaten und Übersetzungen der Kursvorlage;
- `sessionsDetails`: konkrete Termine;
- `courseTemplateId`: stabile Kursreferenz;
- `courseInstanceId`: konkrete Instanzreferenz;
- `courseId`: zusätzliche, für `hold` erforderliche Instanz-ID;
- `date`, `startTime`, `duration`, `locations`, `status`.

Domänenabbildung:

```text
Course.provider_course_ref             <- courseTemplateId
CourseOccurrence.provider_occurrence_ref <- courseInstanceId
adapterinterne Buchungsdetails         <- courseId
BookingResult.provider_booking_ref     <- bookingReference
```

`courseFrequency: DAILY` darf nicht als Wiederholungsregel verwendet werden.
Termine derselben Vorlage können an unterschiedlichen Wochentagen und Uhrzeiten
stattfinden. WellbeingBot selektiert daher über Template-ID, Wochentag und
Startzeit.

Ein allgemeiner Endpoint zur vollständigen Kursentdeckung wurde nicht
aufgezeichnet. Der aktuelle MVP verwendet deshalb pro Provider-Verbindung
konfigurierte, kommaseparierte Kursvorlagen-IDs.

### Belegung

```http
GET /clubs/{siteId}/sessions/occupancy
```

Zuordnung über `courseInstanceId`. Relevante Felder:

- `currentOccupancy`;
- `maxOccupancy`;
- `hasEverReachedMaxOccupancy`.

Eine Instanz wird im Adapter als verfügbar betrachtet, wenn ihr Status `active`
ist und `currentOccupancy < maxOccupancy`. Der nachfolgende `hold` bleibt die
maßgebliche serverseitige Prüfung.

### Vollständiger Buchungsablauf

#### 1. Purchase anlegen

```http
POST /purchases
Content-Type: application/json

{"siteId":<SITE_ID>}
```

Response:

```json
{"purchaseId": 123456789}
```

Ein Live-Test bestätigte, dass dieser Endpoint einen unsignierten Request
akzeptierte. Eine Purchase ist ungefähr 15 Minuten gültig und enthält allein
noch keine Kursreservierung.

#### 2. Kurs halten

```http
POST /clubs/{siteId}/classes/sessions/{courseInstanceId}/hold
X-Timestamp: <unix-seconds>
X-Signature: <dynamic-signature>
Content-Type: application/json

{
  "contactId": "<ENCODED_CONTACT_ID>",
  "courseId": 123456789,
  "purchaseId": 987654321
}
```

Eine erfolgreiche Response enthält unter anderem:

- `classBookingId`;
- `bookingData.bookingReference`;
- `bookingData.status: active`;
- `bookingData.stockItemId`;
- `bookingData.priceInPennies`;
- `classPrice`.

`active` ist eine vorläufige Reservierung und noch nicht die abschließend
bestätigte Buchung.

Live-Tests ohne `X-Signature` wurden sowohl mit einem weiter entfernten als
auch mit einem innerhalb des Buchungsfensters liegenden Kurs durchgeführt.
Beide wurden bei `hold` mit HTTP 401 oder 403 abgelehnt. Die anschließende
Buchungsliste enthielt keine neue bestätigte Buchung. Damit ist ausgeschlossen,
dass nur das Buchungsfenster die Ursache war; `hold` verlangt praktisch eine
gültige dynamische Signatur.

#### 3. Kostenlosen Kauf vorbereiten/abschließen

```http
POST /members/me/purchases/{purchaseId}/prepare-for-payment?adyenDecomV2=true
X-Timestamp: <unix-seconds>
X-Signature: <dynamic-signature>
Content-Type: application/json

{
  "revenueStream": "CLASS",
  "useDirectDebit": false,
  "locale": "de_DE"
}
```

Bei einem kostenlosen Kurs wurde beobachtet:

```json
{
  "needsPayment": false,
  "purchaseExpirationInMinutes": 15,
  "totalPriceInPennies": 0,
  "currencyCode": "EUR"
}
```

Wenn `needsPayment` wahr ist, soll der Bot abbrechen. Zahlungen werden nicht
automatisiert.

#### 4. Erfolg verifizieren

Nach Prepare erneut `/members/me/bookings` laden. Erfolg liegt nur vor, wenn
die erwartete `courseInstanceId` den Status `confirmed` besitzt. Die endgültige
`bookingReference` kann gegenüber der vorläufigen Hold-Referenz einen
zusätzlichen Suffix enthalten.

### Weitere beobachtete Endpoints

| Endpoint | Bedeutung |
|---|---|
| `GET /class-types` | Kategorien, nicht konkrete Termine |
| `GET /clubs/{siteId}/members/me/sessions/all-stars-timetable?sportId=...` | All-Stars-spezifischer Stundenplan; im Mitschnitt leer |
| `GET /clubs/{siteId}/classes/sessions/{instanceId}/station-details` | Stationsinformationen |
| `GET /members/me/classes/bookings/by-ref/station-booking?...` | Stationsbuchung zu einer Buchungsreferenz |
| `GET /members/me/class-templates-booked-before` | zuvor gebuchte Vorlagen; kein vollständiger Katalog |
| `GET /clubs/{siteId}/members/me/class-settings` | unter anderem Rabatte |
| `GET /clubs/titles` | Clubtitel/-metadaten |

## Aktueller WellbeingBot-Stand

Implementiert in `wellbeingbot/providers/davidlloyd.py`:

- Dashboard-Konfiguration für Access-Token, Refresh-Token, Device-ID, Club-ID,
  optionale kodierte Mitglieds-ID und Kursvorlagen-IDs;
- verschlüsselte Credential-Speicherung;
- automatischer OAuth-Refresh vor Ablauf;
- einmaliger Refresh/Retry nach HTTP 401;
- verschlüsselte Persistenz neuer und rotierter Tokens;
- Verbindungstest und Buchungsliste;
- Kursauflösung über bekannte Template-IDs;
- Belegungsprüfung;
- Idempotenzprüfung auf bestätigte Buchungen;
- Purchase/Hold/Prepare/Verify-Ablauf;
- Ablehnung kostenpflichtiger Buchungen.

Noch nicht implementiert:

- dynamische `X-Signature`;
- Firebase-App-Check-/Attestierungsablauf;
- Entschlüsselung des HMAC-Keys;
- vollständige Kursentdeckung ohne konfigurierte Template-IDs;
- Stornierung;
- vollständige Fehlerabbildung für `full`, `not_open` und providerspezifische
  Hold-/Prepare-Fehler.

Bis ein zulässiger Signer verfügbar ist, sollten echte Buchungen ohne Signer
kontrolliert blockiert werden, statt unsignierte Holds zu versuchen.

## Empfohlene nächste Schritte

1. Eine `DavidLloydRequestSigner`-Schnittstelle ergänzen.
2. JSON deterministisch in kompakte UTF-8-Bytes serialisieren und exakt diese
   Bytes signieren und senden.
3. Ohne Signer vor `POST /purchases` beziehungsweise spätestens vor `hold`
   mit einer verständlichen Providerfehlermeldung abbrechen.
4. Offizielle Dokumentation oder einen autorisierten Signierweg klären.
5. Erst danach kontrollierte Live-Tests mit einem kostenfreien, stornierten
   Testtermin durchführen.
6. HTTP 401 und 403 getrennt behandeln: 401 kann einen Token-Refresh auslösen;
   403 bei `hold` darf nicht irreführend als abgelaufene Anmeldung gemeldet
   werden.
7. Vor jedem Retry die Buchungsliste prüfen. Nach einem Timeout kann der
   serverseitige Vorgang bereits erfolgreich gewesen sein.

## Kurzreferenz des Provider-Ablaufs

```text
Provider-Verbindung laden
    -> Credentials entschlüsseln
    -> Access-Token prüfen/refreshen
    -> GET Template + Occupancy
    -> Instanz über Datum und Uhrzeit auflösen
    -> GET Bookings: bereits confirmed?
    -> dynamischen Signer anfordern
    -> POST Purchase
    -> POST Hold (signiert)
    -> POST Prepare (signiert)
    -> GET Bookings: confirmed?
    -> BookingResult speichern
```
