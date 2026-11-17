# David-Lloyd Login-Assistent

Lokaler, einfacher PKCE-Login-Assistent auf Basis der Erkenntnisse aus
`DAVIDLLOYD_API_NOTES.md`. Das Werkzeug ist für die spätere Integration in
WellbeingBot 2.0 gedacht und führt keine Buchungen aus.

## Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Danach `http://127.0.0.1:8080` öffnen.

## Sicherheitsmodell

- Benutzername und Passwort werden vom lokalen Python-Prozess direkt an den
  offiziellen Okta-Endpunkt von David Lloyd übertragen, nicht gespeichert und
  nicht protokolliert.
- PKCE-Verifier, State und Nonce liegen nur für die Dauer des automatischen
  Login-Requests im Arbeitsspeicher.
- Authorization Codes, Requests und Tokens werden nicht geloggt.
- Tokens werden genau einmal im Browser angezeigt und nicht auf Platte gespeichert.
- Der JWT-Payload wird nur für unvalidierte Komfortangaben gelesen.

Der Assistent führt zuerst die in den technischen Notizen beschriebene Okta-
Primäranmeldung durch und verwendet den einmaligen `sessionToken` anschließend
für den PKCE-Authorize-Request. Er liest den Authorization Code ausschließlich
aus dem serverseitigen Redirect zur registrierten Custom-URL
`uk.co.davidlloyd.mobile-app:/login` und tauscht ihn sofort mit dem
ursprünglichen PKCE-Verifier. Es sind weder ein Browser noch manuelles Kopieren
einer Rückgabe-URL nötig. Konten, für die Okta eine zusätzliche
MFA-Bestätigung verlangt, werden aktuell nicht automatisiert unterstützt.

Private Endpunkte nur mit einem eigenen autorisierten Konto und im Rahmen der
Nutzungsbedingungen verwenden. Eine dynamische `X-Signature`, Firebase App Check
und Kursbuchungen sind bewusst nicht Teil dieses Assistenten.

## Lokaler Request-Signer

[`davidlloyd_signing.py`](davidlloyd_signing.py) stellt die wiederverwendbare
Signer-Schnittstelle und die lokal getestete Android-v1-Implementierung für
WellbeingBot 2.0 bereit. Sie kann ein temporäres RSA-2048-Schlüsselpaar für
`/hmac/key` erzeugen, die Antwort lokal entschlüsseln und exakt dieselben
Body-Bytes per HMAC-SHA256 signieren, die anschließend übertragen werden.
Login, HTTP-Transport, Key-Erneuerung und Buchungsablauf bleiben bewusst
außerhalb des Moduls. Die Integration ist in
[`WELLBEINGBOT_SIGNER_INTEGRATION.md`](WELLBEINGBOT_SIGNER_INTEGRATION.md)
beschrieben.
