# Integration des David-Lloyd-Signers

`davidlloyd_signing.py` enthält die lokal getestete Android-v1-Signatur für
WellbeingBot 2.0. Das Modul führt selbst weder Login noch HTTP-Aufrufe oder
Buchungen aus. Es erzeugt ein temporäres RSA-2048-Schlüsselpaar, entschlüsselt
eine autorisierte `/hmac/key`-Antwort und signiert anschließend die exakten
Request-Bytes.

## Provider-Integration

Der Provider erhält den Signer per Dependency Injection:

```python
from davidlloyd_signing import DavidLloydRequestSigner

class DavidLloydProvider:
    def __init__(self, credentials, settings=None, signer: DavidLloydRequestSigner | None = None):
        # bestehende Initialisierung
        self.signer = signer
```

Vor `POST /purchases` muss der Buchungsablauf blockieren, solange kein Signer
vorhanden ist. Dadurch entsteht keine verwaiste Purchase:

```python
if self.signer is None:
    raise ProviderError(
        "David-Lloyd-Buchungen sind blockiert: autorisierter dynamischer Signer fehlt"
    )
```

Für `hold` und `prepare-for-payment` wird `json=payload` bewusst **nicht**
verwendet. Stattdessen werden dieselben Body-Bytes signiert und gesendet:

```python
prepared = prepare_signed_json_request(
    self.signer,
    "POST",
    path,
    payload,
    self._headers(),
)
response = requests.post(
    f"{self.base_url}{prepared.path}",
    data=prepared.body,
    headers=dict(prepared.headers),
    timeout=self.timeout,
)
```

Ein Retry nach HTTP 401 muss einen **neuen** Timestamp und eine neue Signatur
erzeugen. HTTP 403 bei `hold` darf keinen Token-Refresh auslösen. Nach einem
Timeout wird zuerst die Buchungsliste geprüft, bevor irgendein POST wiederholt
wird.

## Lokale Signer-Implementierung

Provisionierung und Transport bleiben bewusst beim aufrufenden Provider:

```python
from davidlloyd_signing import HmacProvisioningKey, DavidLloydHmacSigner

provisioning_key = HmacProvisioningKey.generate()

# Der Provider sendet ausschließlich dieses Payload an POST /hmac/key.
payload = provisioning_key.request_payload()

# Nach dem HTTP-Aufruf, ohne Response oder Schlüssel zu protokollieren:
material = provisioning_key.consume_response(
    response_json,
    device_id=device_id,
)
signer = DavidLloydHmacSigner(material)
```

`prepare_signed_json_request()` serialisiert den Body genau einmal und ergänzt
`X-Timestamp`, `X-Signature` und `X-Device-Id`. Kurz vor Ablauf des HMAC-Keys
verweigert der Signer weitere Signaturen; der Provider muss dann neu
provisionieren und den ursprünglichen Request mit frischer Signatur wiederholen.

Der entschlüsselte HMAC-Key, private RSA-Key, App-Check-Token und vollständige
Signaturen dürfen weder protokolliert noch in Capture-Dateien gespeichert
werden. `safe_traffic_summary()` erzeugt ausschließlich Hashes und Längen für
eine sichere Vergleichstabelle.
