# Rocketguard – Der Rocket.Chat Alert Dedupe Proxy

**Rocketguard** ist ein hochperformanter, minimalistischer Proxy, der doppelte Alerts aus mehreren Alertmanager-Instanzen unterdrückt, bevor sie in **Rocket.Chat** landen. Er wurde speziell für Multi‑Cluster- oder Multi‑RZ‑Umgebungen entwickelt, in denen identische Alerts mehrfach ausgelöst werden können.

Rocketguard sorgt dafür, dass in Rocket.Chat **nur ein Alert** erscheint – egal aus welchem Cluster der ursprüngliche Alert stammt.

---

## 🚀 Features

* **Alert-Deduplizierung per Fingerprint**
* **TTL-basierte Suppression** (memory oder Redis)
* **Rocket.Chat Incoming Webhook Support**
* **Prometheus/Alertmanager kompatibel**
* **Prometheus Metrics Endpoint** (`/metrics`)
* **Einfaches Deployment in Kubernetes**
* **Ultra leichtgewichtig** (Go Binary < 15 MB)
* **Kein zentraler Alertmanager notwendig**

---

## 🧠 Architektur

```
Alertmanager RZ1 ───►
                  Rocketguard ───► Rocket.Chat
Alertmanager RZ2 ───►
```

Rocketguard:

1. Empfängt Alerts von beliebig vielen Alertmanager-Instanzen
2. Erzeugt pro Alert ein Fingerprint
3. Checkt im Cache (TTL-basiert), ob dieser Alert bereits verarbeitet wurde
4. Leitet nur neue Alerts an Rocket.Chat weiter

---

## 🔧 Konfiguration

Rocketguard wird vollständig über Umgebungsvariablen konfiguriert.

### Environment Variablen

| Name                 | Default      | Beschreibung                     |
| -------------------- | ------------ | -------------------------------- |
| `ROCKET_WEBHOOK_URL` | **required** | Rocket.Chat Incoming Webhook URL |
| `DEDUP_TTL_SECONDS`  | `300`        | TTL für identische Alerts        |
| `REDIS_URL`          | empty        | Redis URL (optional)             |
| `LOG_LEVEL`          | `info`       | debug / info / warn / error      |

---

## 📦 Installation

### Docker

```bash
docker run -p 8080:8080 \
  -e ROCKET_WEBHOOK_URL="https://rocket.chat/hooks/123" \
  ghcr.io/your-org/rocketguard:latest
```

### Kubernetes

```bash
kubectl apply -f deploy/k8s/
```

### Alertmanager Receiver

```yaml
receivers:
  - name: rocketguard
    webhook_configs:
      - url: http://rocketguard.monitoring.svc.cluster.local:8080/alert
```

---

## 🧬 Fingerprinting

Rocketguard erzeugt ein Fingerprint aus:

* `alertname`
* `instance`
* `job`
* `severity`
* *optional*: Labels nach Wunsch

Dieses Fingerprint steuert die Deduplizierung.

### Beispiel

```
ERROR: service_down{job="api",instance="pod-1"}
```

→ Fingerprint: `hash("service_down|api|pod-1|critical")`

---

## 📊 Metrics

Rocketguard stellt einen Prometheus-Metrics Endpoint bereit.

Verfügbare Metriken:

* `rocketguard_dedup_hits_total`
* `rocketguard_dedup_misses_total`
* `rocketguard_alerts_forwarded_total`
* `rocketguard_cache_backend`

Abrufbar unter:

```
/metrics
```

---

## 📁 Projektstruktur

```
rocketguard/
├─ cmd/rocketguard/main.go
├─ deploy/k8s/
├─ Dockerfile
└─ README.md
```

---

## 🛡️ Sicherheit

* läuft als non-root
* minimaler Attack Surface
* optional: NetworkPolicies
* optional: Redis-Auth

---

## 🧪 Testing

### Beispiel Request

```bash
curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -d @examples/alert.json
```

---

## 🧭 Roadmap

* [ ] Rate Limiting für massiven Alert-Output
* [ ] Multi-Receiver Support (Slack, Teams)
* [ ] UI für Dedupe-Cache
* [ ] Persistent Cache für Wartungsfenster

---

## 📜 Lizenz

MIT

---

## ❤️ Support

Fragen? Ideen? Bock auf ein Feature?
Einfach melden – oder ein PR öffnen!
