# Rocketguard – Alert Dedupe Proxy for Alertmanager → Rocket.Chat

Rocketguard ist ein hochperformanter, minimaler Alert-Dedupe-Proxy für
Multi-Cluster-Umgebungen, in denen mehrere Alertmanager dieselben Alerts senden.
Der Proxy verhindert Doppelmeldungen durch Fingerprinting & TTL-Cache
(in-memory oder Redis).

Ideal für Umgebungen ohne zentralen Alertmanager, z. B.:

- mehrere Rechenzentren (RZ1, RZ2)
- identische Prometheus/Alertmanager-Deployments
- Federation zwischen Clustern
- deduplizierte Chat-Anbindung (Rocket.Chat, Slack, Teams, Mattermost)

---

## ✨ Features

- 🔥 Deduplizierung identischer Alerts anhand Fingerprint
- 🧠 dynamische TTL (pro severity/alertname möglich)
- 🚀 extrem leichtgewichtig (Go, <15 MB Docker Image)
- 📡 Rocket.Chat kompatibel (andere Webhooks auch)
- 🎯 Redis oder in-memory Cache
- 🛡️ optional NetworkPolicy, RBAC, Helm-Chart
- 🔍 Metriken via `/metrics` (Prometheus)

---

## 📐 Architektur

Alertmanager RZ1 ───► Rocketguard ──► Rocket.Chat
Alertmanager RZ2 ───►


Rocketguard kontrolliert:

- ob ein Alert bereits kürzlich empfangen wurde
- und unterdrückt ihn falls identisch

Kein LoadBalancer oder Mesh erforderlich.

---

## 🚀 Getting Started

### 1. Docker

```bash
docker run -p 8080:8080 \
  -e ROCKET_WEBHOOK_URL="https://chat.company/hooks/123" \
  ghcr.io/your-org/rocketguard:latest
```
### 2. Kubernetes (minimal)

kubectl apply -f deploy/k8s/

### 3. Alertmanager Receiver

receivers:
  - name: rocketchat
    webhook_configs:
      - url: http://rocketguard.monitoring.svc.cluster.local:8080/alert

⚙️ Environment Variables

| Variable             | Default      | Description                                      |
| -------------------- | ------------ | ------------------------------------------------ |
| `ROCKET_WEBHOOK_URL` | **required** | Rocket.Chat Incoming Webhook                     |
| `DEDUP_TTL_SECONDS`  | `300`        | global TTL für Dedupe Cache                      |
| `REDIS_URL`          | empty        | optional Redis (`redis://user:pass@host:6379/0`) |
| `LOG_LEVEL`          | `info`       | debug / info / warn / error                      |

📊 Metrics (Prometheus)

Rocketguard exposes:

rocketguard_dedup_hits_total

rocketguard_dedup_misses_total

rocketguard_cache_type

rocketguard_alerts_forwarded_total

Endpoint: /metrics

🔒 Security

Runs as non-root

Optional NetworkPolicy

Limited RBAC

No persistent data (unless Redis used)

🧪 Test

curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -d @examples/rocket-webhook.json

📜 License

MIT

---

# 🏷️ **Kubernetes Deployment Labeling (Best Practices)**

Ich verwende die **recommended labels** (Kubernetes SIG Apps):

```yaml
metadata:
  name: rocketguard
  labels:
    app.kubernetes.io/name: rocketguard
    app.kubernetes.io/instance: rocketguard
    app.kubernetes.io/version: "1.0.0"
    app.kubernetes.io/component: dedupe-proxy
    app.kubernetes.io/part-of: monitoring
    app.kubernetes.io/managed-by: fluxcd
    app.kubernetes.io/created-by: rocketguard
```
Und zusätzlich (Monitoring-/SRE-tauglich):
```
    observability.role: alert-dedupe
    security-context: restricted
    cluster-layer: application
```
Diese Label sind suchbar, sortierbar, eindeutig und industrieweit akzeptiert.
