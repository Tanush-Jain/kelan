# Kelan Deployment & Infrastructure Configurations

This directory contains container orchestration, monitoring, and infrastructure deployment manifests for Kelan.

## Configuration Overview

### Container Orchestration
* **`docker-compose.yml`**: Base Docker Compose stack defining core service dependencies.
* **`docker-compose.dev.yml`**: Local development overrides (debugging ports, source mounts).
* **`docker-compose.prod.yml`**: Production deployment specification including database persistence and isolated network bridges.
* **`docker-compose.monitoring.yml`**: Standalone monitoring stack (Prometheus, Grafana, Alertmanager).
* **`deploy.sh`**: Automated zero-downtime deployment script.

### Telemetry & Monitoring
* **`monitoring-prometheus.yml` / `observability-prometheus.yml`**: Prometheus scrape configuration for Kelan metrics endpoints (`/metrics`, `/api/stats`).
* **`monitoring-alerts-kelan.yml`**: Alerting rules for abnormal drop rates, high verdict latencies, and circuit breaker activations.
* **`monitoring-alertmanager.yml`**: Alert routing, grouping, and notification dispatch rules.
* **`monitoring-grafana-provisioning-*.yml`**: Automated datasource and dashboard provisioning for Grafana.

### Cloud & CI/CD
* **`deploy-kelan-init.yaml`**: Cloud-init / Kubernetes deployment specification for automated instance bootstrap.
* **`oracle-cloud/`**: Oracle Cloud Infrastructure (OCI) resource templates and guides.
* **`github-action-ci.yml` / `github-action-secret-guard.yml`**: GitHub Actions workflows for continuous integration and secret scanning.

## Usage

```bash
# Start production stack with monitoring
docker compose -f deploy/docker-compose.prod.yml -f deploy/docker-compose.monitoring.yml up -d

# Start development stack
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml up -d
```

