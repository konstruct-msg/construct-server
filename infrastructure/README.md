# Infrastructure Directory

⚠️ **DEPRECATED** - This directory contains OLD architecture configurations.

---

## 🚀 Current Deployment

**All current deployment configs are in [`/ops/`](../ops/) directory.**

- **Production VPS:** `ops/docker-compose.prod.yml` + `ops/envoy.prod.yaml`
- **Staging (Fly.io):** `ops/fly.toml` + `ops/envoy.fly.yaml`
- **Local dev:** `ops/docker-compose.dev.yml` + `ops/envoy.yaml`
- **Documentation:** `ops/DEPLOYMENT_GUIDE.md`

---

## 🏗️ Architecture Change

### Old Architecture (DEPRECATED)
```
Client → Nginx Gateway (80/443) → REST API → Services (8001-8005)
```
- **Gateway:** Nginx reverse proxy
- **Protocol:** HTTP/REST
- **Ports:** 7 public ports (80, 443, 8001-8005)
- **Configuration:** Nginx conf files

### New Architecture (CURRENT)
```
Client → Envoy Proxy (443) → gRPC → Services (50051-50057)
```
- **Gateway:** Envoy Proxy
- **Protocol:** gRPC (with gRPC-Web support for browsers)
- **Ports:** 1 public port (443 with path-based routing: `/auth.*` → auth-service, etc.)
- **Configuration:** Envoy YAML files

**Why the change?**
- ✅ Single TLS certificate (not 7)
- ✅ Firewall-friendly (1 port instead of 7)
- ✅ Native gRPC support (better performance)
- ✅ gRPC-Web for browser clients
- ✅ Centralized observability (Envoy metrics)

---

## 📂 What Moved

| Old Location | New Location | Status |
|--------------|--------------|--------|
| `infrastructure/terraform` | `ops/terraform` | ✅ Moved |
| `infrastructure/ansible` | `ops/ansible` | ✅ Moved |
| `infrastructure/security` | `ops/security` | ✅ Moved |
| `infrastructure/docker-compose.prod.yml` | `ops/docker-compose.prod.yml` | ✅ Replaced |
| `infrastructure/nginx/*` | `ops/envoy.*.yaml` | ✅ Replaced |
| `infrastructure/deploy.sh` | `ops/DEPLOYMENT_GUIDE.md` | ✅ Replaced |

---

## 🗄️ Archive

Old deployment configs (Nginx, REST API, old docker-compose) are in **`DEPRECATED/`** subdirectory.

**⚠️ DO NOT USE THESE IN PRODUCTION** - They reference the old REST architecture.

Contents:
- `DEPRECATED/Caddyfile` - Old Caddy reverse proxy config
- `DEPRECATED/nginx/` - Old Nginx configs
- `DEPRECATED/docker-compose.*.yml` - Old service definitions (ports 8001-8005)
- `DEPRECATED/deploy.sh` - Old deployment script

These are kept for historical reference only.

---

## 📋 Migration Checklist

If you need to migrate from old infrastructure:

1. **Update firewall rules:**
   ```bash
   # Close old ports
   ufw delete allow 8001:8005/tcp
   
   # Open new ports
   ufw allow 443/tcp
   ufw allow 9901/tcp  # Envoy admin (optional, localhost only)
   ```

2. **Update DNS:**
   - All clients point to single domain (e.g., `api.construct.app`)
   - No need for separate subdomains per service

3. **Update service definitions:**
   - Change from REST ports (8001-8005) to gRPC ports (50051-50057)
   - See `ops/docker-compose.prod.yml` for new structure

4. **Update monitoring:**
   - Envoy exposes metrics on `:9901/stats`
   - Old Nginx access logs → Envoy access logs

5. **Update TLS certificates:**
   - Single cert for main domain
   - Mount at `/etc/letsencrypt/live/yourdomain.com/` for Envoy

---

## 🔗 Quick Links

- **Current deployment guide:** [`ops/DEPLOYMENT_GUIDE.md`](../ops/DEPLOYMENT_GUIDE.md)
- **Envoy setup:** [`ops/ENVOY_SETUP.md`](../ops/ENVOY_SETUP.md)
- **Fly.io deployment:** [`ops/FLY_IO_DEPLOYMENT.md`](../ops/FLY_IO_DEPLOYMENT.md)
- **Migration plan:** [`infrastructure/MIGRATION_PLAN.md`](./MIGRATION_PLAN.md)

---

## ❓ Questions?

See detailed migration plan: `infrastructure/MIGRATION_PLAN.md`

**Last updated:** February 2026 (Architecture pivot to Envoy Proxy + gRPC)
