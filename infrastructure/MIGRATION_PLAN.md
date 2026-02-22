# Infrastructure Migration Plan

## 🚨 Critical Change: Old → New Architecture

### Old Architecture (DEPRECATED)
```
Client → Nginx Gateway (80/443) → REST API → Services (8001-8005)
```
- **Gateway:** Nginx reverse proxy
- **Protocol:** REST/HTTP
- **Ports:** 7 ports (80, 443, 8001-8005)
- **TLS:** Nginx terminates
- **Files:** All in `infrastructure/` directory

### New Architecture (CURRENT)
```
Client → Envoy Proxy (443) → gRPC → Services (50051-50057)
```
- **Gateway:** Envoy Proxy
- **Protocol:** gRPC (with gRPC-Web for browsers)
- **Ports:** 1 port (443 with path-based routing)
- **TLS:** Envoy terminates (or Fly.io)
- **Files:** All in `ops/` directory

---

## 📂 Directory Structure Decision

### ❌ What's Obsolete (infrastructure/)

**Completely outdated:**
- `nginx/` - Replaced by Envoy
- `Caddyfile` - Replaced by Envoy
- `docker-compose.gateway.yml` - No REST gateway anymore
- `docker-compose.app.yml` - Old service ports (8001-8005)
- `docker-compose.message.yml` - Old REST messaging
- `docker-compose.prod.yml` - Old architecture
- `deploy.sh` - Hardcoded for old setup

**Potentially useful but needs updates:**
- `ansible/` - Playbooks might work with new docker-compose
- `terraform/` - VPS provisioning still valid
- `security/` - Firewall rules need updates (443 only now)
- `.env.prod.example` - Needs gRPC port variables

---

## ✅ Reorganization Strategy

### Option 1: Merge into ops/ (Recommended)
**Pros:** Single source of truth, no confusion  
**Cons:** Need to move terraform/ansible

```
ops/
├── envoy.yaml (local dev)
├── envoy.fly.yaml (staging)
├── envoy.prod.yaml (production)
├── docker-compose.prod.yml (VPS)
├── fly.toml (Fly.io staging)
├── DEPLOYMENT_GUIDE.md
├── terraform/ (moved from infrastructure/)
├── ansible/ (moved from infrastructure/)
└── monitoring/ (future)
```

### Option 2: Keep separate, document clearly
**Pros:** Historical reference  
**Cons:** Risk of using outdated configs

```
ops/ - Current deployment (Envoy + gRPC)
infrastructure/ - Archived (for reference only)
infrastructure/README.md - "DEPRECATED - See ops/"
```

---

## 🔄 Migration Actions

### Immediate (P0)
1. **Archive old configs:**
   ```bash
   mkdir infrastructure/DEPRECATED
   mv infrastructure/{nginx,Caddyfile,docker-compose.*.yml,deploy.sh} infrastructure/DEPRECATED/
   ```

2. **Update infrastructure/README.md:**
   - Add deprecation notice
   - Link to ops/ directory
   - Explain architecture change

3. **Move reusable components:**
   ```bash
   mv infrastructure/terraform ops/
   mv infrastructure/ansible ops/
   mv infrastructure/security ops/
   ```

### Short-term (P1)
4. **Update Terraform configs:**
   - Change ports: 80,443,8001-8005 → 443,9901
   - Update firewall rules
   - Remove Nginx, add Envoy

5. **Update Ansible playbooks:**
   - Install Envoy instead of Nginx
   - Deploy from ops/docker-compose.prod.yml
   - Update Let's Encrypt for Envoy

6. **Create new .env.prod.example in ops/:**
   - gRPC ports (50051-50057)
   - Envoy admin port (9901)
   - Remove REST gateway variables

### Long-term (P2)
7. **Delete infrastructure/ entirely** (after 1-2 months)
   - Confirm nothing references old configs
   - Delete DEPRECATED/ folder

---

## 📋 File-by-File Assessment

| File | Status | Action |
|------|--------|--------|
| `infrastructure/nginx/*` | ❌ Obsolete | Move to DEPRECATED |
| `infrastructure/Caddyfile` | ❌ Obsolete | Move to DEPRECATED |
| `infrastructure/docker-compose.*.yml` | ❌ Obsolete | Move to DEPRECATED |
| `infrastructure/deploy.sh` | ❌ Obsolete | Move to DEPRECATED |
| `infrastructure/terraform/*` | ⚠️ Needs update | Move to ops/, update ports |
| `infrastructure/ansible/*` | ⚠️ Needs update | Move to ops/, update tasks |
| `infrastructure/security/*` | ⚠️ Needs update | Move to ops/, update firewall |
| `infrastructure/.env.prod.example` | ⚠️ Needs update | Rewrite in ops/ |
| `infrastructure/README.md` | ⚠️ Needs rewrite | Update with deprecation notice |

---

## 🎯 Recommended Immediate Action

```bash
# 1. Archive old deployment configs
mkdir -p infrastructure/DEPRECATED
mv infrastructure/{Caddyfile,deploy.sh,docker-compose.*.yml} infrastructure/DEPRECATED/
mv infrastructure/nginx infrastructure/DEPRECATED/

# 2. Move reusable infrastructure-as-code
mv infrastructure/terraform ops/
mv infrastructure/ansible ops/
mv infrastructure/security ops/

# 3. Update README with deprecation notice
# (see next section)

# 4. Eventually delete (after confirming nothing breaks)
# rm -rf infrastructure/
```

---

## 📝 New infrastructure/README.md

```markdown
# Infrastructure Directory

⚠️ **DEPRECATED** - This directory contains OLD architecture configurations.

## 🚀 Current Deployment

**All current deployment configs are in `/ops/` directory.**

- Production VPS: `ops/docker-compose.prod.yml` + `ops/envoy.prod.yaml`
- Staging (Fly.io): `ops/fly.toml` + `ops/envoy.fly.yaml`
- Local dev: `ops/docker-compose.dev.yml` + `ops/envoy.yaml`

See: `ops/DEPLOYMENT_GUIDE.md`

## 🏗️ Architecture Change

**Old (deprecated):**
- Nginx Gateway (REST)
- 7 ports (80, 443, 8001-8005)
- HTTP/REST protocol

**New (current):**
- Envoy Proxy (gRPC)
- 1 port (443 with path-based routing)
- gRPC protocol (with gRPC-Web support)

## 📂 What Moved

- Terraform: `infrastructure/terraform` → `ops/terraform`
- Ansible: `infrastructure/ansible` → `ops/ansible`
- Deployment: `infrastructure/docker-compose.prod.yml` → `ops/docker-compose.prod.yml`

## 🗄️ Archive

Old configs are in `DEPRECATED/` subdirectory for historical reference only.
**DO NOT USE THESE IN PRODUCTION.**
```

---

## ✅ Success Criteria

- [ ] All old configs archived in DEPRECATED/
- [ ] Terraform/Ansible moved to ops/ and updated
- [ ] infrastructure/README.md explains deprecation
- [ ] ops/ is single source of truth
- [ ] Team aware of directory change
- [ ] CI/CD updated to use ops/ (if applicable)

---

## 🤔 Questions to Resolve

1. **Keep infrastructure/ or delete entirely?**
   - Recommendation: Keep for 1-2 months, then delete

2. **Terraform state files - are they in version control?**
   - If yes: Need to update paths carefully
   - If no: Can move freely

3. **Do any scripts reference infrastructure/ paths?**
   - Need to update: CI/CD, deployment scripts, docs

4. **Is ansible/ actively used for deployment?**
   - If yes: Update playbooks for Envoy ASAP
   - If no: Can update later or skip
