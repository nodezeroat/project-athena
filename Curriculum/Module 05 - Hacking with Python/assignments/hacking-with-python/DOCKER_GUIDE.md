# Docker Compose Guide

This guide explains how to use the unified `docker-compose.yml` to run all challenge servers.

## Quick Start

```bash
# From the hacking-with-python directory
cd "Curriculum/Module 05 - Hacking with Python/assignments/hacking-with-python"

# Start all challenge servers
docker-compose up -d

# Verify all services are running
docker-compose ps
```

## Services Overview

The unified docker-compose starts 4 challenge servers:

| Service | Container Name | Port | Assignment | Endpoint |
|---------|---------------|------|------------|----------|
| **uuid-discovery** | assignment1-uuid-discovery | 5000 | Assignment 1 | <http://localhost:5000/api/health> |
| **math-challenge** | assignment3-math-challenge | 9999 | Assignment 3 | `nc localhost 9999` |
| **web-scraping** | assignment4-web-scraping | 8080 | Assignment 4 | <http://localhost:8080> |
| **multi-stage-api** | assignment5-multi-stage | 7000 | Assignment 5 | <http://localhost:7000/api/register> |

## Common Commands

### Start Services

```bash
# Start all services in detached mode
docker-compose up -d

# Start all services with logs visible
docker-compose up

# Start specific service only
docker-compose up -d uuid-discovery
```

### View Logs

```bash
# View logs from all services
docker-compose logs

# Follow logs in real-time
docker-compose logs -f

# View logs for specific service
docker-compose logs -f uuid-discovery
docker-compose logs -f math-challenge
docker-compose logs -f web-scraping
docker-compose logs -f multi-stage-api

# View last 50 lines
docker-compose logs --tail=50
```

### Check Status

```bash
# List all running services
docker-compose ps

# Check health status
docker-compose ps
```

### Stop Services

```bash
# Stop all services (containers remain)
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop and remove containers + volumes
docker-compose down -v

# Stop specific service
docker-compose stop uuid-discovery
```

### Restart Services

```bash
# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart uuid-discovery

# Rebuild and restart (after code changes)
docker-compose up -d --build
docker-compose up -d --build uuid-discovery  # Specific service
```

## Accessing Services

### Assignment 1: UUID Discovery

```bash
# Test health endpoint
curl http://localhost:5000/api/health

# The app.min.js file is generated in assignment-1-web-api/
ls -lh assignment-1-web-api/app.min.js

# Run solution
cd assignment-1-web-api
python solution.py
```

### Assignment 3: Math Challenge

```bash
# Connect with netcat
nc localhost 9999

# Or use the solution script
cd assignment-3-math-solver
python solution.py
```

### Assignment 4: Web Scraping

```bash
# Access in browser
open http://localhost:8080

# Or test with curl
curl http://localhost:8080

# Run solution
cd assignment-4-web-scraping
python solution.py
```

### Assignment 5: Multi-Stage

```bash
# Test health endpoint
curl http://localhost:7000/api/register

# Run solution
cd assignment-5-multi-stage
python solution.py
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs for errors
docker-compose logs <service-name>

# Common issues:
# - Port already in use
# - Build errors
# - Missing files
```

### Port Already in Use

```bash
# Find what's using the port
lsof -i :5000
lsof -i :9999
lsof -i :8080
lsof -i :7000

# Kill the process or change port in docker-compose.yml
```

### Rebuild After Changes

```bash
# Rebuild all services
docker-compose build

# Rebuild specific service
docker-compose build uuid-discovery

# Rebuild and restart
docker-compose up -d --build
```

### Reset Everything

```bash
# Stop and remove all containers, networks, volumes
docker-compose down -v

# Remove all images
docker-compose down --rmi all

# Start fresh
docker-compose up -d --build
```

### View Container Shell

```bash
# Access container bash
docker-compose exec uuid-discovery /bin/bash
docker-compose exec math-challenge /bin/sh
docker-compose exec web-scraping /bin/bash
docker-compose exec multi-stage-api /bin/bash
```

### Check Resource Usage

```bash
# View resource usage
docker stats

# View disk usage
docker system df
```

## Network Configuration

All services are connected to a shared network: `hacking-python-network`

This allows services to communicate with each other (e.g., Assignment 5 can access Assignment 3's math server).

## Volume Mounts

### Assignment 1 (UUID Discovery)

The `app.min.js` file is generated inside the container and mounted to:

```text
./assignment-1-web-api/app.min.js
```

This allows student scripts to read the file from the host filesystem.

## Environment Variables

Each service generates a unique flag with a random component on startup.

**Flag Format:** `FLAG{Description_<random_hex>}`

Where `<random_hex>` is a 16-character hexadecimal string generated using `secrets.token_hex(8)`.

**Examples:**

- Assignment 1: `FLAG{UUID_Discovery_Complete_a1b2c3d4e5f67890}`
- Assignment 3: `FLAG{Automation_Beats_Manual_1234567890abcdef}`
- Assignment 4: `FLAG{Web_Scraping_Masters_fedcba0987654321}`
- Assignment 5: `FLAG{Multi_Stage_Master_0011223344556677}`

**Why Random Flags?**

- Prevents flag sharing between students
- Each container restart generates a new flag
- Ensures academic integrity
- Simulates real CTF environments where flags are unique per team

To see your flag, check the container logs:

```bash
docker-compose logs uuid-discovery | grep FLAG
docker-compose logs math-challenge | grep FLAG
```

## Health Checks

Services with HTTP endpoints include health checks:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:5000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 10s
```

Check health status:

```bash
docker-compose ps
# HEALTHY status means service is running correctly
```

## Best Practices

1. **Start services before working on assignments**

   ```bash
   docker-compose up -d
   ```

2. **Check logs if something doesn't work**

   ```bash
   docker-compose logs -f <service-name>
   ```

3. **Stop services when done to free resources**

   ```bash
   docker-compose down
   ```

4. **Rebuild after updating server code**

   ```bash
   docker-compose up -d --build <service-name>
   ```

5. **Use individual docker-compose files for focused work**

   ```bash
   cd assignment-1-web-api
   docker-compose up -d
   ```

## Individual vs Unified Docker Compose

### Unified (Recommended for Testing All)

```bash
# From hacking-with-python directory
docker-compose up -d
```

**Pros:**

- Start all servers at once
- Test multiple assignments
- Realistic CTF environment

**Cons:**

- Uses more resources
- More complex troubleshooting

### Individual (Recommended for Learning)

```bash
# From specific assignment directory
cd assignment-1-web-api
docker-compose up -d
```

**Pros:**

- Focused environment
- Less resource usage
- Easier debugging

**Cons:**

- Must start/stop for each assignment
- Assignment 5 needs Assignment 3 running

## Summary

```bash
# Quick reference
docker-compose up -d          # Start all
docker-compose ps             # Check status
docker-compose logs -f        # View logs
docker-compose down           # Stop all
docker-compose restart        # Restart all
docker-compose up -d --build  # Rebuild and restart
```

For more help, see individual assignment README files or the main [README.md](README.md).
