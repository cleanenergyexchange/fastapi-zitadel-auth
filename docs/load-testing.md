# Load testing

Guide for load testing the `fastapi-zitadel-auth` package.

## Prerequisites

- `service_user.json` with service account credentials
- Configured `demo_project/.env` file
- Docker and Docker Compose

## Running Tests

1. Start testing environment:
   ```bash
   docker compose -f docker-compose.locust.yml up --scale locust-worker=4
   ```

2. Open [http://localhost:8089](http://localhost:8089)
3. Set test parameters (users, spawn rate)
4. Click "Start"

## Worker Configuration

### Locust Workers
```bash
docker compose -f docker-compose.locust.yml up --scale locust-worker=2
```

### API Workers
In `demo_project/Dockerfile`, adjust:
```dockerfile
CMD ["uvicorn", "demo_project.main:app", "--port", "8001", "--host", "0.0.0.0", "--workers", "2"]
```

## Tips
- Match worker count to available CPU cores
- Monitor system resources during tests
- Check Docker resource allocation
