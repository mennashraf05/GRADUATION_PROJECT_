# Sentinel AI Graduation Project

Sentinel AI is a full-stack cybersecurity dashboard built with a Flask/Python backend and a React/Vite frontend. It includes authentication, admin dashboards, phishing checks, password analysis, PCAP analysis, identity leak monitoring, reports, notifications, and file-vault features.

## Technologies

- Backend: Python, Flask, Flask-SQLAlchemy, SQLite, scikit-learn, XGBoost, tshark
- Frontend: React, Vite, TypeScript, nginx
- Runtime: Docker Compose

## Environment

Create a local environment file from the template:

```bash
cp .env.example .env
```

Edit `.env` with local values before running the project. Use strong random values for `SECRET_KEY` and `JWT_SECRET_KEY`. Never commit real `.env` files, API keys, tokens, passwords, SQLite databases, uploaded files, generated reports, or PCAP artifacts.

## Run With Docker

Build and start both services:

```bash
docker compose up --build
```

Open:

- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

Stop the containers:

```bash
docker compose down
```

The backend starts with `python run_server_no_reload.py` inside the `Backend` folder and binds Flask to `0.0.0.0:5000`. The frontend is built with `npm run build` and served by nginx on container port `80`.

## Project Structure

- `Backend/`: Flask backend source, Python requirements, models, analyzers, scanners, and services
- `Cybersecurity Dashboard Design/`: React/Vite frontend source
- `Dockerfile`: backend image
- `Dockerfile.frontend`: frontend build and nginx image
- `docker-compose.yml`: local multi-container setup
- `nginx.conf`: nginx SPA routing configuration
- `.env.example`: placeholder environment variables only

## GitHub Safety

The repository ignore rules exclude local secrets, virtual environments, dependencies, build output, SQLite databases, uploaded files, PCAP runs, generated reports, logs, archives, and OS metadata. Keep real credentials and runtime artifacts out of GitHub.
