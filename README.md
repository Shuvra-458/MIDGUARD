# MIDGUARD

## Middleware Intelligent Defense Gateway for User-Agent Request Defense

MIDGUARD is a production-grade AI security middleware designed to protect enterprise AI agents and LLM-powered applications from prompt injection, jailbreak attempts, PII leakage, toxic outputs, and malicious user interactions.

It acts as a transparent security gateway between client applications and AI models, intercepting and analyzing requests/responses in real time using rule-based and AI-driven detection pipelines.

---

# 🚀 Features

* 🔐 HMAC-SHA256 API Key Authentication
* ⚡ Redis Token Bucket Rate Limiting
* 🛡️ Prompt Injection Detection
* 🚨 Jailbreak Detection (DAN, Grandma Exploit, etc.)
* 🧠 DistilBERT-based Semantic Threat Analysis
* 🔎 PII Detection

  * Aadhaar
  * PAN
  * IFSC
  * Credit Cards
* ☣️ Toxicity Detection
* 🔄 Bidirectional Filtering (Input + Output)
* 📜 PostgreSQL Audit Logging
* 📊 Real-Time SOC Dashboard
* 📈 Prometheus Metrics
* 🐳 Dockerized Deployment
* ⚙️ Async FastAPI Backend
* 🧪 97 Automated Unit Tests
* ☁️ Railway Deployment Support

---

# 🏗️ System Architecture

```text
Client Application
        │
        ▼
 ┌────────────────────┐
 │     MIDGUARD       │
 │ Security Middleware│
 └────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ Phase 1 - Authentication  │
│ Phase 2 - Policy Engine   │
│ Phase 3 - Threat Detection│
│ Phase 4 - Enforcement     │
│ Phase 5 - Output Filter   │
│ Phase 6 - SOC Dashboard   │
│ Phase 7 - Attack Sim      │
│ Phase 8 - Metrics         │
└───────────────────────────┘
        │
        ▼
   Protected AI Agent
   (Groq Llama 3.1 8B)
```

---

# 📂 Project Structure

```text
MIDGUARD/
│
├── alembic/                 # Database migrations
├── config/                  # YAML policy configurations
├── frontend/                # Frontend + SOC Dashboard
├── gateway/
│   ├── auth/                # Authentication + Rate Limiting
│   ├── enforcement/         # Enforcement layer
│   ├── models/              # Database & Pydantic models
│   ├── output/              # Output filtering
│   ├── policy/              # Policy engine
│   ├── soc/                 # SOC dashboard routes
│   ├── threat/              # AI threat detectors
│   ├── database.py
│   ├── redis_client.py
│   └── main.py
│
├── scripts/                 # Utility scripts
├── tests/                   # Unit tests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── Makefile
```

---

# 🧠 Threat Detection Pipeline

## Phase 1 — Authentication

* HMAC-SHA256 API authentication
* JWT validation
* Agent verification

## Phase 2 — Policy Engine

* YAML-based policy validation
* Network & action restrictions
* Rule-based enforcement

## Phase 3 — Threat Detection

Includes parallel AI detectors:

### Injection Detector

* DistilBERT
* Regex patterns

### Jailbreak Detector

Detects:

* DAN
* Grandma Exploit
* Ignore Previous Instructions
* Roleplay attacks

### PII Scanner

Detects:

* Aadhaar
* PAN
* IFSC
* Credit Cards
* Emails
* Phone numbers

### Toxicity Scanner

* Harmful content analysis
* Offensive language filtering

## Phase 4 — Enforcement Layer

Actions:

* ALLOW
* BLOCK
* QUARANTINE

## Phase 5 — Output Filter

Scans AI responses for:

* Hallucinations
* PII leakage
* Toxic outputs

## Phase 6 — SOC Dashboard

* Live monitoring
* Threat visualization
* WebSocket updates

## Phase 7 — Attack Simulation

* Real-world attack testing
* Red-team scenarios

## Phase 8 — Metrics & Monitoring

* Prometheus metrics
* System observability

---

# 🛠️ Tech Stack

## Backend

* Python 3.11
* FastAPI
* Uvicorn
* AsyncIO

## AI / ML

* DistilBERT
* LLM Guard
* spaCy
* Groq Llama 3.1 8B

## Database & Cache

* PostgreSQL 15
* Redis 7
* SQLAlchemy
* Alembic

## Monitoring

* Prometheus
* WebSocket
* Chart.js

## DevOps

* Docker
* Docker Compose
* Railway

---
# 🔧 Prerequisites

Before running MIDGUARD, ensure the following software and tools are installed on your system.

---

# 🖥️ System Requirements

Recommended:

* OS: Ubuntu 22.04+ / Linux / macOS / Windows (WSL2 recommended)
* RAM: Minimum 8 GB
* Storage: Minimum 10 GB free
* CPU: Multi-core processor recommended
* Internet connection for downloading AI models and Docker images

---

# 📦 Required Software

## 1️⃣ Python 3.11+

MIDGUARD is built using Python 3.11.

### Verify Installation

```bash id="xq0h3j"
python3 --version
```

### Download Python

* Linux/macOS/Windows:
  https://www.python.org/downloads/

---

## 2️⃣ Docker

Docker is required to run:

* FastAPI backend
* PostgreSQL
* Redis
* Monitoring services

### Verify Installation

```bash id="j0u8d1"
docker --version
```

### Install Docker

* Official Installation Guide:
  https://docs.docker.com/get-docker/

### Ubuntu Quick Install

```bash id="b9e2ms"
sudo apt update
sudo apt install docker.io -y
sudo systemctl enable docker
sudo systemctl start docker
```

---

## 3️⃣ Docker Compose

Used for multi-container orchestration.

### Verify Installation

```bash id="h7t9pl"
docker-compose --version
```

### Install Docker Compose

* Official Docs:
  https://docs.docker.com/compose/install/

### Ubuntu Quick Install

```bash id="0v8x6f"
sudo apt install docker-compose -y
```

---

## 4️⃣ Make Utility

Required for running Makefile commands.

### Verify Installation

```bash id="vm1yaf"
make --version
```

### Install Make

### Ubuntu/Debian

```bash id="mlpl8m"
sudo apt install make -y
```

### macOS

```bash id="vyd6oz"
xcode-select --install
```

---

# 🧠 AI/ML Dependencies

The following models/libraries are automatically downloaded during setup or first execution.

## DistilBERT

Used for:

* Prompt injection detection
* Semantic analysis

### HuggingFace

https://huggingface.co/

---

## spaCy NLP Model

Used for:

* PII detection
* Named Entity Recognition

### Install Manually (Optional)

```bash id="k9c0gc"
python -m spacy download en_core_web_sm
```

### spaCy Official Website

https://spacy.io/

---

# 🗄️ Database & Cache

These are automatically started via Docker Compose.

## PostgreSQL 15

Used for:

* Audit logs
* Agent authentication
* Persistent storage

Official Website:
https://www.postgresql.org/

---

## Redis 7

Used for:

* Rate limiting
* Token bucket implementation
* Temporary caching

Official Website:
https://redis.io/

---

# ☁️ Groq API Access

MIDGUARD integrates with Groq-hosted Llama 3.1 8B.

## Create Free Groq API Key

1. Visit:
   https://console.groq.com/

2. Sign up/Login

3. Generate API key

4. Add it inside `.env`

Example:

```env id="k8mn1r"
GROQ_API_KEY=your_api_key_here
```

---

# 🧪 Optional Development Tools

## Postman

Used for:

* API testing
* Attack simulation
* Request debugging

Download:
https://www.postman.com/downloads/

---

## Git

### Verify Installation

```bash id="6hrl4p"
git --version
```

### Install Git

https://git-scm.com/downloads

---

# 📥 Clone the Repository

```bash id="b1fdh9"
git clone https://github.com/your-username/MIDGUARD.git
cd MIDGUARD
```

---

# 📄 Install Python Dependencies (Optional Local Setup)

If running locally without Docker:

```bash id="yo4rde"
pip install -r requirements.txt
```

---

# ⚡ Quick Start (Recommended)

## Start MIDGUARD

```bash id="xf8p4o"
make start
```

## Access Backend

```text id="4smwln"
http://localhost:8000
```

## Access SOC Dashboard

```text id="dxl1cx"
http://localhost:8000/soc
```

## Access Metrics

```text id="zq0j4g"
http://localhost:8000/metrics
```

---

# 🛑 Common Issues

## Docker Permission Denied

Run:

```bash id="2j6tdn"
sudo usermod -aG docker $USER
newgrp docker
```

---

## Port Already in Use

Check ports:

```bash id="br4h6k"
sudo lsof -i :8000
```

Kill process if needed:

```bash id="i0q0w7"
sudo kill -9 <PID>
```

---

# ✅ Recommended Startup Flow

```bash id="13h59g"
# Clone repo
git clone https://github.com/your-username/MIDGUARD.git

# Enter project
cd MIDGUARD

# Create environment variables
touch .env

# Start application
make rebuild

# Check logs
make logs
```

---

# 🎯 Ready to Use

Once the containers are running successfully:

* Backend API becomes available
* SOC dashboard becomes live
* Threat detection pipeline activates
* Redis/PostgreSQL services connect automatically
* Metrics endpoint becomes accessible

MIDGUARD is now ready to defend AI applications against prompt injections, jailbreaks, PII leaks, and toxic outputs.


# ⚙️ Installation & Setup

# 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/MIDGUARD.git
cd MIDGUARD
```

---

# 2️⃣ Create Environment File

Create a `.env` file:

```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/midguard
REDIS_URL=redis://redis:6379

JWT_SECRET=your_jwt_secret
HMAC_SECRET=your_hmac_secret

GROQ_API_KEY=your_groq_api_key
```

---

# 3️⃣ Build & Start Containers

## Start Containers

```bash
make start
```

## Rebuild Containers

```bash
make rebuild
```

## Stop Containers

```bash
make stop
```

## Remove Containers + Volumes

```bash
make clean
```

## View Logs

```bash
make logs
```

## Check Running Containers

```bash
make ps
```

---

# 🐳 Docker Commands (Manual)

## Start

```bash
docker-compose up -d
```

## Build & Start

```bash
docker-compose up -d --build
```

## Stop

```bash
docker-compose down
```

---

# 🧪 Running Tests

Run all unit tests:

```bash
pytest
```

Run specific test files:

```bash
pytest tests/test_phase1_auth.py
pytest tests/test_phase2_policy.py
pytest tests/test_phase3_threat.py
pytest tests/test_phase4_enforcement.py
pytest tests/test_phase5_output.py
```

---

# 📊 SOC Dashboard

Access the SOC dashboard:

```text
http://localhost:8000/soc
```

Features:

* Live attack monitoring
* Threat analytics
* WebSocket event streaming
* Real-time charts

---

# 📈 Prometheus Metrics

Metrics endpoint:

```text
http://localhost:8000/metrics
```

---

# 🔐 API Authentication

MIDGUARD uses:

* HMAC-SHA256 signing
* JWT-based access control
* PostgreSQL-backed agent verification

---

# 🔥 Example Attack Scenarios

MIDGUARD successfully detects:

* Prompt Injection
* DAN Jailbreak
* Grandma Exploit
* SQL Injection
* Base64 Smuggling
* PII Leakage
* Toxic Prompts
* Malicious AI Responses

---

# 🌐 API Endpoints

## Health Check

```http
GET /health
```

## Main Gateway Endpoint

```http
POST /gateway/chat
```

## Metrics

```http
GET /metrics
```

## SOC Dashboard

```http
GET /soc
```

---

# 📌 Current Implementation Status

✅ 8 Security Phases Completed
✅ 97 Automated Tests Passing
✅ 12 Attack Simulations Validated
✅ Real-Time SOC Dashboard Working
✅ Railway Deployment Active
✅ Groq LLM Integration Complete

---

# 🔮 Future Enhancements

* Sentence Transformer Hallucination Detection
* Multi-Tenant Architecture
* Grafana Integration
* OpenTelemetry Tracing
* Advanced Threat Intelligence
* SaaS Deployment Model

---

# 👨‍💻 Team Members

* Aayushman Sahu
* Gyan Prakash Nayak
* Jyotiprakash Panda
* Sameer Raj Panda
* Shuvrajyoti Nayak

---

# 🏫 Institution

Centre for Cybersecurity
Faculty of Engineering & Technology (ITER)
Siksha ‘O’ Anusandhan University
Bhubaneswar, Odisha

---

# 📚 References

1. OWASP Top 10 for LLM Applications
2. Guardrails AI
3. NVIDIA NeMo Guardrails
4. Meta LlamaGuard
5. Prompt Injection Research Papers

---

# 📜 License

This project is developed for academic and research purposes.

---

# ⭐ MIDGUARD Vision

Building a secure future for enterprise AI systems through intelligent middleware defense.
