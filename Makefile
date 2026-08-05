.PHONY: dev build test clean stop logs frontend backend check

# ── Default: start the full stack ────────────────────────────────────────────
dev: check
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║       Kelan Security — Dev Stack             ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) -j2 backend frontend

# ── Check prerequisites ───────────────────────────────────────────────────────
check:
	@command -v cargo  >/dev/null || (echo "ERROR: Rust not installed. Run: curl https://sh.rustup.rs | sh" && exit 1)
	@command -v node   >/dev/null || echo "WARN: Node.js not found — frontend will be skipped"
	@echo "Prerequisites OK"

# ── Backend (Intelligence Core server) ───────────────────────────────────────
backend:
	@echo "Starting Intelligence Core on http://localhost:3000..."
	@if [ -f "../venv/bin/python" ]; then \
		../venv/bin/python scripts/start_server.py; \
	elif [ -f "venv/bin/python" ]; then \
		venv/bin/python scripts/start_server.py; \
	elif [ -f ".venv/bin/python" ]; then \
		.venv/bin/python scripts/start_server.py; \
	else \
		python3 scripts/start_server.py; \
	fi

# ── Frontend (dashboard) ──────────────────────────────────────────────────────
frontend:
	@if [ -d "../kelan-web" ] && command -v node >/dev/null; then \
		echo "Starting frontend on http://localhost:5173..."; \
		cd ../kelan-web && npm install --silent && npm run dev; \
	elif [ -d "aitp-dashboard" ] && command -v node >/dev/null; then \
		echo "Starting frontend on http://localhost:5173..."; \
		cd aitp-dashboard && npm install --silent && npm run dev; \
	elif [ -d "frontend" ] && command -v node >/dev/null; then \
		echo "Starting frontend on http://localhost:5173..."; \
		cd frontend && npm install --silent && npm run dev; \
	else \
		echo "No frontend directory found or Node.js not installed."; \
		echo "Dashboard is served by FastAPI at http://localhost:3000"; \
	fi

# ── Build release binary ─────────────────────────────────────────────────────
build:
	@echo "Python project has no build binary step. Environment ready."

# ── Run all tests ─────────────────────────────────────────────────────────────
test:
	@if [ -f "../venv/bin/pytest" ]; then \
		../venv/bin/pytest; \
	elif [ -f "venv/bin/pytest" ]; then \
		venv/bin/pytest; \
	elif [ -f ".venv/bin/pytest" ]; then \
		.venv/bin/pytest; \
	else \
		pytest; \
	fi

# ── Stop all running instances ────────────────────────────────────────────────
stop:
	@pkill -f start_server.py 2>/dev/null || true
	@pkill -f uvicorn 2>/dev/null || true
	@pkill -f "npm run dev" 2>/dev/null || true
	@lsof -ti:3000 | xargs kill -9 2>/dev/null || true
	@lsof -ti:5173 | xargs kill -9 2>/dev/null || true
	@echo "All processes stopped. Ports 3000 and 5173 freed."

# ── Tail server logs ──────────────────────────────────────────────────────────
logs:
	tail -f log/kelan-server.log

# ── Lint ─────────────────────────────────────────────────────────────────────
lint:
	@echo "Python project format and lint checks..."

# ── Clean build artifacts ─────────────────────────────────────────────────────
clean:
	rm -rf kelan.db kelan.db-shm kelan.db-wal data/kelan.db data/kelan.db-shm data/kelan.db-wal log/*.log
	@echo "Cleaned"

# ── Fresh start (wipe DB + restart) ──────────────────────────────────────────
fresh: stop clean
	@$(MAKE) dev

# ── Docker targets ────────────────────────────────────────────────────────────
docker-build:
	docker build -t kelan-server:local .

docker-run:
	docker run -p 3000:3000 -p 9999:9999/udp \
		-e OLLAMA_ENDPOINT=$${OLLAMA_ENDPOINT} \
		-e AITP_JWT_SECRET=$${AITP_JWT_SECRET:-$(shell openssl rand -base64 48)} \
		-v kelan_data:/app/data \
		kelan-server:local

docker-stop:
	docker ps -q --filter "ancestor=kelan-server:local" | xargs -r docker stop
