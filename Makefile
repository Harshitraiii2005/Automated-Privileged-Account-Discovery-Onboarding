.PHONY: help setup lab-gen lab-up lab-health lab-down lab-reset test lint demo site serve

COMPOSE := docker compose
PY := uv run python -m
AO := uv run autoonboard

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: ## install Python dependencies
	uv sync

lab-gen: setup ## create .env, PKI, SSH keys, seed data and ground truth (idempotent)
	$(PY) autoonboard.lab.generate

lab-up: lab-gen ## build and start the lab, then init/unseal/configure Vault
	$(COMPOSE) up -d --build --wait
	$(PY) autoonboard.lab.vault_bootstrap

lab-health: ## verify every lab component is up and configured as designed
	$(PY) autoonboard.lab.healthcheck

lab-down: ## stop the lab, keep data volumes
	$(COMPOSE) down

lab-reset: ## destroy the lab: containers, volumes, generated material and pipeline outputs (.env is kept)
	$(COMPOSE) down -v --remove-orphans
	rm -rf lab/.generated out

test: ## run unit tests
	uv run pytest -q

lint: ## ruff + mypy
	uv run ruff check src tests
	uv run ruff format --check src tests
	uv run mypy src

demo: ## full end-to-end run on a fresh lab (about 2 minutes once images are built)
	$(MAKE) lab-reset
	$(MAKE) lab-up
	$(MAKE) lab-health
	$(AO) discover
	$(AO) classify
	$(AO) plan --prepared-by pipeline
	$(AO) approve --all --approver security-lead --yes --comment "make demo"
	$(AO) onboard --dry-run
	$(AO) onboard
	$(AO) cpm
	$(AO) simulate failures
	@echo "--- next CPM cycle: 2 reconciles expected, plus 1 critical failure (exit 1 is expected here)"
	-$(AO) cpm
	$(AO) simulate restore
	$(AO) cpm
	$(AO) cpm --force
	$(AO) simulate access-check
	$(AO) report --pdf
	$(AO) evidence
	$(AO) site

site: ## rebuild the static demo page (site/) from the last run's outputs
	$(AO) site

serve: ## API + report on http://127.0.0.1:8000
	$(AO) serve
