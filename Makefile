.PHONY: setup run dev api test clean docker docker-dev

setup:
	uv sync
	uv run playwright install

run:
	uv run main.py

dev:
	uv run server.py --reload

api:
	uv run server.py

test:
	uv run pytest

clean:
	rm -rf .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +

docker:
	docker-compose up api

docker-dev:
	docker-compose up dev
