.PHONY: lint format format-check typecheck test check clean

lint:
	ruff check . --fix

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy . --exclude '.venv|__pycache__|hooks/tests'

test:
	pytest --cov --cov-report=term-missing

check: format-check lint typecheck test

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
