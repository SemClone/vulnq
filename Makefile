.PHONY: help install dev test lint format clean build publish

help:
	@echo "Available commands:"
	@echo "  install    Install vulnq in production mode"
	@echo "  dev        Install vulnq in development mode"
	@echo "  test       Run tests"
	@echo "  lint       Run linting tools"
	@echo "  format     Format code with black and isort"
	@echo "  clean      Remove build artifacts and cache"
	@echo "  build      Build distribution packages"
	@echo "  publish    Publish to PyPI"

install:
	pip install .

dev:
	pip install -e .[dev]
	pre-commit install

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=vulnq --cov-report=html --cov-report=term

lint:
	flake8 vulnq/ --max-line-length=100 --extend-ignore=E203,W503
	mypy vulnq/ --ignore-missing-imports
	black --check vulnq/
	isort --check-only vulnq/

format:
	black vulnq/
	isort vulnq/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

publish: build
	python -m twine upload dist/*

publish-test: build
	python -m twine upload --repository testpypi dist/*