# Lemonade Security — convenience targets.

PYTHON ?= python3

.PHONY: all help install test lint type fmt clean

all: lint type test

help:
	@echo "Targets:"
	@echo "  make install     Install the package (editable) with dev extras"
	@echo "  make test        Run the test suite"
	@echo "  make lint        Run ruff"
	@echo "  make type        Run mypy"
	@echo "  make fmt         Run ruff format"
	@echo "  make clean       Remove build artifacts and caches"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests

type:
	$(PYTHON) -m mypy

fmt:
	$(PYTHON) -m ruff format src tests

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -exec rm -rf {} +
	find . -name '*.egg-info' -type d -exec rm -rf {} +
