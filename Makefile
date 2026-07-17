.PHONY: install test demo clean

install:
	pip install -e ".[dev]"

test:
	pytest -v

demo:
	python -m vulnscan 127.0.0.1 -p 1-1024

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
