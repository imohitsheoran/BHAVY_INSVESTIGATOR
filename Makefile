.PHONY: demo test cases
demo:
	python -m si demo

test:
	python -m pytest -q

cases:
	python tools/build_cases.py
