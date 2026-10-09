.PHONY: test
test:
	python3 kemeleon.py
	python3 ml_bua_skem.py
	python3 cpace.py
	python3 oquake.py
	python3 cpaceoquake.py
	python3 oquake_plus.py
	python3 cpaceoquake_plus.py

.PHONY: check
check:
	python3 check_vectors.py

.PHONY: clean
clean:
	rm -rf __pycache__

.PHONY: distclean
distclean: clean
	rm -rf .cache
