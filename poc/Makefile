H2C_DIR := ./cpace/poc/draft-irtf-cfrg-hash-to-curve/poc/
VOPRF_DIR := ./cpace/poc/draft-irtf-cfrg-voprf/poc/
CPACE_DIR := ./cpace/poc/

SAGEFILES := $(basename $(notdir $(wildcard *.sage))) \
             $(basename $(notdir $(wildcard $(H2C_DIR)*.sage))) \
             $(basename $(notdir $(wildcard $(VOPRF_DIR)*.sage))) \
             $(basename $(notdir $(wildcard $(CPACE_DIR)*.sage)))

PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES))) sagelib/hash_to_field.py
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

print:
	echo $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

sagelib/%.py: $(H2C_DIR)%.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

sagelib/%.py: $(VOPRF_DIR)%.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

sagelib/%.py: $(H2C_DIR)%.py
	@echo "Copying $<"
	@cp $< $@

sagelib/%.py: $(CPACE_DIR)%.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

test: pyfiles
	sage kemeleon.py
	sage cpaceoquake.py
	sage cpaceoquake_plus.py

.PHONY: check
check:
	python3 check_vectors.py

vectors: pyfiles
	@echo "Removing vectors folder, if present"
	@rm -rf vectors
	@echo "Creating vectors folder"
	@mkdir -p vectors
	sage kemeleon.py
	sage cpaceoquake.py
	sage cpaceoquake_plus.py


.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii .cache
