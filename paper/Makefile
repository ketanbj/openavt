PYTHON ?= python3
TECTONIC ?= tectonic
OUTPUT ?= ../output/pdf

.PHONY: all results pdf clean
all: pdf

results:
	$(PYTHON) scripts/extract_results.py

pdf: results
	mkdir -p $(OUTPUT)
	$(TECTONIC) --keep-logs --keep-intermediates --outdir $(OUTPUT) main.tex

clean:
	rm -f $(OUTPUT)/main.aux $(OUTPUT)/main.bbl $(OUTPUT)/main.blg $(OUTPUT)/main.log $(OUTPUT)/main.out
