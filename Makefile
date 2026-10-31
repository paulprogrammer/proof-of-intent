# Makefile for IETF Internet-Drafts
# Compiles RFCXML (v3), TXT, and HTML derivatives from markdown sources and validates with idnits.

KRAMDOWN_RFC ?= kramdown-rfc
XML2RFC      ?= xml2rfc
IDNITS       ?= idnits
IDNITS_FLAGS ?= -m submission --fail-on errors

# Discover draft markdown sources
SOURCES := $(sort $(wildcard draft-*.md))
XMLS    := $(SOURCES:.md=.xml)
TXTS    := $(SOURCES:.md=.txt)
HTMLS   := $(SOURCES:.md=.html)
PDFS    := $(SOURCES:.md=.pdf)

.PHONY: all txt html xml pdf idnits check clean help

# Default target builds text and HTML deliverables and validates with idnits
all: txt html idnits

# Target aliases
txt: $(TXTS)
html: $(HTMLS)
xml: $(XMLS)
pdf: $(PDFS)

# Validation targets (validates both RFCXML v3 and plain text deliverables)
check: idnits
idnits: $(TXTS) $(XMLS)
	@for target in $(TXTS) $(XMLS); do \
		echo "Validating $$target with $(IDNITS)..."; \
		$(IDNITS) $(IDNITS_FLAGS) $$target || exit 1; \
	done

# Preserve intermediate XML files across builds
.SECONDARY: $(XMLS)
.PRECIOUS: %.xml

# Pattern rules: compiles markdown to RFCXML v2, then upgrades to canonical RFCXML v3
%.xml: %.md
	$(KRAMDOWN_RFC) $< > $@.v2
	$(XML2RFC) $@.v2 --v2v3 -o $@
	rm -f $@.v2

%.txt: %.xml
	$(XML2RFC) $< --text -o $@

%.html: %.xml
	$(XML2RFC) $< --html -o $@

%.pdf: %.xml
	$(XML2RFC) $< --pdf -o $@

clean:
	rm -f $(XMLS) $(TXTS) $(HTMLS) $(PDFS) *.v2

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all     Build text, HTML, and run idnits validation (default)"
	@echo "  txt     Build paginated RFC plain text outputs (.txt)"
	@echo "  html    Build HTML outputs (.html)"
	@echo "  xml     Build canonical RFCXML v3 files (.xml)"
	@echo "  pdf     Build PDF outputs (.pdf, requires weasyprint backend)"
	@echo "  idnits  Validate generated text and XML drafts with idnits (alias: check)"
	@echo "  clean   Remove all derived artifacts (.xml, .txt, .html, .pdf)"
