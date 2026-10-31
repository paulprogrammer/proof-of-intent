# Makefile for IETF Internet-Drafts
# Compiles RFCXML, TXT, and HTML derivatives from markdown sources.

KRAMDOWN_RFC ?= kramdown-rfc
XML2RFC      ?= xml2rfc

# Discover draft markdown sources
SOURCES := $(sort $(wildcard draft-*.md))
XMLS    := $(SOURCES:.md=.xml)
TXTS    := $(SOURCES:.md=.txt)
HTMLS   := $(SOURCES:.md=.html)
PDFS    := $(SOURCES:.md=.pdf)

.PHONY: all txt html xml pdf clean help

# Default target builds both text and HTML deliverables
all: txt html

# Target aliases
txt: $(TXTS)
html: $(HTMLS)
xml: $(XMLS)
pdf: $(PDFS)

# Preserve intermediate XML files across builds
.SECONDARY: $(XMLS)
.PRECIOUS: %.xml

# Pattern rules
%.xml: %.md
	$(KRAMDOWN_RFC) $< > $@

%.txt: %.xml
	$(XML2RFC) $< --text -o $@

%.html: %.xml
	$(XML2RFC) $< --html -o $@

%.pdf: %.xml
	$(XML2RFC) $< --pdf -o $@

clean:
	rm -f $(XMLS) $(TXTS) $(HTMLS) $(PDFS)

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all    Build text and HTML drafts (default)"
	@echo "  txt    Build paginated RFC plain text outputs (.txt)"
	@echo "  html   Build HTML outputs (.html)"
	@echo "  xml    Build RFCXML intermediate files (.xml)"
	@echo "  pdf    Build PDF outputs (.pdf, requires weasyprint backend)"
	@echo "  clean  Remove all derived artifacts (.xml, .txt, .html, .pdf)"
