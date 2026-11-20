# Makefile for IETF Internet-Drafts
# Compiles RFCXML (v3), TXT, and HTML derivatives from markdown sources, validates with idnits,
# and uploads revisions to the IETF Datatracker submission API.

-include .env

KRAMDOWN_RFC        ?= kramdown-rfc
XML2RFC             ?= xml2rfc
IDNITS              ?= idnits
IDNITS_FLAGS        ?= -m submission --fail-on errors
DATATRACKER_USER    ?= paul@barefootcoders.com
DATATRACKER_SUBMIT  ?= https://datatracker.ietf.org/api/submission

# Discover draft markdown sources
SOURCES := $(sort $(wildcard draft-*.md))
XMLS    := $(SOURCES:.md=.xml)
TXTS    := $(SOURCES:.md=.txt)
HTMLS   := $(SOURCES:.md=.html)
PDFS    := $(SOURCES:.md=.pdf)

# Allow positional syntax: `make submit core-01` or `make submit chained-state-01`
ifeq (submit,$(firstword $(MAKECMDGOALS)))
  SUBMIT_ARG := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifneq ($(SUBMIT_ARG),)
    $(eval $(SUBMIT_ARG):;@:)
  endif
endif

.PHONY: all txt html xml pdf idnits check submit clean help

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

# Submit a specific draft revision to Datatracker:
#   make submit core-01
#   make submit chained-state-01
submit:
	@target="$(strip $(or $(DRAFT),$(SUBMIT_ARG)))"; \
	if [ -z "$$target" ]; then \
		echo "ERROR: missing draft target. Usage: make submit core-XX | make submit chained-state-XX" >&2; \
		exit 1; \
	fi; \
	case "$$target" in \
		core-[0-9][0-9]|chained-state-[0-9][0-9]) \
			stem="draft-williams-oauth-poi-$$target" ;; \
		draft-williams-oauth-poi-core-[0-9][0-9]|draft-williams-oauth-poi-chained-state-[0-9][0-9]) \
			stem="$$target" ;; \
		*) \
			echo "ERROR: invalid target '$$target'. Expected core-[0-9]{2} or chained-state-[0-9]{2} (e.g., core-01)." >&2; \
			exit 1 ;; \
	esac; \
	md_file="$$stem.md"; \
	xml_file="$$stem.xml"; \
	txt_file="$$stem.txt"; \
	if [ ! -f "$$md_file" ]; then \
		echo "ERROR: source file '$$md_file' does not exist." >&2; \
		exit 1; \
	fi; \
	echo "==> Building fresh $$xml_file and $$txt_file (with today's date)..."; \
	$(MAKE) -B "$$xml_file" "$$txt_file" || exit 1; \
	echo "==> Validating $$txt_file and $$xml_file with $(IDNITS)..."; \
	$(IDNITS) $(IDNITS_FLAGS) "$$txt_file" || exit 1; \
	$(IDNITS) $(IDNITS_FLAGS) "$$xml_file" || exit 1; \
	if [ "$${DRY_RUN:-0}" = "1" ]; then \
		echo "[DRY_RUN] Would submit $$xml_file as $(DATATRACKER_USER) to $(DATATRACKER_SUBMIT)"; \
		exit 0; \
	fi; \
	echo "==> Uploading $$xml_file to $(DATATRACKER_SUBMIT) as $(DATATRACKER_USER)..."; \
	auth_hdr=(); \
	if [ -n "$(AUTHORTOOLS_API_KEY)" ]; then \
		auth_hdr=(-H "X-API-KEY: $(AUTHORTOOLS_API_KEY)"); \
	fi; \
	resp="$$(curl -sS "$${auth_hdr[@]}" \
		-F "user=$(DATATRACKER_USER)" \
		-F "xml=@$$xml_file" \
		"$(DATATRACKER_SUBMIT)")" || { echo "ERROR: curl upload to $(DATATRACKER_SUBMIT) failed." >&2; exit 1; }; \
	sub_id="$$(printf '%s' "$$resp" | jq -r '.id // empty' 2>/dev/null)"; \
	if [ -z "$$sub_id" ]; then \
		echo "ERROR: Datatracker submission failed:" >&2; \
		printf '%s\n' "$$resp" | jq . >&2 || printf '%s\n' "$$resp" >&2; \
		exit 1; \
	fi; \
	status_api="$$(printf '%s' "$$resp" | jq -r '.status_url // "https://datatracker.ietf.org/api/submission/\(.id)/status"')"; \
	web_url="https://datatracker.ietf.org/submit/status/$$sub_id/"; \
	printf '%s\n' "$$resp" | jq -r '"Submission accepted: id=\(.id), draft=\(.name)-\(.rev)"'; \
	echo "API status endpoint: $$status_api"; \
	echo ""; \
	echo "========================================================================"; \
	echo " Open this verification URL in your browser to review and publish:"; \
	echo " $$web_url"; \
	echo "========================================================================"

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all                        Build text, HTML, and run idnits validation (default)"
	@echo "  txt                        Build paginated RFC plain text outputs (.txt)"
	@echo "  html                       Build HTML outputs (.html)"
	@echo "  xml                        Build canonical RFCXML v3 files (.xml)"
	@echo "  pdf                        Build PDF outputs (.pdf, requires weasyprint backend)"
	@echo "  idnits                     Validate generated text and XML drafts with idnits (alias: check)"
	@echo "  submit <core-XX|chained-state-XX>  Build, validate, and upload revision XML to Datatracker"
	@echo "  clean                      Remove all derived artifacts (.xml, .txt, .html, .pdf)"
