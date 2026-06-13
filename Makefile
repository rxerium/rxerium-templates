# rxerium-templates automation
#
# Common developer tasks for adding/maintaining CVE Nuclei templates.
#
# Examples:
#   make new CVE=CVE-2026-12345
#   make new CVE=CVE-2026-9999-WIP SEVERITY=critical VENDOR=Acme PRODUCT=Foo CVSS=9.8
#   make validate
#   make update
#   make stats

.PHONY: help new update validate stats clean

# Default target
help:
	@echo "rxerium-templates automation"
	@echo ""
	@echo "Targets:"
	@echo "  make new CVE=CVE-2026-12345 [WIP=1] [SEVERITY=...] [VENDOR=...] [PRODUCT=...] [CVSS=9.8]"
	@echo "      Scaffold a new template (opens $$EDITOR). Also refreshes indexes locally."
	@echo "  make update          Run both index updaters (templates.json + README stats)"
	@echo "  make validate        Strict validation of all templates (used in CI)"
	@echo "  make stats           Alias for update (legacy)"
	@echo ""
	@echo "Non-interactive example:"
	@echo "  make new CVE=CVE-2026-0001 WIP=1 VENDOR=\"Palo Alto\" PRODUCT=\"PAN-OS\" CVSS=9.8 NO_EDIT=1"

# Add a new CVE template.
# Pass positional-ish via variables because Make doesn't do subcommand args easily.
new:
	@if [ -z "$(CVE)" ]; then \
		echo "Usage: make new CVE=CVE-2026-12345 [WIP=1] [SEVERITY=critical] [VENDOR=...] [PRODUCT=...] [CVSS=9.8] [NO_EDIT=1]"; \
		exit 1; \
	fi
	@WIP_FLAG=""; \
	if [ "$(WIP)" = "1" ] || [ "$(WIP)" = "true" ]; then WIP_FLAG="--wip"; fi; \
	NO_EDIT_FLAG=""; \
	if [ "$(NO_EDIT)" = "1" ] || [ "$(NO_EDIT)" = "true" ]; then NO_EDIT_FLAG="--no-edit"; fi; \
	YES_FLAG="-y"; \
	SEV_FLAG=""; if [ -n "$(SEVERITY)" ]; then SEV_FLAG="--severity $(SEVERITY)"; fi; \
	VEND_FLAG=""; if [ -n "$(VENDOR)" ]; then VEND_FLAG="--vendor \"$(VENDOR)\""; fi; \
	PROD_FLAG=""; if [ -n "$(PRODUCT)" ]; then PROD_FLAG="--product \"$(PRODUCT)\""; fi; \
	CVSS_FLAG=""; if [ -n "$(CVSS)" ]; then CVSS_FLAG="--cvss $(CVSS)"; fi; \
	echo "🚀 Running new template helper for $(CVE)..."; \
	python3 scripts/new_cve_template.py $(CVE) $$WIP_FLAG $$NO_EDIT_FLAG $$YES_FLAG $$SEV_FLAG $$VEND_FLAG $$PROD_FLAG $$CVSS_FLAG

update:
	python3 scripts/update_readme_stats.py
	python3 scripts/update_templates_json.py

validate:
	python3 scripts/validate_templates.py

stats: update

# Optional: remove any generated temp dirs from manual experiments (e.g. future year dirs)
clean:
	@find . -type d -name '20[0-9][0-9]' -empty -delete 2>/dev/null || true
	@echo "Cleaned empty year directories (if any)."
