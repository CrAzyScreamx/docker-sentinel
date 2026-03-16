DIST_DIR  := dist
UNAME     := $(shell uname -s 2>/dev/null || echo Windows)
ENTRY     := docker_sentinel/cli.py

# Flags shared by both platforms
NUITKA := python -m nuitka \
	--onefile \
	--output-dir=$(DIST_DIR) \
	--assume-yes-for-downloads \
	--include-package=docker_sentinel \
	--include-package=litellm \
	--include-package=google.adk \
	--include-package=google.genai \
	--include-package=anthropic \
	--include-package=openai

.PHONY: build-linux build-windows clean install-dev help

help:
	@echo "Targets: install-dev | build-linux | build-windows | clean"

install-dev:
	pip install -e .[dev]

build-linux:
ifneq ($(findstring Linux,$(UNAME)),Linux)
	$(warning WARNING: build-linux should run on Linux, not $(UNAME))
endif
	$(NUITKA) --output-filename=docker-sentinel-linux-amd64 $(ENTRY)
	@echo "→ $(DIST_DIR)/docker-sentinel-linux-amd64"

build-windows:
ifeq ($(findstring Linux,$(UNAME)),Linux)
	$(warning WARNING: build-windows should run on Windows, not $(UNAME))
endif
	$(NUITKA) --output-filename=docker-sentinel-windows-amd64.exe $(ENTRY)
	@echo "Binary: $(DIST_DIR)/docker-sentinel-windows-amd64.exe"

clean:
	rm -rf $(DIST_DIR) docker_sentinel.build
