FIRMWARE ?= p2im/cnc # Default is set in runner-entrypoint.sh if empty
DOCKER ?= sudo docker

# For tracing only. Specify the range we generage program counter traces for.
# E.g., only the firmware's .text segment (exclude the runtime, Python
# handlers, etc.)
TRACE_CODE_START ?= 0x08000000
TRACE_CODE_END ?= 0x08010000

.PHONY: build run run-fuzz run-covcomp run-sh run-ghidra debug debug-sh trace \
	clean setup-binfmt setup-crossbuild help

help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run: ## Run the Docker container(s) (single firmware invocation)
	@$(DOCKER) compose run --rm surgeon-runner "/runner-entrypoint.sh $(FIRMWARE)"

run-fuzz: ## Run the Docker container(s) (fuzzing campaign invocation)
	@$(DOCKER) compose run --rm surgeon-runner "/runner-entrypoint.sh $(FIRMWARE) fuzz"

run-covcmp: ## Run the Docker container(s) for coverage detection comparison
	@$(DOCKER) compose run --rm \
	  --env AFL_NO_UI=1 \
	  --env SURGEON_AFL_TIMEOUT=5000 \
	  surgeon-runner "/runner-entrypoint.sh $(FIRMWARE) fuzz"

run-sh: ## Run the Docker container(s) and spawn a shell
	@$(DOCKER) compose run --rm surgeon-runner "/bin/bash"

run-ghidra: ## Run the Ghidra analysis scripts on the firmware
	@$(DOCKER) compose run --rm ghidrathon-headless "/ghidrathon-entrypoint.sh $(FIRMWARE)"

clean: ## Remove any Docker residues
	@$(DOCKER) compose down --remove-orphans

debug: ## Start the debugger service (connect with gdb via `target remote :1234`)
	@$(DOCKER) compose run --rm --service-ports surgeon-debugger "/debugger-entrypoint.sh $(FIRMWARE)"

debug-sh: ## Open debug ports and spawn a shell
	@$(DOCKER) compose run --rm --service-ports surgeon-debugger "/bin/bash"

trace: ## Start the fw with qemu-user and collect pc traces filtered by range
	@$(DOCKER) compose run --rm --service-ports surgeon-debugger "/trace-entrypoint.sh $(FIRMWARE) $(TRACE_CODE_START) $(TRACE_CODE_END)"

setup-binfmt: ## Set up  binfmt handlers for executing foreign architecture binaries (see the README for more information)
	@$(DOCKER) run --rm --privileged \
		multiarch/qemu-user-static \
		--reset \
		-p yes

setup-crossbuild: setup-binfmt ## Set Docker up for cross-building / cross-executing images (see the README for more information)
	@$(DOCKER) buildx create \
		--name armcross \
		--node armcross \
		--platform linux/amd64,linux/i368,linux/arm64,linux/arm/v7 \
		--use
