export V ?= 0

OUTPUT_DIR := $(CURDIR)/out

AUTOSAR_LIST := $(subst /,,$(dir $(wildcard */Makefile)))

.PHONY: all
all: autosar prepare-for-rootfs

.PHONY: clean
clean: autosar-clean prepare-for-rootfs-clean

autosar:
	@for each in $(AUTOSAR_LIST); do \
		$(MAKE) -C $$each CROSS_COMPILE="$(HOST_CROSS_COMPILE)" || exit -1; \
	done

autosar-clean:
	@for each in $(AUTOSAR_LIST); do \
		$(MAKE) -C $$each clean || exit -1; \
	done

prepare-for-rootfs: autosar
	@echo "Copying autosar CA and TA binaries to $(OUTPUT_DIR)..."
	@mkdir -p $(OUTPUT_DIR)
	@mkdir -p $(OUTPUT_DIR)/ta
	@mkdir -p $(OUTPUT_DIR)/ca
	@for each in $(AUTOSAR_LIST); do \
		if [ -e $$each/host/optee_autosar_$$each ]; then \
			cp -p $$each/host/optee_autosar_$$each $(OUTPUT_DIR)/ca/; \
		fi; \
		cp -pr $$each/ta/*.ta $(OUTPUT_DIR)/ta/; \
	done

prepare-for-rootfs-clean:
	@rm -rf $(OUTPUT_DIR)/ta
	@rm -rf $(OUTPUT_DIR)/ca
	@rmdir --ignore-fail-on-non-empty $(OUTPUT_DIR) || test ! -e $(OUTPUT_DIR)
