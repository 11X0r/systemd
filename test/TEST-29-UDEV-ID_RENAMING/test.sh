#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="UDEV ID_RENAMING property"
IMAGE_NAME="udev-id-renaming"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=300

test_append_files() {
    (
        instmods dummy
        generate_module_dependencies
    )
}

do_test "$@" 29
