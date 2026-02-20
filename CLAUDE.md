# CLAUDE.md — Guide for AI Assistants Working on systemd

## Project Overview

systemd is a suite of system and service management daemons, libraries, and utilities for Linux.
It provides PID 1 (the init system), service management, logging (journald), networking (networkd),
DNS resolution (resolved), device management (udevd), and many other core OS components.

- **Language**: C (gnu17 with GNU extensions), plus Python tooling and shell scripts
- **License**: LGPL-2.1-or-later (SPDX header required in all source files)
- **Build system**: Meson (>= 0.62.0)
- **Repository**: https://github.com/systemd/systemd

## Repository Structure

```
src/                    # All source code
├── basic/              # Fundamental utility library (string, path, memory, fd helpers)
├── shared/             # Shared library code used across multiple components
├── fundamental/        # Very basic definitions shared with bootloader (EFI) code
├── core/               # systemd PID 1 service manager
├── systemd/            # Public API headers (sd-bus, sd-event, sd-journal, etc.)
├── libsystemd/         # libsystemd.so implementation
├── libsystemd-network/ # Network protocol library (DHCP, LLDP, etc.)
├── libudev/            # libudev.so implementation (maintained, no new symbols)
├── journal/            # journald logging daemon
├── network/            # systemd-networkd
├── resolve/            # systemd-resolved
├── login/              # systemd-logind
├── udev/               # systemd-udevd device manager
├── nspawn/             # systemd-nspawn container manager
├── boot/               # systemd-boot EFI bootloader and sd-stub
├── home/               # systemd-homed
├── machine/            # systemd-machined
├── portable/           # systemd-portabled
├── analyze/            # systemd-analyze
├── run/                # systemd-run
├── systemctl/          # systemctl
├── test/               # Unit tests (test-*.c files)
├── fuzz/               # Fuzz test harnesses
├── ...                 # Many more component directories
test/                   # Integration tests and test data
├── integration-tests/  # Integration test suites
├── fuzz/               # Fuzz corpora
tools/                  # Development and build helper scripts
man/                    # Man page sources (XML, 2-space indent)
docs/                   # Documentation (CODING_STYLE.md, CONTRIBUTING.md, HACKING.md)
coccinelle/             # ~60 Coccinelle semantic patches enforcing code patterns
mkosi/                  # mkosi configuration for building/testing OS images
units/                  # systemd unit files
catalog/                # Journal message catalog entries
hwdb.d/                 # Hardware database files
shell-completion/       # Bash/zsh completions
po/                     # Translations
```

## Building

systemd uses the Meson build system with mkosi for development environments.

### Quick build with mkosi (recommended)

```sh
mkosi -f genkey                                            # One-time: generate signing keys
mkosi -f box -- meson setup -Dbpf-framework=disabled build # Configure
mkosi -f box -- meson compile -C build                     # Build
mkosi -f box -- meson test -C build --print-errorlogs      # Run unit tests
```

### Direct build (if dependencies are available)

```sh
meson setup build
meson compile -C build
meson test -C build
```

### Key build options

- `-Dmode=developer` (default): Enables extra checks for development
- `-Dmode=release`: Disables development-only checks
- Build standard: `c_std=gnu17`

## Testing

### Unit tests

- Located in `src/test/test-*.c` — matching files in `src/basic/` and `src/shared/`
- Example: `src/test/test-path-util.c` tests functions in `src/basic/path-util.c`
- Run: `meson test -C build --print-errorlogs`
- Use assertion macros from `tests.h`: `ASSERT_OK()`, `ASSERT_GE()`, `ASSERT_OK_ERRNO()`, etc.

### Integration tests

- Located in `test/integration-tests/`
- Excluded from default test suite (run separately)
- Build and boot an OS image: `mkosi -f box -- meson compile -C build mkosi && mkosi vm`

### Fuzz tests

- Harnesses in `src/fuzz/`
- Corpora in `test/fuzz/`
- Supports both OSS-Fuzz and libFuzzer

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `build-test.yml` — Main build and test pipeline
- `unit-tests.yml` — Unit test runs
- `unit-tests-musl.yml` — Tests with musl libc
- `mkosi.yml` — Full OS image build and integration tests
- `codeql.yml`, `coverity.yml` — Static analysis
- `coverage.yml` — Code coverage
- `linter.yml` — Code linting
- `differential-shellcheck.yml` — Shell script checking

## C Coding Style

Full reference: `docs/CODING_STYLE.md`

### Formatting

- **8-space indentation**, no tabs (2-space for man pages, 4-space for shell scripts)
- **Max line length**: ~109 characters
- **Opening braces** on same line as statement (`void foo() {`)
- **Single-line if**: no braces (`if (x)\n        do_thing();`)
- **else** on same line as closing brace (`} else`)
- **Function parameters** split across lines use **double indentation (16 spaces)**
- **Pointer type**: asterisk with the type (`const char* foo(...)` not `const char *foo(...)`)
- No space before function call parens (`foo()` not `foo ()`)
- Use `for (;;)` for infinite loops, not `while (1)`
- No Yoda comparisons: `if (a == 7)` not `if (7 == a)`

### Naming

- **Functions and variables**: `snake_case`
- **Types/structs**: `PascalCase`
- **Macros/constants**: `UPPER_CASE`
- **Command-line parameters**: prefix with `arg_`
- **Return parameters** (success): prefix with `ret_`
- **Return parameters** (failure): prefix with `reterr_`
- **Public API functions**: prefix with `sd_`, marked `_public_`

### License header

Every source file must start with:
```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */
```

### Header include order

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <system-headers.h>      /* 1. External/system headers (alphabetical) */

#include "sd-bus.h"              /* 2. Public sd-* headers (alphabetical) */

#include "alloc-util.h"          /* 3. Internal headers (alphabetical) */
#include "string-util.h"
```

### Error handling

- Return negative errno values: `return -EINVAL;`
- Combined log + return: `return log_error_errno(r, "Failed to ...: %m");`
- Synthetic errors: `return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to ...");`
- Convert libc returns: `r = RET_NERRNO(open(...));`
- Cast intentionally ignored errors: `(void) unlink("/foo/bar");`
- Library code (`src/basic/`, `src/shared/`) must NOT log (except at DEBUG level)

### Memory management

- Use cleanup attributes: `_cleanup_free_ char *buf = NULL;`
- Use `_cleanup_(xyz_freep)` for custom destructors
- Use `new()`, `new0()` instead of raw `malloc()`/`calloc()`
- Use `mfree()` to free and return NULL
- Never use raw `alloca()`/`strdupa()` — use `alloca_safe()`/`strdupa_safe()`
- Use C99 struct initializers instead of `memset()`

### Destructors

- Must accept `NULL` as a no-op
- Must return the same type (returning `NULL`)
- Naming: `xyz_free()` (full), `xyz_done()` (members only), `xyz_clear()` (reset for reuse)
- Ref counting: `xyz_ref()` / `xyz_unref()`

### Variable declarations

- Declare where initializable; avoid big lists at function top
- Exception: `int r` for error codes goes at the top (declared last)
- Don't mix declarations with function calls

### Function parameter order

1. Mutable object being operated on
2. Input parameters (use `const` for pointers)
3. `ret_` output parameters (set on success)
4. `reterr_` output parameters (set on failure)

### Enums

```c
typedef enum FoobarMode {
        FOOBAR_AAA,
        FOOBAR_BBB,
        _FOOBAR_MAX,
        _FOOBAR_INVALID = -EINVAL,
} FoobarMode;
```

Flags enums use `1 << N` syntax with aligned values.

### Functions to avoid

| Avoid | Use instead |
|-------|-------------|
| `memset(..., 0, ...)` | `zero()` or C99 initializers |
| `strcmp()`/`strncmp()` | `streq()`/`strneq()` |
| `strtol()`/`atoi()` | `safe_atoli()`/`safe_atou32()` |
| `htonl()`/`ntohl()` | `htobe32()`/`htobe16()` |
| `dup()` | `fcntl(fd, F_DUPFD_CLOEXEC, 3)` |
| `fgets()` | `read_line()` |
| `exit()` | Return from main; `_exit()` in children |
| `basename()`/`dirname()` | `path_extract_filename()`/`path_extract_directory()` |
| `strdupa()` | `strdupa_safe()` |
| `getenv()` | `secure_getenv()` (default in library code) |

### File descriptors

- Always use `O_CLOEXEC` / `SOCK_CLOEXEC` / `MSG_CMSG_CLOEXEC`
- Use `O_NONBLOCK` when opening user-specified files
- Prefer `openat()`-style APIs

### Types

- Use `unsigned` not `unsigned int`
- Use `uint8_t` for bytes, `char` for characters
- Use `usec_t` for time values
- Never use `off_t` — use `uint64_t`
- Use `bool` internally, `int` in public APIs
- Prefer `double` over `float`

## Python Style

- Configured via `ruff.toml` and `mypy.ini`
- Line length: 109 characters
- Target: Python 3.7+ (ruff), 3.9+ (mypy)
- Single quotes preferred
- Strict mypy type checking enabled
- Lint rules: E, F, I, UP (error, pyflakes, import, upgrade)

## Commit Messages

- Prefix with component name: `journal: `, `nspawn: `, `networkd: `, etc.
- No `Signed-Off-By:` lines
- AI-generated contributions must be disclosed in commit messages and PR descriptions
- Comments explaining "why" belong in the code itself, not just commit messages

## Key Development Patterns

### Coccinelle enforcement

~60 semantic patches in `coccinelle/` enforce patterns automatically:
- Memory: `memset` → `zero()`, `close()` → `safe_close()`, `free()+NULL` → `mfree()`
- Strings: use `streq()`, `isempty()`, `strjoina()`
- Error handling: standardize errno patterns
- FD handling: `dup()` → `fcntl(F_DUPFD_CLOEXEC, 3)`

### Forward declaration headers

To avoid circular header dependencies and speed up incremental builds:
- `src/basic/basic-forward.h`
- `src/libsystemd/sd-forward.h`
- `src/shared/shared-forward.h`
- Component-specific: e.g. `resolved-forward.h`

Always include the corresponding forward header in header files first.

### Threading

Avoid threads, especially in PID 1. Use worker processes with `execve()` instead.
Write thread-safe code for library paths using `thread_local` / `pthread_once()`.

### Testing conventions

- Add unit tests for new shared functionality in `src/test/test-<module>.c`
- Use `ASSERT_OK()`, `ASSERT_GE()`, `ASSERT_OK_ERRNO()` from `tests.h`
- Run the test suite locally before submitting PRs
- When modifying tests, convert to new assertion macros if not already using them

### Public API (`libsystemd.so`)

- Never break ABI/API — add new interfaces instead
- Functions must be prefixed with `sd_` and marked `_public_`
- Use `assert_return()` for input validation
- Use `int` for booleans (C89 compatibility), `_SD_ENUM_FORCE_S64()` for enums

## Useful References

- [Coding Style](docs/CODING_STYLE.md) — comprehensive formatting and semantic rules
- [Contributing](docs/CONTRIBUTING.md) — PR and issue guidelines
- [Hacking Guide](docs/HACKING.md) — build, test, and debug workflows with mkosi
- [Testing with Sanitizers](docs/TESTING_WITH_SANITIZERS.md) — ASan/UBSan/etc. setup
