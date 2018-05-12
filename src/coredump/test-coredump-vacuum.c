/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek
***/

#include <stdlib.h>

#include "coredump-vacuum.h"

int main(int argc, char *argv[]) {

        if (coredump_vacuum(-1, (uint64_t) -1, 70 * 1024) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
