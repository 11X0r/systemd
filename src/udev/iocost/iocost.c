/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "build.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "devnum-util.h"
#include "device-util.h"
#include "main-func.h"
#include "path-util.h"
#include "pretty-print.h"
#include "verbs.h"

static char *arg_bandwidth_threshold = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_bandwidth_threshold, freep);

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "Iocost", "BandwidthThreshold", config_parse_string, 0, &arg_bandwidth_threshold }
        };
        return config_parse(
                        NULL,
                        "/etc/udev/iocost.conf",
                        NULL,
                        "Iocost\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        NULL,
                        NULL);
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Set up iocost model and qos solutions for block devices\n"
               "\nCommands:\n"
               "  apply <path> [solution]    Apply the known solution for the device, if any, otherwise do nothing\n"
               "  query <path>               Query the known solution for the device\n"
               "\nOptions:\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int get_known_solutions(sd_device *device, char ***ret_solutions) {
        _cleanup_free_ char **s = NULL;
        const char *value;
        int r;

        assert(ret_solutions);

        r = sd_device_get_property_value(device, "IOCOST_SOLUTIONS", &value);
        if (r < 0)
                return r;

        s = strv_split(value, " ");
        if (!s)
                return -ENOMEM;

        *ret_solutions = TAKE_PTR(s);

        return 0;
}

static int choose_solution(char **solutions, const char **ret_name) {
        assert(ret_name);

        if (strv_isempty(solutions))
                return log_error_errno(
                                SYNTHETIC_ERRNO(EINVAL), "IOCOST_SOLUTIONS exists in hwdb but is empty.");

        if (arg_bandwidth_threshold && strv_find(solutions, arg_bandwidth_threshold)) {
                *ret_name = arg_bandwidth_threshold;
                log_debug("Selected solution based on bandwidth threshold: %s", *ret_name);
        } else {
                *ret_name = solutions[0];
                log_debug("Selected first available solution: %s", *ret_name);
        }

        return 0;
}

static int query_named_solution(
                sd_device *device,
                const char *name,
                const char **ret_model,
                const char **ret_qos) {
        _cleanup_strv_free_ char **solutions = NULL;
        _cleanup_free_ char *upper_name = NULL, *qos_key = NULL, *model_key = NULL;
        const char *qos = NULL, *model = NULL;
        int r;

        assert(ret_qos);
        assert(ret_model);

        /* If NULL is passed we query the default solution, which is the first one listed
         * in the SOLUTIONS key or the one specified by the BandwidthThreshold setting.
         */
        if (!name) {
                r = get_known_solutions(device, &solutions);
                if (r < 0)
                        return r == -ENOENT ? 0 : log_error_errno(r, "Failed to query solutions from device: %m");

                r = choose_solution(solutions, &name);
                if (r < 0)
                        return r;
        }

        upper_name = strdup(name);
        if (!upper_name)
                return log_oom();

        ascii_strupper(upper_name);
        string_replace_char(upper_name, '-', '_');

        qos_key = strjoin("IOCOST_QOS_", upper_name);
        if (!qos_key)
                return log_oom();

        model_key = strjoin("IOCOST_MODEL_", upper_name);
        if (!model_key)
                return log_oom();

        r = sd_device_get_property_value(device, qos_key, &qos);
        if (r < 0)
                return r == -ENOENT ? 0 : log_error_errno(r, "Failed to obtain model for iocost solution from device: %m");

        r = sd_device_get_property_value(device, model_key, &model);
        if (r < 0)
                return r == -ENOENT ? 0 : log_error_errno(r, "Failed to obtain model for iocost solution from device: %m");

        *ret_qos = qos;
        *ret_model = model;

        return 0;
}

static int apply_solution_for_path(const char *path, const char *name) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *qos = NULL, *model = NULL;
        const char *qos_params = NULL, *model_params = NULL;
        dev_t devnum;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        r = query_named_solution(device, name, &model_params, &qos_params);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(device, &devnum);
        if (r < 0)
                return log_error_errno(r, "Error getting devnum for device %s: %m", path);

        if (asprintf(&qos, DEVNUM_FORMAT_STR " enable=1 ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), qos_params) < 0)
                return log_oom();

        if (asprintf(&model, DEVNUM_FORMAT_STR " model=linear ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), model_params) < 0)
                return log_oom();

        log_debug("Applying iocost parameters to %s using solution '%s'\n"
                        "\tio.cost.qos: %s\n"
                        "\tio.cost.model: %s\n", path, name ?: "default", qos, model);

        r = cg_set_attribute("io", NULL, "io.cost.qos", qos);
        if (r < 0) {
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to set io.cost.qos: %m");
                return r == -ENOENT ? 0 : r;
        }

        r = cg_set_attribute("io", NULL, "io.cost.model", model);
        if (r < 0) {
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to set io.cost.model: %m");
                return r == -ENOENT ? 0 : r;
        }

        return 0;
}

static int query_solutions_for_path(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_strv_free_ char **solutions = NULL;
        const char *default_solution = NULL;
        const char *model_name = NULL;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        if ((sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &model_name) < 0 &&
             sd_device_get_property_value(device, "ID_MODEL", &model_name) < 0))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Model name for device %s is unknown", path);

        r = get_known_solutions(device, &solutions);
        if (r < 0)
                return log_error_errno(r, "No solutions found for device %s, model name %s on hwdb: %m\n", path, model_name);

        r = choose_solution(solutions, &default_solution);
        if (r < 0)
                return log_error_errno(
                                r,
                                "No solutions found for device %s, model name %s on hwdb: %m",
                                path,
                                model_name);

        log_info("Known solutions for %s model name: %s\n", path, model_name);
        log_info("Preferred bandwidth threshold: %s", arg_bandwidth_threshold);
        log_info("Solution that would be applied: %s", default_solution);
        STRV_FOREACH(s, solutions) {
                const char *model = NULL, *qos = NULL;

                r = query_named_solution(device, *s, &model, &qos);
                if (r < 0 || !model || !qos)
                        continue;

                log_info("%s: io.cost.qos: %s\n"
                         "%s: io.cost.model: %s", *s, qos, *s, model);
        }

        return 0;
}

static int verb_query(int argc, char *argv[], void *userdata) {
        return query_solutions_for_path(ASSERT_PTR(argv[1]));
}

static int verb_apply(int argc, char *argv[], void *userdata) {
        return apply_solution_for_path(
                        ASSERT_PTR(argv[1]),
                        argc > 2 ? ASSERT_PTR(argv[2]) : NULL);
}

static int iocost_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "query", 2, 2, 0, verb_query },
                { "apply", 2, 3, 0, verb_apply },
                {},
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) parse_config();

        if (!arg_bandwidth_threshold) {
                arg_bandwidth_threshold = strdup("isolated-bandwidth");
                if (!arg_bandwidth_threshold)
                        return log_oom();
        }

        log_debug("Preferred bandwidth threshold: %s.", arg_bandwidth_threshold);

        r = iocost_main(argc, argv);

        return r;
}

DEFINE_MAIN_FUNCTION(run);
