/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "image-varlink.h"
#include "string-util.h"

static int rename_image(Manager *manager, Image *image, const char* new_name) {
        assert(manager);
        assert(image);

        int r;

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        /* The image is cached with its name, hence it is necessary to remove from the cache before renaming. */
        assert_se(hashmap_remove_value(manager->image_cache, image->name, image));

        r = image_rename(image, new_name);
        if (r < 0) {
                image_unref(image);
                return r;
        }

        /* Then save the object again in the cache. */
        assert_se(hashmap_put(manager->image_cache, image->name, image) > 0);
        return 0;
}

int vl_method_update_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        struct params {
                const char *image_name;
                const char *new_name;
                int read_only;
                uint64_t limit;
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct params, image_name), SD_JSON_MANDATORY },
                { "newName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct params, new_name),   0 },
                { "readOnly", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(struct params, read_only),  0 },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(struct params, limit),      0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        struct params p = {
                .new_name = NULL,
                .read_only = -1,
                .limit = UINT64_MAX, /* TODO(ikruglov): is it appropriate placeholder? */
        };
        Image *image;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!image_name_is_valid(p.image_name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        r = manager_acquire_image(manager, p.image_name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.Machine.NoSuchImage", NULL);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-images",
                        (const char**) STRV_MAKE("image", image->name,
                                                 "verb", "update_image"), /* TODO(ikruglov): new polkit verb! */
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (p.new_name) {
                r = rename_image(manager, image, p.new_name);
                if (r == -EINVAL)
                        return sd_varlink_error_invalid_parameter_name(link, "newName");
                if (r < 0)
                        return r;
        }

        if (p.read_only >= 0) {
                r = image_read_only(image, (bool) p.read_only);
                if (r < 0)
                        return r;
        }

        if (p.limit != UINT64_MAX) {
                r = image_set_limit(image, p.limit);
                if (r < 0)
                        return r;
        }

        return sd_varlink_reply(link, NULL);
}
