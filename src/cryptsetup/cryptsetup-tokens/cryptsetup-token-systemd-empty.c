/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "macro.h"
#include "version.h"

#define TOKEN_NAME "systemd-empty"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {

        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR " systemd-v" STRINGIFY(PROJECT_VERSION) " (" GIT_VERSION ")";
}

_public_ int cryptsetup_token_open_pin(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                const char *pin,
                size_t pin_size,
                char **ret_password, /* freed by cryptsetup_token_buffer_free */
                size_t *ret_password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        _cleanup_free_ char *p = NULL;

        assert(token >= 0);
        assert(!pin || pin_size > 0);
        assert(ret_password);
        assert(ret_password_len);

        p = strdup("");
        if (!p)
                return crypt_log_oom(cd);

        *ret_password = TAKE_PTR(p);
        *ret_password_len = 0;
        return 0;
}

/*
 * This function is called from within following libcryptsetup calls
 * provided conditions further below are met:
 *
 * crypt_activate_by_token(), crypt_activate_by_token_type(type == 'systemd-empty'):
 *
 * - token is assigned to at least one luks2 keyslot eligible to activate LUKS2 device
 *   (alternatively: name is set to null, flags contains CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY
 *   and token is assigned to at least single keyslot).
 *
 * - if plugin defines validate function (systemd-empty does not) it must have passed the
 *   check (aka return 0)
 */
_public_ int cryptsetup_token_open(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                char **ret_password, /* freed by cryptsetup_token_buffer_free */
                size_t *ret_password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        return cryptsetup_token_open_pin(cd, token, NULL, 0, ret_password, ret_password_len, usrptr);
}

/*
 * libcryptsetup callback for memory deallocation of 'password' parameter passed in
 * any crypt_token_open_* plugin function
 */
_public_ void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len) {
        free(buffer);
}
