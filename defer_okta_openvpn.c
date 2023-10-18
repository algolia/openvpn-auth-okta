//go:build ignore
/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>

#include "openvpn-plugin.h"
#include "build/libokta-openvpn.h"

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;

/*
 * Constants indicating minimum API and struct versions by the functions
 * in this plugin.  Consult openvpn-plugin.h, look for:
 * OPENVPN_PLUGIN_VERSION and OPENVPN_PLUGINv3_STRUCTVER
 *
 * Strictly speaking, this sample code only requires plugin_log, a feature
 * of structver version 1.  However, '1' lines up with ancient versions
 * of openvpn that are past end-of-support.  As such, we are requiring
 * structver '5' here to indicate a desire for modern openvpn, rather
 * than a need for any particular feature found in structver beyond '1'.
 */
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define OPENVPN_PLUGIN_STRUCTVER_MIN 5

/*
 * Our context, where we keep our state.
 */

struct plugin_context {
    char *script_path;
};

/* module name for plugin_log() */
static char *MODULE = "openvpn-plugin-okta";

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 * From https://github.com/OpenVPN/openvpn/blob/master/sample/sample-plugins/log/log_v3.c
 */
static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

void handle_sigchld(int sig)
{
    /*
     * nonblocking wait (WNOHANG) for any child (-1) to come back
     */
    while(waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
}

/* Require a minimum OpenVPN Plugin API */
OPENVPN_EXPORT int
openvpn_plugin_min_version_required_v1()
{
    return OPENVPN_PLUGIN_VERSION_MIN;
}

/* use v3 functions so we can use openvpn's logging and base64 etc. */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct plugin_context *context;

    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;

    /*
     * Allocate our context
     */
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (!context)
    {
        goto error;
    }

    /*
     * Which callbacks to intercept.
     */
    ret->type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    ret->handle = (openvpn_plugin_handle_t *) context;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

error:
    if (context)
    {
        free(context);
    }
    plugin_log(PLOG_NOTE, MODULE, "initialization failed");
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

static int
deferred_auth_handler(const char *argv[], const char *envp[])
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sa.sa_handler = &handle_sigchld;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* we do not want to complicate our lives with having to wait()
     * for child processes (so they are not zombiefied) *and* we MUST NOT
     * fiddle with signal handlers (= shared with openvpn main), so
     * we use double-fork() trick.
     */

    /* fork, sleep, succeed (no "real" auth done = always succeed) */
    pid_t p1 = fork();
    if (p1 < 0)                 /* Fork failed */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (p1 > 0)                 /* parent process */
    {
        waitpid(p1, NULL, 0);
        return OPENVPN_PLUGIN_FUNC_DEFERRED;
    }

    /* first gen child process, fork() again and exit() right away */
    pid_t p2 = fork();
    if (p2 < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: fork(2) failed");
        exit(1);
    }

    if (p2 != 0)                            /* new parent: exit right away */
    {
        exit(0);
    }

    /* (grand-)child process
     *  - return status is communicated by file which we pass as an env
     */

    /* do mighty complicated work that will really take time here... */
    const char *ctrF = get_env("auth_control_file", envp);
    const char *ip = get_env("untrusted_ip", envp);
    const char *cn = get_env("common_name", envp);
    const char *user = get_env("username", envp);
    const char *pass = get_env("password", envp);

    void *handle;
    char *error;
    // Load the Golang c-shared lib
    // dlopen is needed here, otherwise Go runtime wont respect alredy set signal handlers
    handle = dlopen ("libokta-openvpn.so", RTLD_LAZY);
    if (!handle) {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Can not load libokta-openvpn.so");
        exit(127);
    }

    void (*Run)(char*, char*, char*, char*, char*) = dlsym(handle, "Run");
    if ((error = dlerror()) != NULL)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "Error run Run from lib: %s", error);
        exit(1);
    }
    // Call the Golang c-shared lib function
    (*Run)((char*)ctrF, (char*)ip, (char*)cn, (char*)user, (char*)pass);
    exit(0);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int v3structver,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    const char **argv = args->argv;
    const char **envp = args->envp;
    struct plugin_context *context = (struct plugin_context *) args->handle;
    switch (args->type)
    {
        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
           return deferred_auth_handler(argv, envp);

        default:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_?");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free(context);
}
