/*
 * auth-script OpenVPN plugin
 * 
 * Runs an external script to decide whether to authenticate a user or not.
 * Useful for checking 2FA on VPN auth attempts as it doesn't block the main
 * openvpn process, unlike passing the script to --auth-user-pass-verify.
 * 
 * Functions required to be a valid OpenVPN plugin:
 * openvpn_plugin_open_v3
 * openvpn_plugin_func_v3
 * openvpn_plugin_close_v1
 */

/* Required to use strdup */
#define __EXTENSIONS__

/********** Includes */
#include <stddef.h>
#include <errno.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/********** Constants */
/* For consistency in log messages */
#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0

/* Where we store our own settings/state */
struct plugin_context 
{
        plugin_log_t plugin_log;
        const char *argv[];
};

void handle_sigchld(int sig)
{
    /*
     * nonblocking wait (WNOHANG) for any child (-1) to come back
     */
    (void)(sig); // to skip unused parameter ‘sig‘ error
    while(waitpid(-1, 0, WNOHANG) > 0) {}
}

/* Handle an authentication request */
static int deferred_handler(struct plugin_context *context, 
                const char *envp[])
{
        plugin_log_t log = context->plugin_log;
        pid_t pid;

        log(PLOG_DEBUG, PLUGIN_NAME, 
                        "Deferred handler using script_path=%s", 
                        context->argv[SCRIPT_NAME_IDX]);

        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        sa.sa_handler = &handle_sigchld;

        if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Child Control - Spin off our sucessor */
        pid = fork();

        if (pid < 0) {
            log(PLOG_ERR, PLUGIN_NAME,
                "pid failed < 0 check, got %d", pid);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        } else if (pid > 0) {
            /*
             * We're the parent.  Tell openvpn we're deferring.
             */
            return OPENVPN_PLUGIN_FUNC_DEFERRED;
        } else {
            /*
             * We're the child.  Invoke the script.
             */

            /* Daemonize */
            umask(0);
            setsid();

            /* Close open files and move to root */
            int chdir_rc = chdir("/");
            if (chdir_rc < 0)
                log(PLOG_DEBUG, PLUGIN_NAME,
                    "Error trying to change pwd to \'/\'");
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);

            int execve_rc = execve(context->argv[0],
                                   (char *const*)context->argv,
                                   (char *const*)envp);
            if ( execve_rc == -1 ) {
                switch(errno) {
                    case E2BIG:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: E2BIG");
                        break;
                    case EACCES:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: EACCES");
                        break;
                    case EAGAIN:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: EAGAIN");
                        break;
                    case EFAULT:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: EFAULT");
                        break;
                    case EINTR:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: EINTR");
                        break;
                    case EINVAL:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: EINVAL");
                        break;
                    case ELOOP:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ELOOP");
                        break;
                    case ENAMETOOLONG:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENAMETOOLONG");
                        break;
                    case ENOENT:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENOENT");
                        break;
                    case ENOEXEC:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENOEXEC");
                        break;
                    case ENOLINK:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENOLINK");
                        break;
                    case ENOMEM:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENOMEM");
                        break;
                    case ENOTDIR:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ENOTDIR");
                        break;
                    case ETXTBSY:
                        log(PLOG_DEBUG, PLUGIN_NAME,
                            "Error trying to exec: ETXTBSY");
                        break;
                    default:
                        log(PLOG_ERR, PLUGIN_NAME,
                            "Error trying to exec: unknown, errno: %d",
                            errno);
                }
            }
            exit(EXIT_FAILURE);
        }
}

/* We require OpenVPN Plugin API v3 */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1()
{
        return OPENVPN_PLUGIN_VERSION_MIN;
}

/* 
 * Handle plugin initialization
 *        arguments->argv[0] is path to shared lib
 *        arguments->argv[1] is expected to be path to script
 */
OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                struct openvpn_plugin_args_open_in const *arguments,
                struct openvpn_plugin_args_open_return *retptr)
{
        plugin_log_t log = arguments->callbacks->plugin_log;
        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

        struct plugin_context *context = NULL;

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Tell OpenVPN we want to handle these calls */
        retptr->type_mask = OPENVPN_PLUGIN_MASK(
                        OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

        
        /*
         * Determine the size of the arguments provided so we can allocate and
         * argv array of appropriate length.
         */
        size_t arg_size = 0;
        for (int arg_idx = 1; arguments->argv[arg_idx]; arg_idx++)
                arg_size += strlen(arguments->argv[arg_idx]);


        /* 
         * Plugin init will fail unless we create a handler, so we'll store our
         * script path and it's arguments there as we have to create it anyway. 
         */
        context = (struct plugin_context *) malloc(
                        sizeof(struct plugin_context) + arg_size);
        memset(context, 0, sizeof(struct plugin_context) + arg_size);
        context->plugin_log = log;


        /* 
         * Check we've been handed a script path to call
         * This comes directly from openvpn config file:
         *           plugin /path/to/auth.so /path/to/auth/script.sh
         *
         * IDX 0 should correspond to the library, IDX 1 should be the
         * script, and any subsequent entries should be arguments to the script.
         *
         * Note that if arg_size is 0 no script argument was included.
         */
        if (arg_size > 0) {
                memcpy(&context->argv, &arguments->argv[1], arg_size);

                log(PLOG_DEBUG, PLUGIN_NAME, 
                                "script_path=%s", 
                                context->argv[SCRIPT_NAME_IDX]);
        } else {
                free(context);
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: no script_path specified in config file");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }        

        /* Pass state back to OpenVPN so we get handed it back later */
        retptr->handle = (openvpn_plugin_handle_t) context;

        log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Called when we need to handle OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY calls */
OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                struct openvpn_plugin_args_func_in const *arguments,
                struct openvpn_plugin_args_func_return *retptr)
{
        (void)retptr; /* Squish -Wunused-parameter warning */
        struct plugin_context *context = 
                (struct plugin_context *) arguments->handle;
        plugin_log_t log = context->plugin_log;

        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_func_v3");

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if(arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
                log(PLOG_DEBUG, PLUGIN_NAME,
                                "Handling auth with deferred script");
                return deferred_handler(context, arguments->envp);
        } else
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
        struct plugin_context *context = (struct plugin_context *) handle;
        free(context);
}
