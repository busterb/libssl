/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <poll.h>
#include <termios.h>
#include <fcntl.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#include <signal.h>
#include <stdlib.h>
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>

#ifdef HAVE_ARGP_H
#include <argp.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define USER "myuser"
#define PASS "mypassword"
#define BUF_SIZE 1048576
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)
#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

static int error = 0;

/* A userdata struct for channel. */
struct channel_data_struct {
    /* pid of the child process the channel will spawn. */
    pid_t pid;
    /* For PTY allocation */
    socket_t pty_master;
    socket_t pty_slave;
    /* For communication with the child process. */
    socket_t child_stdin;
    socket_t child_stdout;
    /* Only used for subsystem and exec requests. */
    socket_t child_stderr;
    /* Event which is used to poll the above descriptors. */
    ssh_event event;
    /* Terminal size struct. */
    struct winsize *winsize;
};

struct session_data_struct {
    /* Pointer to the channel the session will allocate. */
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
};

struct winsize wsize = {
	.ws_row = 0,
	.ws_col = 0,
	.ws_xpixel = 0,
	.ws_ypixel = 0
};

struct channel_data_struct channel_data = {
	.pid = 0,
	.pty_master = -1,
	.pty_slave = -1,
	.child_stdin = -1,
	.child_stdout = -1,
	.child_stderr = -1,
	.event = NULL,
	.winsize = &wsize
};

static int auth_password(ssh_session session, const char *user,
                         const char *pass, void *userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    (void) session;

    if (strcmp(user, USER) == 0 && strcmp(pass, PASS) == 0) {
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }

    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

static int auth_gssapi_mic(ssh_session session, const char *user, const char *principal, void *userdata){
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    ssh_gssapi_creds creds = ssh_gssapi_get_creds(session);
    (void)userdata;
    printf("Authenticating user %s with gssapi principal %s\n",user, principal);
    if (creds != NULL)
        printf("Received some gssapi credentials\n");
    else
        printf("Not received any forwardable creds\n");
    printf("authenticated\n");
    sdata->authenticated++;
    return SSH_AUTH_SUCCESS;
}

static int data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    (void) session;
    (void) channel;
    (void) is_stderr;

    if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
        return 0;
    }

    return write(cdata->child_stdin, (char *) data, len);
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char *term, int cols, int rows, int py, int px,
                       void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void) session;
    (void) channel;
    (void) term;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL,
                cdata->winsize) != 0) {
        fprintf(stderr, "Failed to open pty\n");
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols,
                      int rows, int py, int px, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void) session;
    (void) channel;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (cdata->pty_master != -1) {
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
    }

    return SSH_ERROR;
}

static int exec_pty(const char *mode, const char *command,
                    struct channel_data_struct *cdata) {
    switch(cdata->pid = fork()) {
        case -1:
            close(cdata->pty_master);
            close(cdata->pty_slave);
            fprintf(stderr, "Failed to fork\n");
            return SSH_ERROR;
        case 0:
            close(cdata->pty_master);
            if (login_tty(cdata->pty_slave) != 0) {
                exit(1);
            }
            execl("/bin/sh", "sh", mode, command, NULL);
            exit(0);
        default:
            close(cdata->pty_slave);
            /* pty fd is bi-directional */
            cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }
    return SSH_OK;
}

static int exec_nopty(const char *command, struct channel_data_struct *cdata) {
    int in[2], out[2], err[2];

    /* Do the plumbing to be able to talk with the child process. */
    if (pipe(in) != 0) {
        goto stdin_failed;
    }
    if (pipe(out) != 0) {
        goto stdout_failed;
    }
    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    switch(cdata->pid = fork()) {
        case -1:
            goto fork_failed;
        case 0:
            /* Finish the plumbing in the child process. */
            close(in[1]);
            close(out[0]);
            close(err[0]);
            dup2(in[0], STDIN_FILENO);
            dup2(out[1], STDOUT_FILENO);
            dup2(err[1], STDERR_FILENO);
            close(in[0]);
            close(out[1]);
            close(err[1]);
            /* exec the requested command. */
            execl("/bin/sh", "sh", "-c", command, NULL);
            exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

static int exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;


    (void) session;
    (void) channel;

    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-c", command, cdata);
    }
    return exec_nopty(command, cdata);
}

static int subsystem_request(ssh_session session, ssh_channel channel,
                             const char *subsystem, void *userdata) {
    /* subsystem requests behave simillarly to exec requests. */
    if (strcmp(subsystem, "sftp") == 0) {
        return exec_request(session, channel, SFTP_SERVER_PATH, userdata);
    }
    return SSH_ERROR;
}

static int shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-l", NULL, cdata);
    }
    /* Client requested a shell without a pty, let's pretend we allow that */
    return SSH_OK;
}

struct session_data_struct session_data = {
	.channel = NULL,
	.auth_attempts = 0,
	.authenticated = 0
};

struct ssh_channel_callbacks_struct channel_cb = {
	.userdata = &channel_data,
	.channel_pty_request_function = pty_request,
	.channel_pty_window_change_function = pty_resize,
	.channel_shell_request_function = shell_request,
	.channel_exec_request_function = exec_request,
	.channel_data_function = data_function,
	.channel_subsystem_request_function = subsystem_request
};

static ssh_channel new_session_channel(ssh_session session, void *userdata){
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

static int process_stdout(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write(channel, buf, n);
        }
    }

    return n;
}

static int process_stderr(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write_stderr(channel, buf, n);
        }
    }

    return n;
}

#ifdef HAVE_ARGP_H
const char *argp_program_version = "libssh server example "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<libssh@libssh.org>";

/* Program documentation. */
static char doc[] = "libssh -- a Secure Shell protocol implementation";

/* A description of the arguments we accept. */
static char args_doc[] = "BINDADDR";

/* The options we understand. */
static struct argp_option options[] = {
    {
        .name  = "port",
        .key   = 'p',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the port to bind.",
        .group = 0
    },
    {
        .name  = "hostkey",
        .key   = 'k',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the host key.",
        .group = 0
    },
    {
        .name  = "dsakey",
        .key   = 'd',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the dsa key.",
        .group = 0
    },
    {
        .name  = "rsakey",
        .key   = 'r',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the rsa key.",
        .group = 0
    },
    {
        .name  = "verbose",
        .key   = 'v',
        .arg   = NULL,
        .flags = 0,
        .doc   = "Get verbose output.",
        .group = 0
    },
    {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
     * know is a pointer to our arguments structure.
     */
    ssh_bind sshbind = state->input;

    switch (key) {
        case 'p':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, arg);
            break;
        case 'd':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, arg);
            break;
        case 'k':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, arg);
            break;
        case 'r':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg);
            break;
        case 'v':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 1) {
                /* Too many arguments. */
                argp_usage (state);
            }
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg);
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) {
                /* Not enough arguments. */
                argp_usage (state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
#endif /* HAVE_ARGP_H */

int main(int argc, char **argv){
    ssh_session session;
    ssh_bind sshbind;
    ssh_event mainloop;
    struct ssh_server_callbacks_struct cb = {
        .userdata = &session_data,
        .auth_password_function = auth_password,
        .auth_gssapi_mic_function = auth_gssapi_mic,
        .channel_open_request_session_function = new_session_channel
    };

    int r;
	int rc;

    sshbind=ssh_bind_new();
    session=ssh_new();

    //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

#ifdef HAVE_ARGP_H
    /*
     * Parse our arguments; every option seen by parse_opt will
     * be reflected in arguments.
     */
    argp_parse (&argp, argc, argv, 0, 0, sshbind);
#else
    (void) argc;
    (void) argv;
#endif

    if(ssh_bind_listen(sshbind)<0){
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }
    r=ssh_bind_accept(sshbind,session);
    if(r==SSH_ERROR){
        printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
        return 1;
    }
    ssh_callbacks_init(&cb);
	ssh_callbacks_init(&channel_cb);
    ssh_set_server_callbacks(session, &cb);

    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }
    ssh_set_auth_methods(session,SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_GSSAPI_MIC);
    mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);

    while (session_data.authenticated == 0 || session_data.channel == NULL){
        if(error)
            break;
        r = ssh_event_dopoll(mainloop, -1);
        if (r == SSH_ERROR){
            printf("Error : %s\n",ssh_get_error(session));
            ssh_disconnect(session);
            return 1;
        }
    }

	ssh_set_channel_callbacks(session_data.channel, &channel_cb);

    if(error){
        printf("Error, exiting loop\n");
    } else
        printf("Authenticated and got a channel\n");
    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR) {
          ssh_channel_close(session_data.channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (channel_data.event != NULL || channel_data.pid == 0) {
            continue;
        }
        /* Executed only once, once the child process starts. */
        channel_data.event = mainloop;
        /* If stdout valid, add stdout to be monitored by the poll event. */
        if (channel_data.child_stdout != -1) {
            if (ssh_event_add_fd(mainloop, channel_data.child_stdout, POLLIN, process_stdout,
                                 session_data.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stdout to poll context\n");
                ssh_channel_close(session_data.channel);
            }
        }

        /* If stderr valid, add stderr to be monitored by the poll event. */
        if (channel_data.child_stderr != -1){
            if (ssh_event_add_fd(mainloop, channel_data.child_stderr, POLLIN, process_stderr,
                                 session_data.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stderr to poll context\n");
                ssh_channel_close(session_data.channel);
            }
        }
    } while(ssh_channel_is_open(session_data.channel) &&
            (channel_data.pid == 0 || waitpid(channel_data.pid, &rc, WNOHANG) == 0));

    close(channel_data.pty_master);
    close(channel_data.child_stdin);
    close(channel_data.child_stdout);
    close(channel_data.child_stderr);

    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */
    ssh_event_remove_fd(mainloop, channel_data.child_stdout);
    ssh_event_remove_fd(mainloop, channel_data.child_stderr);

    /* If the child process exited. */
    if (kill(channel_data.pid, 0) < 0 && WIFEXITED(rc)) {
        rc = WEXITSTATUS(rc);
        ssh_channel_request_send_exit_status(session_data.channel, rc);
    /* If client terminated the channel or the process did not exit nicely,
     * but only if something has been forked. */
    } else if (channel_data.pid > 0) {
        kill(channel_data.pid, SIGKILL);
    }

    ssh_channel_send_eof(session_data.channel);
    ssh_channel_close(session_data.channel);

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (int n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(mainloop, 100);
    }

	/*
    do{
        i=ssh_channel_read(session_data.channel,buf, 2048, 0);
        if(i>0) {
            ssh_channel_write(session_data.channel, buf, i);
            if (write(1,buf,i) < 0) {
                printf("error writing to buffer\n");
                return 1;
            }
            if (buf[0] == '\x0d') {
                if (write(1, "\n", 1) < 0) {
                    printf("error writing to buffer\n");
                    return 1;
                }
                ssh_channel_write(session_data.channel, "\n", 1);
            }
        }
    } while (i>0);
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
	*/
    return 0;
}

