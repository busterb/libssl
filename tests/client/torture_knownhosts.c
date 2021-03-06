/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include "session.c"
#include "known_hosts.c"

#define TORTURE_KNOWN_HOSTS_FILE "libssh_torture_knownhosts"

#define BADRSA "AAAAB3NzaC1yc2EAAAADAQABAAABAQChm5" \
               "a6Av65O8cKtx5YXOnui3wJnYE6A6J/I4kZSAibbn14Jcl+34VJQwv96f25AxNmo" \
               "NwoiZV93IzdypQmiuieh6s6wB9WhYjU9K/6CkIpNhpCxswA90b3ePjS7LnR9B9J" \
               "slPSbG1H0KC1c5lb7G3utXteXtM+4YvCvpN5VdC4CpghT+p0cwN2Na8Md5vRItz" \
               "YgIytryNn7LLiwYfoSxvWigFrTTZsrVtCOYyNgklmffpGdzuC43wdANvTewfI9G" \
               "o71r8EXmEc228CrYPmb8Scv3mpXFK/BosohSGkPlEHu9lf3YjnknBicDaVtJOYp" \
               "wnXJPjZo2EhG79HxDRpjJHH"
#define BADED25519 "AAAAC3NzaC1lZDI1NTE5AAAAIE74wHmKKkrxpW/dZ69pKPlMoWG9VvWfrNnUkWRQqaDa"

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;
    char known_hosts_file[1024];

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    unlink(known_hosts_file);

    return 0;
}


static void torture_knownhosts_port(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024];
    char buffer[200];
    char *p;
    FILE *file;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    session->opts.port = 1234;
    rc = ssh_write_knownhost(session);
    assert_int_equal(rc, SSH_OK);

    file = fopen(known_hosts_file, "r");
    assert_true(file != NULL);
    p = fgets(buffer, sizeof(buffer), file);
    assert_false(p == NULL);
    fclose(file);
    buffer[sizeof(buffer) - 1] = '\0';
    assert_true(strstr(buffer,"[127.0.0.10]:1234 ") != NULL);

    ssh_disconnect(session);
    ssh_free(session);

    /* Now, connect back to the ssh server and verify the known host line */
    s->ssh.session = session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    session->opts.port = 1234;
    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_fail(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024];
    FILE *file;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_int_equal(rc, SSH_OK);

    file = fopen(known_hosts_file, "w");
    assert_non_null(file);

    fprintf(file, "127.0.0.10 ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_KNOWN_CHANGED);
}

static void torture_knownhosts_other(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024];
    FILE *file;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_int_equal(rc, SSH_OK);

    file = fopen(known_hosts_file, "w");
    assert_non_null(file);
    fprintf(file, "127.0.0.10 ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_FOUND_OTHER);
}

static void torture_knownhosts_other_auto(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024];
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_NOT_KNOWN);

    rc = ssh_write_knownhost(session);
    assert_int_equal(rc, SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    session = ssh_new();
    assert_non_null(session);

    s->ssh.session = session;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    /* ssh-rsa is the default but libssh should try ssh-ed25519 instead */
    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_KNOWN_OK);

    /* session will be freed by session_teardown() */
}

static void torture_knownhosts_conflict(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024];
    FILE *file;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_int_equal(rc, SSH_OK);

    file = fopen(known_hosts_file, "w");
    assert_true(file != NULL);
    fprintf(file, "127.0.0.10 ssh-rsa %s\n", BADRSA);
    fprintf(file, "127.0.0.10 ssh-ed25519 %s\n", BADED25519);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_KNOWN_CHANGED);

    rc = ssh_write_knownhost(session);
    assert_true(rc==SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    session = ssh_new();
    assert_non_null(session);

    s->ssh.session = session;

    ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_is_server_known(session);
    assert_int_equal(rc, SSH_SERVER_KNOWN_OK);

    /* session will be freed by session_teardown() */
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_knownhosts_port,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_fail,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_other,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_other_auto,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_conflict,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}
