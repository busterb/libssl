/*
 * packet.c - packet building functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013 by Aris Adamantiadis
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/socket.h"
#include "libssh/channels.h"
#include "libssh/misc.h"
#include "libssh/session.h"
#include "libssh/messages.h"
#include "libssh/pcap.h"
#include "libssh/kex.h"
#include "libssh/auth.h"
#include "libssh/gssapi.h"

static ssh_packet_callback default_packet_handlers[]= {
  ssh_packet_disconnect_callback,          // SSH2_MSG_DISCONNECT                 1
  ssh_packet_ignore_callback,              // SSH2_MSG_IGNORE	                    2
  ssh_packet_unimplemented,                // SSH2_MSG_UNIMPLEMENTED              3
  ssh_packet_ignore_callback,              // SSH2_MSG_DEBUG	                    4
#if WITH_SERVER
  ssh_packet_service_request,              // SSH2_MSG_SERVICE_REQUEST	          5
#else
  NULL,
#endif
  ssh_packet_service_accept,               // SSH2_MSG_SERVICE_ACCEPT             6
  ssh_packet_ext_info,                     // SSH2_MSG_EXT_INFO                   7
  NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL,      //                                     8-19
  ssh_packet_kexinit,                      // SSH2_MSG_KEXINIT	                  20
  ssh_packet_newkeys,                      // SSH2_MSG_NEWKEYS                    21
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL,                                    //                                     22-29
#if WITH_SERVER
  ssh_packet_kexdh_init,                   // SSH2_MSG_KEXDH_INIT                 30
                                           // SSH2_MSG_KEX_DH_GEX_REQUEST_OLD     30
#else
  NULL,
#endif
  ssh_packet_dh_reply,                     // SSH2_MSG_KEXDH_REPLY                31
                                           // SSH2_MSG_KEX_DH_GEX_GROUP           31
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_INIT            32
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_REPLY           33
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_REQUEST         34
  NULL, NULL, NULL, NULL, NULL, NULL,	NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL,                                    //                                     35-49
#if WITH_SERVER
  ssh_packet_userauth_request,             // SSH2_MSG_USERAUTH_REQUEST           50
#else
  NULL,
#endif
  ssh_packet_userauth_failure,             // SSH2_MSG_USERAUTH_FAILURE           51
  ssh_packet_userauth_success,             // SSH2_MSG_USERAUTH_SUCCESS           52
  ssh_packet_userauth_banner,              // SSH2_MSG_USERAUTH_BANNER            53
  NULL,NULL,NULL,NULL,NULL,NULL,           //                                     54-59
  ssh_packet_userauth_pk_ok,               // SSH2_MSG_USERAUTH_PK_OK             60
                                           // SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ  60
                                           // SSH2_MSG_USERAUTH_INFO_REQUEST	  60
                                           // SSH2_MSG_USERAUTH_GSSAPI_RESPONSE   60
  ssh_packet_userauth_info_response,       // SSH2_MSG_USERAUTH_INFO_RESPONSE     61
                                           // SSH2_MSG_USERAUTH_GSSAPI_TOKEN      61
  NULL,                                    //                                     62
  NULL,                             // SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE 63
  NULL,                                    // SSH2_MSG_USERAUTH_GSSAPI_ERROR      64
  NULL,                                    // SSH2_MSG_USERAUTH_GSSAPI_ERRTOK     65
#if defined(WITH_GSSAPI) && defined(WITH_SERVER)
  ssh_packet_userauth_gssapi_mic,          // SSH2_MSG_USERAUTH_GSSAPI_MIC        66
#else /* WITH_GSSAPI && WITH_SERVER */
  NULL,
#endif /* WITH_GSSAPI && WITH_SERVER */
  NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL,                  //                                     67-79
#ifdef WITH_SERVER
  ssh_packet_global_request,               // SSH2_MSG_GLOBAL_REQUEST             80
#else /* WITH_SERVER */
  NULL,
#endif /* WITH_SERVER */ 
  ssh_request_success,                     // SSH2_MSG_REQUEST_SUCCESS            81
  ssh_request_denied,                      // SSH2_MSG_REQUEST_FAILURE            82
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,//                                     83-89
  ssh_packet_channel_open,                 // SSH2_MSG_CHANNEL_OPEN               90
  ssh_packet_channel_open_conf,            // SSH2_MSG_CHANNEL_OPEN_CONFIRMATION  91
  ssh_packet_channel_open_fail,            // SSH2_MSG_CHANNEL_OPEN_FAILURE       92
  channel_rcv_change_window,               // SSH2_MSG_CHANNEL_WINDOW_ADJUST      93
  channel_rcv_data,                        // SSH2_MSG_CHANNEL_DATA               94
  channel_rcv_data,                        // SSH2_MSG_CHANNEL_EXTENDED_DATA      95
  channel_rcv_eof,                         // SSH2_MSG_CHANNEL_EOF	              96
  channel_rcv_close,                       // SSH2_MSG_CHANNEL_CLOSE              97
  channel_rcv_request,                     // SSH2_MSG_CHANNEL_REQUEST            98
  ssh_packet_channel_success,              // SSH2_MSG_CHANNEL_SUCCESS            99
  ssh_packet_channel_failure,              // SSH2_MSG_CHANNEL_FAILURE            100
};

/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */

/** @internal
 * @handles a data received event. It then calls the handlers for the different packet types
 * or and exception handler callback.
 * @param user pointer to current ssh_session
 * @param data pointer to the data received
 * @len length of data received. It might not be enough for a complete packet
 * @returns number of bytes read and processed.
 */
int ssh_packet_socket_callback(const void *data, size_t receivedlen, void *user)
{
    ssh_session session= (ssh_session) user;
    unsigned int blocksize = (session->current_crypto ?
                              session->current_crypto->in_cipher->blocksize : 8);
    unsigned int lenfield_blocksize = (session->current_crypto ?
                                  session->current_crypto->in_cipher->lenfield_blocksize : 8);
    size_t current_macsize = 0;
    uint8_t *ptr = NULL;
    int to_be_read;
    int rc;
    uint8_t *cleartext_packet = NULL;
    uint8_t *packet_second_block = NULL;
    uint8_t *mac = NULL;
    size_t packet_remaining;
    uint32_t packet_len, compsize, payloadsize;
    uint8_t padding;
    size_t processed = 0; /* number of byte processed from the callback */

    if(session->current_crypto != NULL) {
      current_macsize = hmac_digest_len(session->current_crypto->in_hmac);
    }
    if (lenfield_blocksize == 0) {
        lenfield_blocksize = blocksize;
    }
    if (data == NULL) {
        goto error;
    }

    if (session->session_state == SSH_SESSION_STATE_ERROR) {
        goto error;
    }
#ifdef DEBUG_PACKET
    SSH_LOG(SSH_LOG_PACKET,
            "rcv packet cb (len=%zu, state=%s)",
            receivedlen,
            session->packet_state == PACKET_STATE_INIT ?
                "INIT" :
                session->packet_state == PACKET_STATE_SIZEREAD ?
                    "SIZE_READ" :
                    session->packet_state == PACKET_STATE_PROCESSING ?
                    "PROCESSING" : "unknown");
#endif
    switch(session->packet_state) {
        case PACKET_STATE_INIT:
            if (receivedlen < lenfield_blocksize) {
                /*
                 * We didn't receive enough data to read at least one
                 * block size, give up
                 */
#ifdef DEBUG_PACKET
                SSH_LOG(SSH_LOG_PACKET,
                        "Waiting for more data (%zu < %u)",
                        receivedlen,
                        lenfield_blocksize);
#endif
                return 0;
            }

            session->in_packet = (struct packet_struct) {
                .type = 0,
            };

            if (session->in_buffer) {
                rc = ssh_buffer_reinit(session->in_buffer);
                if (rc < 0) {
                    goto error;
                }
            } else {
                session->in_buffer = ssh_buffer_new();
                if (session->in_buffer == NULL) {
                    goto error;
                }
            }

            ptr = ssh_buffer_allocate(session->in_buffer, lenfield_blocksize);
            if (ptr == NULL) {
                goto error;
            }
            processed += lenfield_blocksize;
            packet_len = ssh_packet_decrypt_len(session, ptr, (uint8_t *)data);

            if (packet_len > MAX_PACKET_LEN) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "read_packet(): Packet len too high(%u %.4x)",
                              packet_len, packet_len);
                goto error;
            }
            to_be_read = packet_len - lenfield_blocksize + sizeof(uint32_t);
            if (to_be_read < 0) {
                /* remote sshd sends invalid sizes? */
                ssh_set_error(session,
                              SSH_FATAL,
                              "Given numbers of bytes left to be read < 0 (%d)!",
                              to_be_read);
                goto error;
            }

            session->in_packet.len = packet_len;
            session->packet_state = PACKET_STATE_SIZEREAD;
            FALL_THROUGH;
        case PACKET_STATE_SIZEREAD:
            packet_len = session->in_packet.len;
            processed = lenfield_blocksize;
            to_be_read = packet_len + sizeof(uint32_t) + current_macsize;
            /* if to_be_read is zero, the whole packet was blocksize bytes. */
            if (to_be_read != 0) {
                if (receivedlen  < (unsigned int)to_be_read) {
                    /* give up, not enough data in buffer */
                    SSH_LOG(SSH_LOG_PACKET,
                            "packet: partial packet (read len) "
                            "[len=%d, receivedlen=%d, to_be_read=%d]",
                            packet_len,
                            (int)receivedlen,
                            to_be_read);
                    return 0;
                }

                packet_second_block = (uint8_t*)data + lenfield_blocksize;
                processed = to_be_read - current_macsize;
            }

            /* remaining encrypted bytes from the packet, MAC not included */
            packet_remaining =
                packet_len - (lenfield_blocksize - sizeof(uint32_t));
            cleartext_packet = ssh_buffer_allocate(session->in_buffer,
                                                   packet_remaining);
            if (session->current_crypto) {
                /*
                 * Decrypt the rest of the packet (lenfield_blocksize bytes already
                 * have been decrypted)
                 */
                if (packet_remaining > 0) {
                    rc = ssh_packet_decrypt(session,
                                            cleartext_packet,
                                            (uint8_t *)data,
                                            lenfield_blocksize,
                                            processed - lenfield_blocksize);
                    if (rc < 0) {
                        ssh_set_error(session, SSH_FATAL, "Decryption error");
                        goto error;
                    }
                }
                mac = packet_second_block + packet_remaining;

                rc = ssh_packet_hmac_verify(session, session->in_buffer, mac, session->current_crypto->in_hmac);
                if (rc < 0) {
                    ssh_set_error(session, SSH_FATAL, "HMAC error");
                    goto error;
                }
                processed += current_macsize;
            } else {
                memcpy(cleartext_packet, packet_second_block, packet_remaining);
            }

            /* skip the size field which has been processed before */
            ssh_buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));

            rc = ssh_buffer_get_u8(session->in_buffer, &padding);
            if (rc == 0) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "Packet too short to read padding");
                goto error;
            }

            if (padding > ssh_buffer_get_len(session->in_buffer)) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "Invalid padding: %d (%d left)",
                              padding,
                              ssh_buffer_get_len(session->in_buffer));
                goto error;
            }
            ssh_buffer_pass_bytes_end(session->in_buffer, padding);
            compsize = ssh_buffer_get_len(session->in_buffer);

#ifdef WITH_ZLIB
            if (session->current_crypto
                && session->current_crypto->do_compress_in
                && ssh_buffer_get_len(session->in_buffer) > 0) {
                rc = decompress_buffer(session, session->in_buffer,MAX_PACKET_LEN);
                if (rc < 0) {
                    goto error;
                }
            }
#endif /* WITH_ZLIB */
            payloadsize = ssh_buffer_get_len(session->in_buffer);
            session->recv_seq++;
            if (session->raw_counter != NULL) {
                session->raw_counter->in_bytes += payloadsize;
                session->raw_counter->in_packets++;
            }

            /*
             * We don't want to rewrite a new packet while still executing the
             * packet callbacks
             */
            session->packet_state = PACKET_STATE_PROCESSING;
            ssh_packet_parse_type(session);
            SSH_LOG(SSH_LOG_PACKET,
                    "packet: read type %hhd [len=%d,padding=%hhd,comp=%d,payload=%d]",
                    session->in_packet.type, packet_len, padding, compsize, payloadsize);

            /* Execute callbacks */
            ssh_packet_process(session, session->in_packet.type);
            session->packet_state = PACKET_STATE_INIT;
            if (processed < receivedlen) {
                /* Handle a potential packet left in socket buffer */
                SSH_LOG(SSH_LOG_PACKET,
                        "Processing %" PRIdS " bytes left in socket buffer",
                        receivedlen-processed);

                ptr = ((uint8_t*)data) + processed;

                rc = ssh_packet_socket_callback(ptr, receivedlen - processed,user);
                processed += rc;
            }

            return processed;
        case PACKET_STATE_PROCESSING:
            SSH_LOG(SSH_LOG_PACKET, "Nested packet processing. Delaying.");
            return 0;
    }

    ssh_set_error(session,
                  SSH_FATAL,
                  "Invalid state into packet_read2(): %d",
                  session->packet_state);

error:
    session->session_state= SSH_SESSION_STATE_ERROR;
    SSH_LOG(SSH_LOG_PACKET,"Packet: processed %" PRIdS " bytes", processed);
    return processed;
}

static void ssh_packet_socket_controlflow_callback(int code, void *userdata)
{
    ssh_session session = userdata;
    struct ssh_iterator *it;
    ssh_channel channel;

    if (code == SSH_SOCKET_FLOW_WRITEWONTBLOCK) {
        SSH_LOG(SSH_LOG_TRACE, "sending channel_write_wontblock callback");

        /* the out pipe is empty so we can forward this to channels */
        it = ssh_list_get_iterator(session->channels);
        while (it != NULL) {
            channel = ssh_iterator_value(ssh_channel, it);
            ssh_callbacks_execute_list(channel->callbacks,
                                       ssh_channel_callbacks,
                                       channel_write_wontblock_function,
                                       session,
                                       channel,
                                       channel->remote_window);
            it = it->next;
        }
    }
}

void ssh_packet_register_socket_callback(ssh_session session, ssh_socket s){
	session->socket_callbacks.data=ssh_packet_socket_callback;
	session->socket_callbacks.connected=NULL;
    session->socket_callbacks.controlflow = ssh_packet_socket_controlflow_callback;
	session->socket_callbacks.userdata=session;
	ssh_socket_set_callbacks(s,&session->socket_callbacks);
}

/** @internal
 * @brief sets the callbacks for the packet layer
 */
void ssh_packet_set_callbacks(ssh_session session, ssh_packet_callbacks callbacks){
  if(session->packet_callbacks == NULL){
    session->packet_callbacks = ssh_list_new();
  }
  if (session->packet_callbacks != NULL) {
    ssh_list_append(session->packet_callbacks, callbacks);
  }
}

/** @internal
 * @brief sets the default packet handlers
 */
void ssh_packet_set_default_callbacks(ssh_session session){
	session->default_packet_callbacks.start=1;
	session->default_packet_callbacks.n_callbacks=sizeof(default_packet_handlers)/sizeof(ssh_packet_callback);
	session->default_packet_callbacks.user=session;
	session->default_packet_callbacks.callbacks=default_packet_handlers;
	ssh_packet_set_callbacks(session, &session->default_packet_callbacks);
}

/** @internal
 * @brief dispatch the call of packet handlers callbacks for a received packet
 * @param type type of packet
 */
void ssh_packet_process(ssh_session session, uint8_t type){
	struct ssh_iterator *i;
	int r=SSH_PACKET_NOT_USED;
	ssh_packet_callbacks cb;

	SSH_LOG(SSH_LOG_PACKET, "Dispatching handler for packet type %d",type);
	if(session->packet_callbacks == NULL){
		SSH_LOG(SSH_LOG_RARE,"Packet callback is not initialized !");

		return;
	}
	i=ssh_list_get_iterator(session->packet_callbacks);
	while(i != NULL){
		cb=ssh_iterator_value(ssh_packet_callbacks,i);
		i=i->next;
		if(!cb)
			continue;
		if(cb->start > type)
			continue;
		if(cb->start + cb->n_callbacks <= type)
			continue;
		if(cb->callbacks[type - cb->start]==NULL)
			continue;
		r=cb->callbacks[type - cb->start](session,type,session->in_buffer,cb->user);
		if(r==SSH_PACKET_USED)
			break;
	}
	if(r==SSH_PACKET_NOT_USED){
		SSH_LOG(SSH_LOG_RARE,"Couldn't do anything with packet type %d",type);
		ssh_packet_send_unimplemented(session, session->recv_seq-1);
	}
}

/** @internal
 * @brief sends a SSH_MSG_UNIMPLEMENTED answer to an unhandled packet
 * @param session the SSH session
 * @param seqnum the sequence number of the unknown packet
 * @return SSH_ERROR on error, else SSH_OK
 */
int ssh_packet_send_unimplemented(ssh_session session, uint32_t seqnum){
    int rc;

    rc = ssh_buffer_pack(session->out_buffer,
                         "bd",
                         SSH2_MSG_UNIMPLEMENTED,
                         seqnum);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    rc = ssh_packet_send(session);

    return rc;
}

/** @internal
 * @brief handles a SSH_MSG_UNIMPLEMENTED packet
 */
SSH_PACKET_CALLBACK(ssh_packet_unimplemented){
    uint32_t seq;
    int rc;

    (void)session; /* unused */
    (void)type;
    (void)user;

    rc = ssh_buffer_unpack(packet, "d", &seq);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARNING,
                "Could not unpack SSH_MSG_UNIMPLEMENTED packet");
    }

    SSH_LOG(SSH_LOG_RARE,
            "Received SSH_MSG_UNIMPLEMENTED (sequence number %d)",seq);

    return SSH_PACKET_USED;
}

/** @internal
 * @parse the "Type" header field of a packet and updates the session
 */
int ssh_packet_parse_type(struct ssh_session_struct *session)
{
    session->in_packet = (struct packet_struct) {
        .type = 0,
    };

    if (session->in_buffer == NULL) {
        return SSH_ERROR;
    }

    if (ssh_buffer_get_u8(session->in_buffer, &session->in_packet.type) == 0) {
        ssh_set_error(session, SSH_FATAL, "Packet too short to read type");
        return SSH_ERROR;
    }

    session->in_packet.valid = 1;

    return SSH_OK;
}

/*
 * This function places the outgoing packet buffer into an outgoing
 * socket buffer
 */
static int ssh_packet_write(ssh_session session) {
  int rc = SSH_ERROR;

  rc=ssh_socket_write(session->socket,
      ssh_buffer_get(session->out_buffer),
      ssh_buffer_get_len(session->out_buffer));

  return rc;
}

static int packet_send2(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->blocksize : 8);
  unsigned int lenfield_blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->lenfield_blocksize : 0);
  enum ssh_hmac_e hmac_type = (session->current_crypto ?
      session->current_crypto->out_hmac : session->next_crypto->out_hmac);
  uint32_t currentlen = ssh_buffer_get_len(session->out_buffer);
  unsigned char *hmac = NULL;
  char padstring[32] = { 0 };
  int rc = SSH_ERROR;
  uint32_t finallen,payloadsize,compsize;
  uint8_t padding;
  ssh_buffer header_buffer = ssh_buffer_new();

  payloadsize = currentlen;
#ifdef WITH_ZLIB
  if (session->current_crypto
      && session->current_crypto->do_compress_out
      && ssh_buffer_get_len(session->out_buffer)) {
    if (compress_buffer(session,session->out_buffer) < 0) {
      goto error;
    }
    currentlen = ssh_buffer_get_len(session->out_buffer);
  }
#endif /* WITH_ZLIB */
  compsize = currentlen;
  /* compressed payload + packet len (4) + padding len (1) */
  /* totallen - lenfield_blocksize must be equal to 0 (mod blocksize) */
  padding = (blocksize - ((blocksize - lenfield_blocksize + currentlen + 5) % blocksize));
  if(padding < 4) {
    padding += blocksize;
  }

  if (session->current_crypto != NULL) {
      int ok;

      ok = ssh_get_random(padstring, padding, 0);
      if (!ok) {
          ssh_set_error(session, SSH_FATAL, "PRNG error");
          goto error;
      }
  }

  if (header_buffer == NULL){
    ssh_set_error_oom(session);
    goto error;
  }
  finallen = currentlen + padding + 1;
  rc = ssh_buffer_pack(header_buffer, "db", finallen, padding);
  if (rc == SSH_ERROR){
    goto error;
  }

  rc = ssh_buffer_prepend_data(session->out_buffer,
                               ssh_buffer_get(header_buffer),
                               ssh_buffer_get_len(header_buffer));
  if (rc < 0) {
    goto error;
  }
  rc = ssh_buffer_add_data(session->out_buffer, padstring, padding);
  if (rc < 0) {
    goto error;
  }
#ifdef WITH_PCAP
  if (session->pcap_ctx) {
      ssh_pcap_context_write(session->pcap_ctx,
                             SSH_PCAP_DIR_OUT,
                             ssh_buffer_get(session->out_buffer),
                             ssh_buffer_get_len(session->out_buffer),
                             ssh_buffer_get_len(session->out_buffer));
  }
#endif
  hmac = ssh_packet_encrypt(session, ssh_buffer_get(session->out_buffer),
      ssh_buffer_get_len(session->out_buffer));
  if (hmac) {
    rc = ssh_buffer_add_data(session->out_buffer, hmac, hmac_digest_len(hmac_type));
    if (rc < 0) {
      goto error;
    }
  }

  rc = ssh_packet_write(session);
  session->send_seq++;
  if (session->raw_counter != NULL) {
      session->raw_counter->out_bytes += payloadsize;
      session->raw_counter->out_packets++;
  }

  SSH_LOG(SSH_LOG_PACKET,
          "packet: wrote [len=%d,padding=%hhd,comp=%d,payload=%d]",
          finallen, padding, compsize, payloadsize);
  if (ssh_buffer_reinit(session->out_buffer) < 0) {
    rc = SSH_ERROR;
  }
error:
  if (header_buffer != NULL) {
      ssh_buffer_free(header_buffer);
  }
  return rc; /* SSH_OK, AGAIN or ERROR */
}


int ssh_packet_send(ssh_session session) {
    return packet_send2(session);
}
