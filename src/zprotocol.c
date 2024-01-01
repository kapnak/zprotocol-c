#include "zprotocol.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>



void * call_message_listener(void *args) {
    CallListenerArgs *arg = (CallListenerArgs *)args;
    arg->message_listener(arg->remote_peer, arg->message);
    (*arg->threads)--;
    free(args);
    return NULL;
}



void * call_connection_listener(void *args) {
    CallListenerArgs *arg = (CallListenerArgs *)args;
    arg->remote_peer->local_peer->connection_listener(arg->remote_peer);
    (*arg->threads)--;
    free(args);
    return NULL;
}



void * handle_server_listener(void *args) {
    LocalPeer *local_peer = (LocalPeer *)args;

    int r;
    do {
        RemotePeer *remote_peer = malloc(sizeof(RemotePeer));
        printf("Accepting ...\n");
        r = z_accept(local_peer, remote_peer);
        printf("Accepted\n");
        remote_peer->free_on_disconnect = 1;
        if (r == 0) {
            local_peer->threads++;
            pthread_t thread;
            pthread_create(&thread, NULL, handle_listeners, remote_peer);
            pthread_detach(thread);
        } else {
            free(remote_peer);
        }
    } while (r >= 0);      // Loop until the socket return an error.

    while (local_peer->threads)
        sleep(1);

    return NULL;
}



void * handle_listeners(void *args) {
    RemotePeer *remote_peer = (RemotePeer *)args;
    atomic_int threads = 0;

    // Calling the connection listener
    if (remote_peer->local_peer->connection_listener != NULL) {
        CallListenerArgs *arg = malloc(sizeof(CallListenerArgs));
        arg->remote_peer = remote_peer;
        arg->threads = &threads;
        threads++;
        pthread_t thread;
        pthread_create(&thread, NULL, call_connection_listener, arg);
        pthread_detach(thread);
    }

    // We choose remote peer listener over local peer listener.
    MessageListener message_listener =
            remote_peer->message_listener != NULL ?
            remote_peer->message_listener :
            remote_peer->local_peer->message_listener;

    DisconnectionListener disconnection_listener =
            remote_peer->disconnection_listener != NULL ?
            remote_peer->disconnection_listener :
            remote_peer->local_peer->disconnection_listener;

    // If a listener is defined, we listen get messages endlessly and send them to the listener.
    if (message_listener != NULL) {
        while (1) {
            Message *message = malloc(sizeof(Message));
            if (z_receive(remote_peer, message) == -1) {
                free(message);
                break;
            }

            if (IS_REPLY(message->id)) {  // If the message is a reply.
                int free_reply = 1;
                pthread_mutex_lock(&remote_peer->reply_listeners_mutex);                // LOCK
                for (int i = 0; i < remote_peer->reply_listeners_len; i++) {
                    if (remote_peer->reply_listeners[i] != NULL) {
                        if (memcmp(remote_peer->reply_listeners[i]->id, message->id, MESSAGE_ID_LENGTH) == 0) {
                            remote_peer->reply_listeners[i]->reply = message;
                            pthread_cond_signal(&remote_peer->reply_listeners[i]->cond);
                            free_reply = 0;
                            break;
                        }
                    }
                }
                pthread_mutex_unlock(&remote_peer->reply_listeners_mutex);              // UNLOCK
                if (free_reply) {
                    z_cleanup_message(message);
                }        // If no reply listeners have been called we free up message.

            } else {                // If the message is not a reply.
                CallListenerArgs *arg = malloc(sizeof(CallListenerArgs));
                arg->message_listener = message_listener;
                arg->remote_peer = remote_peer;
                arg->message = message;
                arg->threads = &threads;
                threads++;
                pthread_t thread;
                pthread_create(&thread, NULL, call_message_listener, arg);
                pthread_detach(thread);
            }
        }

        if (disconnection_listener != NULL)
            disconnection_listener(remote_peer);
    }

    while (threads)
        sleep(1);

    remote_peer->local_peer->threads--;
    if (remote_peer->free_on_disconnect)
        free(remote_peer);
    return NULL;
}



void z_initialize_local_peer(LocalPeer *local_peer,
                             const unsigned char pk[ED25519_PK_LENGTH],
                             const unsigned char sk[ED25519_SK_LENGTH],
                             MessageListener message_listener,
                             ConnectionListener connection_listener,
                             DisconnectionListener disconnection_listener) {
    memcpy(local_peer->pk, pk, ED25519_PK_LENGTH);
    memcpy(local_peer->sk, sk, ED25519_SK_LENGTH);
    // WARNING : See the notes https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
    if (crypto_sign_ed25519_pk_to_curve25519(local_peer->pk_x25519, local_peer->pk) ||
        crypto_sign_ed25519_sk_to_curve25519(local_peer->sk_x25519, local_peer->sk))
        perror("Failed to convert local_peer ed25519 keys to curve25519 keys");
    local_peer->message_listener = message_listener;
    local_peer->connection_listener = connection_listener;
    local_peer->disconnection_listener = disconnection_listener;
    local_peer->threads = 0;
}



void z_set_message_listener(RemotePeer *remote_peer, MessageListener message_listener) {
    remote_peer->message_listener = message_listener;
}



int z_listen(LocalPeer *local_peer, const char *address, unsigned short port) {
    struct sockaddr_in server;
    if ((local_peer->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("Socket creation failed:");

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_addr.s_addr = inet_addr(address);

    if (setsockopt(local_peer->fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        return -1;

    if (bind(local_peer->fd, (struct sockaddr *)&server, sizeof(server)) < 0)
        return -1;

    if (listen(local_peer->fd, 1) != 0)
        return -1;

    handle_server_listener(local_peer);
    return 0;
}



void z_connect(LocalPeer *local_peer,
               RemotePeer *remote_peer,
               const char *address,
               unsigned short port,
               const unsigned char pk[ED25519_PK_LENGTH]) {     // TODO : Add listeners there.

    // Initialize the RemotePeer structure
    remote_peer->message_listener = NULL;
    remote_peer->disconnection_listener = NULL;
    remote_peer->reply_listeners = NULL;
    remote_peer->reply_listeners_len = 0;
    pthread_mutex_init(&remote_peer->reply_listeners_mutex, NULL);
    pthread_mutex_init(&remote_peer->encryption_mutex, NULL);
    remote_peer->local_peer = local_peer;
    remote_peer->free_on_disconnect = 0;
    remote_peer->attribute = NULL;
    remote_peer->encrypted_conversation = pk != NULL;
    if (pk != NULL)
        memcpy(remote_peer->pk, pk, ED25519_PK_LENGTH);
    else
        memset(remote_peer->pk, 0, ED25519_PK_LENGTH);

    // Generate encryption cipher (header & encryption_state)
    unsigned char header_to_send[HEADER_LENGTH];
    unsigned char shared_key_decryption[SHARED_KEY_LENGTH];
    memset(header_to_send, 0, HEADER_LENGTH);
    if (remote_peer->encrypted_conversation) {
        unsigned char remote_pk_x25519[X25519_LENGTH];
        unsigned char shared_key_encryption[SHARED_KEY_LENGTH];
        if (crypto_sign_ed25519_pk_to_curve25519(remote_pk_x25519, remote_peer->pk) != 0)
            perror("Failed to convert the remote pk");

        if (crypto_kx_client_session_keys(
                shared_key_decryption, shared_key_encryption,
                remote_peer->local_peer->pk_x25519, remote_peer->local_peer->sk_x25519,
                remote_pk_x25519) != 0) {
            // TODO : Handle this case.
        }
        crypto_secretstream_xchacha20poly1305_init_push(&(remote_peer->encryption_state), header_to_send, shared_key_encryption);
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_addr.s_addr = inet_addr(address);

    if ((remote_peer->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("Socket creation failed");

    if (connect(remote_peer->fd, (struct sockaddr *)&server, sizeof(server)) < 0)
        perror("Failed to connect");

    // Initialize encryption cipher
    send(remote_peer->fd, "\0", 1, MSG_MORE);
    send(remote_peer->fd, remote_peer->pk, ED25519_PK_LENGTH, MSG_MORE);
    send(remote_peer->fd, remote_peer->local_peer->pk, ED25519_PK_LENGTH, MSG_MORE);
    send(remote_peer->fd, header_to_send, HEADER_LENGTH, 0);

    // Receive header and generate decryption cipher if encryption is set.
    if (remote_peer->encrypted_conversation) {
        unsigned char header[HEADER_LENGTH];
        recv(remote_peer->fd, header, HEADER_LENGTH, MSG_WAITALL);
        crypto_secretstream_xchacha20poly1305_init_pull(&(remote_peer->decryption_state), header, shared_key_decryption);
    }

    handle_listeners(remote_peer);
}



int z_accept(LocalPeer *local_peer, RemotePeer *remote_peer) {
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    remote_peer->local_peer = local_peer;
    remote_peer->free_on_disconnect = 0;
    remote_peer->message_listener = NULL;
    remote_peer->disconnection_listener = NULL;
    remote_peer->reply_listeners = NULL;
    remote_peer->reply_listeners_len = 0;
    remote_peer->attribute = NULL;
    pthread_mutex_init(&remote_peer->reply_listeners_mutex, NULL);
    pthread_mutex_init(&remote_peer->encryption_mutex, NULL);

    // We use poll to wait for connection with timeout.
    int r;
    do {
        struct pollfd fds[1];
        fds[0].fd = local_peer->fd;
        fds[0].events = POLLIN;
        r = poll(fds, 1, 3000);
    } while (r == 0);

    if (r < 0)
        return -1;

    if ((remote_peer->fd = accept(local_peer->fd, (struct sockaddr *)&client, &client_len)) == -1)
        return -1;

    // Receiving initialization data :
    char garbage;
    char server_pk[ED25519_PK_LENGTH];
    unsigned char header_received[HEADER_LENGTH];
    if (recv(remote_peer->fd, &garbage, 1, MSG_WAITALL) == -1)
        return -2;

    if (recv(remote_peer->fd, server_pk, ED25519_PK_LENGTH, MSG_WAITALL) == -1)
        return -2;

    if (recv(remote_peer->fd, remote_peer->pk, ED25519_PK_LENGTH, MSG_WAITALL) == -1)
        return -2;

    if (recv(remote_peer->fd, header_received, HEADER_LENGTH, MSG_WAITALL) == -1)
        return -2;

    // Setting the encryption, yes if the header is not filled with null characters else no.
    unsigned char empty_header[HEADER_LENGTH];
    memset(empty_header, 0, HEADER_LENGTH);
    remote_peer->encrypted_conversation = memcmp(header_received, empty_header, HEADER_LENGTH);

    // Generating cipher if encryption set
    if (remote_peer->encrypted_conversation) {
        unsigned char client_pk_x25519[X25519_LENGTH];
        unsigned char shared_key_encryption[SHARED_KEY_LENGTH];
        unsigned char shared_key_decryption[SHARED_KEY_LENGTH];
        unsigned char header_to_send[HEADER_LENGTH];
        if (crypto_sign_ed25519_pk_to_curve25519(client_pk_x25519, remote_peer->pk))
            perror("Failed to convert remote pk");

        if (crypto_kx_server_session_keys(
                shared_key_decryption, shared_key_encryption,
                remote_peer->local_peer->pk_x25519, remote_peer->local_peer->sk_x25519,
                client_pk_x25519) != 0) {
            // TODO : Handle this case.
        }
        crypto_secretstream_xchacha20poly1305_init_push(&(remote_peer->encryption_state), header_to_send, shared_key_encryption);
        crypto_secretstream_xchacha20poly1305_init_pull(&(remote_peer->decryption_state), header_received, shared_key_decryption);

        // Send the header.
        if (send(remote_peer->fd, header_to_send, HEADER_LENGTH, 0) < 0)
            return -2;
    }

    return 0;
}



int z_receive(RemotePeer *remote_peer, Message *message) {
    int payload_length;

    // We use poll to wait for data with timeout.
    int r;
    do {
        struct pollfd fds[1];
        fds[0].fd = remote_peer->fd;
        fds[0].events = POLLIN;
        r = poll(fds, 1, 3000);
    } while (r == 0);

    if (r < 0)
        return -1;

    if (recv(remote_peer->fd, message->id, MESSAGE_ID_LENGTH, MSG_WAITALL) < 1)
        return -1;

    if (recv(remote_peer->fd, &payload_length, sizeof(int), MSG_WAITALL) < 1)
        return -1;

    if (!remote_peer->encrypted_conversation) {
        message->content_length = payload_length;
        message->content = malloc(message->content_length);
        if (recv(remote_peer->fd, message->content, message->content_length, MSG_WAITALL) < 1) {
            free(message->content);
            return -1;
        }
    } else {
        unsigned char payload[payload_length];           // TODO : Try to used the same buffer for encrypted and decrypted payload
        if (recv(remote_peer->fd, payload, payload_length, MSG_WAITALL) < 1)
            return -1;

        message->content_length = payload_length - PAYLOAD_ADDED_LENGTH;    // TODO : Clang-Tidy: Narrowing conversion from 'unsigned int' to signed type 'int' is implementation-defined
        message->content = malloc(message->content_length);
        if (crypto_secretstream_xchacha20poly1305_pull(&remote_peer->decryption_state,
                                                       message->content,
                                                       NULL,
                                                       NULL,
                                                       payload,
                                                       payload_length,
                                                       NULL,
                                                       0) != 0) {
            perror("Failed to decrypt payload");
            free(message->content);
        }
    }

    return 0;
}



int z_send(RemotePeer *remote_peer, void *message_payload, uint32_t message_payload_length, int timeout, Message **reply) {    // TODO : Change to allow user to know the ID of the message that have been sent.
    int message_length = MESSAGE_ID_LENGTH + MESSAGE_LENGTH_LENGTH + message_payload_length + PAYLOAD_ADDED_LENGTH;
    unsigned char message[message_length];

    // Generate & send message ID
    randombytes_buf(message, MESSAGE_ID_LENGTH);
    SET_AS_MESSAGE(message)

    if (!remote_peer->encrypted_conversation) {
        message_length -= PAYLOAD_ADDED_LENGTH;
        memcpy(MESSAGE_GET_LENGTH(message), &message_payload_length, MESSAGE_LENGTH_LENGTH);
        memcpy(MESSAGE_GET_PAYLOAD(message), message_payload, message_payload_length);
        if (send(remote_peer->fd, message, message_length, 0) == -1)
            return -1;
    } else {
        uint32_t encrypted_payload_length = message_payload_length + PAYLOAD_ADDED_LENGTH;
        memcpy(MESSAGE_GET_LENGTH(message), &encrypted_payload_length, MESSAGE_LENGTH_LENGTH);
        pthread_mutex_lock(&remote_peer->encryption_mutex);                              // LOCK THE ENCRYPTION
        if (crypto_secretstream_xchacha20poly1305_push(&remote_peer->encryption_state,
                                                       MESSAGE_GET_PAYLOAD(message),
                                                       NULL,
                                                       message_payload,
                                                       message_payload_length,
                                                       NULL,
                                                       0,
                                                       0) != 0) {
            pthread_mutex_unlock(&remote_peer->encryption_mutex);                       // UNLOCK THE ENCRYPTION
            perror("Failed to encrypt payload");
        }
        if (send(remote_peer->fd, message, message_length, 0) == -1)
            return -1;

        pthread_mutex_unlock(&remote_peer->encryption_mutex);                           // UNLOCK THE ENCRYPTION
    }

    if (timeout) {
        ReplyListener reply_listener;
        reply_listener.reply = NULL;
        memcpy(reply_listener.id, message, MESSAGE_ID_LENGTH);
        SET_AS_REPLY(reply_listener.id)
        pthread_cond_init(&reply_listener.cond, NULL);

        debug("There is %zd reply waiters.\n", remote_peer->reply_listeners_len)
        debug("Waiting for reply_listeners_mutex ...\n")
        pthread_mutex_lock(&remote_peer->reply_listeners_mutex);                       // LOCK
        debug("Taking reply_listeners_mutex.\n")
        int i;
        // Adding the message listener.
        for (i = 0; i <= remote_peer->reply_listeners_len; i++) {
            if (i == remote_peer->reply_listeners_len) {
                remote_peer->reply_listeners_len++;
                remote_peer->reply_listeners = realloc(remote_peer->reply_listeners, remote_peer->reply_listeners_len * sizeof(ReplyListener));
                if (remote_peer->reply_listeners == NULL) {
                    perror("Can't reallocate 'reply_listeners'.");
                    exit(EXIT_FAILURE);
                }
                remote_peer->reply_listeners[i] = &reply_listener;
                break;
            } else if (remote_peer->reply_listeners[i] == NULL) {
                remote_peer->reply_listeners[i] = &reply_listener;
                break;
            }
        }

        debug("Enter the cond.\n")
        int res;
        if (timeout < 0) {
            res = pthread_cond_wait(&reply_listener.cond, &remote_peer->reply_listeners_mutex);                 // WAIT
        } else {
            struct timespec abstime;
            clock_gettime(CLOCK_REALTIME, &abstime);
            abstime.tv_sec += timeout;       // TODO : Change with custom user timeout.
            res = pthread_cond_timedwait(&reply_listener.cond, &remote_peer->reply_listeners_mutex, &abstime);  // WAIT
        }
        debug("Exit the cond.\n");
        if (res == 0) {
            *reply = reply_listener.reply;
            debug("Reply received.\n");
        } else if (res == ETIMEDOUT) {
            debug("Timeout.\n");
        }

        /* Removing the waiter */
        remote_peer->reply_listeners[i] = NULL;
        if (remote_peer->reply_listeners_len == i+1) {
            remote_peer->reply_listeners_len--;
            if (remote_peer->reply_listeners_len == 0) {
                free(remote_peer->reply_listeners);
                remote_peer->reply_listeners = NULL;
            }
            else
                remote_peer->reply_listeners = realloc(remote_peer->reply_listeners, remote_peer->reply_listeners_len * sizeof(ReplyListener));
        }

        debug("Unlocking reply_listeners_mutex ...\n");
        pthread_mutex_unlock(&remote_peer->reply_listeners_mutex);                   // UNLOCK
        debug("Mutex freed.\n");

        return 0;
    }

    // TODO : return message id;
}



int z_reply(RemotePeer *remote_peer, void *reply_payload, uint32_t reply_payload_length, const unsigned char id[MESSAGE_ID_LENGTH]) {
    int reply_length = MESSAGE_ID_LENGTH + MESSAGE_LENGTH_LENGTH + reply_payload_length + PAYLOAD_ADDED_LENGTH;
    unsigned char reply[reply_length];

    // Generate & send message ID
    memcpy(reply, id, MESSAGE_ID_LENGTH);
    reply[3] |= 1;

    if (!remote_peer->encrypted_conversation) {
        reply_length -= PAYLOAD_ADDED_LENGTH;
        memcpy(MESSAGE_GET_LENGTH(reply), &reply_payload_length, MESSAGE_LENGTH_LENGTH);
        memcpy(MESSAGE_GET_PAYLOAD(reply), reply_payload, reply_payload_length);
        if (send(remote_peer->fd, reply, reply_length, 0) == -1)
            return -1;
    } else {
        uint32_t encrypted_payload_length = reply_payload_length + PAYLOAD_ADDED_LENGTH;
        memcpy(MESSAGE_GET_LENGTH(reply), &encrypted_payload_length, MESSAGE_LENGTH_LENGTH);
        pthread_mutex_lock(&remote_peer->encryption_mutex);                                     // LOCK ENCRYPTION
        if (crypto_secretstream_xchacha20poly1305_push(&remote_peer->encryption_state,
                                                       MESSAGE_GET_PAYLOAD(reply),
                                                       NULL,
                                                       reply_payload,
                                                       reply_payload_length,
                                                       NULL,
                                                       0,
                                                       0) != 0) {
            pthread_mutex_unlock(&remote_peer->encryption_mutex);                               // UNLOCK ENCRYPTION
            perror("Failed to encrypt payload");
        }

        if (send(remote_peer->fd, reply, reply_length, MSG_NOSIGNAL) == -1)
            return -1;

        pthread_mutex_unlock(&remote_peer->encryption_mutex);                                   // UNLOCK ENCRYPTION
    }
    return 0;
}


void z_cleanup_message(Message *message) {
    free(message->content);
    free(message);
}


void z_disconnect(RemotePeer *remote_peer) {
    close(remote_peer->fd);
}


void z_stop(LocalPeer *local_peer) {
    close(local_peer->fd);
}
