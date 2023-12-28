#ifndef ZPROTOCOL_LIBRARY_H
#define ZPROTOCOL_LIBRARY_H

#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <stdatomic.h>

#define PK_BS64_LENGTH sodium_base64_ENCODED_LEN(crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define SK_BS64_LENGTH sodium_base64_ENCODED_LEN(crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define ED25519_PK_LENGTH 32
#define ED25519_SK_LENGTH 64
#define X25519_LENGTH crypto_scalarmult_curve25519_BYTES
#define SHARED_KEY_LENGTH crypto_kx_SESSIONKEYBYTES
#define HEADER_LENGTH 24
#define MESSAGE_ID_LENGTH 16
#define MESSAGE_LENGTH_LENGTH 4
#define PAYLOAD_ADDED_LENGTH crypto_secretstream_xchacha20poly1305_ABYTES

// For cygwin
//#ifndef MSG_MORE
//#define MSG_MORE 0x8000
//#endif

#define MESSAGE_GET_LENGTH(message)         ((message) + MESSAGE_ID_LENGTH)
#define MESSAGE_GET_PAYLOAD(message)        ((message) + MESSAGE_ID_LENGTH + MESSAGE_LENGTH_LENGTH)

#define IS_REPLY(id)        (id[3]&1)
#define SET_AS_REPLY(id)    id[3] |= 1;
#define SET_AS_MESSAGE(id)  id[3] &= ~1;

#define VERBOSE 0
#if VERBOSE == 0
#define debug(fmt, ...) ;
#else
#define debug(fmt, ...) \
        printf("%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__);
#endif


typedef struct ReplyListener ReplyListener;
typedef struct CallListenerArgs CallListenerArgs;
typedef struct LocalPeer LocalPeer;
typedef struct RemotePeer RemotePeer;
typedef struct Message Message;


typedef void (*MessageListener)(RemotePeer *, Message *);
typedef void (*ConnectionListener)(RemotePeer *);
typedef void (*DisconnectionListener)(RemotePeer *);


typedef struct ReplyListener {
    unsigned char id[MESSAGE_ID_LENGTH];
    pthread_cond_t cond;
    Message *reply;
} ReplyListener;


typedef struct CallListenerArgs {
    RemotePeer *remote_peer;
    MessageListener message_listener;
    Message *message;
    atomic_int *threads;
} CallListenerArgs;


typedef struct LocalPeer {
    unsigned char pk[ED25519_PK_LENGTH];
    unsigned char sk[ED25519_SK_LENGTH];
    unsigned char pk_x25519[X25519_LENGTH];
    unsigned char sk_x25519[X25519_LENGTH];
    MessageListener message_listener;
    ConnectionListener connection_listener;
    DisconnectionListener disconnection_listener;
    int fd;
    atomic_int threads;
} LocalPeer;


typedef struct RemotePeer {
    unsigned char pk[ED25519_PK_LENGTH];
    int fd;
    LocalPeer* local_peer;
    crypto_secretstream_xchacha20poly1305_state encryption_state;
    crypto_secretstream_xchacha20poly1305_state decryption_state;
    int encrypted_conversation;
    MessageListener message_listener;
    DisconnectionListener disconnection_listener;
    ReplyListener **reply_listeners;
    size_t reply_listeners_len;
    pthread_mutex_t reply_listeners_mutex;
    pthread_mutex_t encryption_mutex;
    char free_on_disconnect;
    void *attribute;
} RemotePeer;


typedef struct Message  {
    unsigned char id[MESSAGE_ID_LENGTH];
    uint32_t content_length;
    unsigned char *content;
} Message;


/**
 * Initialize local peer.
 * @param local_peer An allocated 'LocalPeer'.
 * @param pk The local peer public key.
 * @param sk The local peer secret key.
 * @param message_listener NULL or a message listener that will be called when a message is received.
 * @param connection_listener NULL or a connection listener that will be called when a connection is established with the peer.
 * @param disconnection_listener NULL or a disconnection listener that will be called when the connection is closed.
 */
extern void z_initialize_local_peer(LocalPeer *local_peer,
                                    const unsigned char pk[ED25519_PK_LENGTH],
                                    const unsigned char sk[ED25519_SK_LENGTH],
                                    MessageListener message_listener,
                                    ConnectionListener connection_listener,
                                    DisconnectionListener disconnection_listener);


/**
 * Set the a listener for the specified remote peer.
 * @note If a listener is defined in remote_peer, the global local_peer listener will not be called.
 * @param remote_peer The remote peer.
 * @param message_listener The message listener or NULL.
 * @param disconnection_listener The disconnection listener or NULL. It will be called if the connection is closed.
 */
extern void z_set_listeners(RemotePeer *remote_peer,
                            MessageListener message_listener,
                            DisconnectionListener disconnection_listener);


/**
 * Listen for connection.
 * @param local_peer An initialized local peer structure. With pk, sk, and listeners (z_initialize_local_peer).
 * @param address Address to used.
 * @param port Port to used.
 * @return 0 on success
 */
extern int z_listen(LocalPeer *local_peer, const char *address, unsigned short port);


/**
 * Connect to a remote peer.
 * @param local_peer An initialized local peer structure. With pk, sk, and listeners (z_initialize_local_peer).
 * @param remote_peer An uninitialized remote_peer.
 * @param address The remote peer address.
 * @param port The remote peer port.
 * @param pk The remote peer pk or NULL to not use encryption.
 */
extern void z_connect(LocalPeer *local_peer,
                      RemotePeer *remote_peer,
                      const char *address,
                      unsigned short port,
                      const unsigned char pk[ED25519_PK_LENGTH]);


/**
 * Wait and accept incoming connection.
 * @param local_peer The local peer. (Need to have been initialized with 'z_listen' before).
 * @param remote_peer A remote peer structure that will be initialized.
 * @return 0 on success.
 */
extern int z_accept(LocalPeer *local_peer, RemotePeer *remote_peer);


/**
 * Wait and get a message.
 * @warning This function is not thread-safe.
 * @param remote_peer The remote peer to received from.
 * @param message An empty message struct that will be filled with a new message.
 * /!\ Note that message->content is dynamically allocated.
 * @return -1 if the socket is disconnected
 */
extern int z_receive(RemotePeer *remote_peer, Message *message);


/**
 * Send a message to a remote peer.
 * @param remote_peer The remote peer to send the message to.
 * @param message_payload The message payload.
 * @param message_payload_length The message payload length.
 * @param timeout The number of second to wait the for a reply. 0 to not wait or -1 to wait endlessly.
 * @param reply A reference to a Message pointer.
 * @return 0 on success.
 */
extern int z_send(RemotePeer *remote_peer,
                  void *message_payload,
                  uint32_t message_payload_length,
                  int timeout,
                  Message **reply);


/**
 * Reply to a message.
 * @param remote_peer The remote peer to reply to.
 * @param reply_payload The reply payload.
 * @param reply_payload_length The reply payload length.
 * @param id The message id to reply to.
 */
extern int z_reply(RemotePeer *remote_peer,
                   void *reply_payload,
                   uint32_t reply_payload_length,
                   const unsigned char id[MESSAGE_ID_LENGTH]);


/**
 * Freed message content and message.
 * @param message The message to free.
 */
extern void z_cleanup_message(Message *message);



/**
 * End the connection
 * @param remote_peer The remote peer to disconnect.
 */
extern void z_disconnect(RemotePeer *remote_peer);



/**
 * Stop the local peer to listen for connection.
 * @param local_peer The local peer.
 */
extern void z_stop(LocalPeer *local_peer);


// Internal usage

/**
 * Wrapper for message listener.
 * It will call the given message listener.
 * The goal is to avoid user to cast void argument as its require for threading.
 * @param args A filled 'CallListenerArgs'.
 */
void * call_message_listener(void *args);



/**
 * Handle the listeners by calling them.
 * If one of the message listeners is define, the function will never end.
 * @param args A pointer to a 'RemotePeer'.
 */
void * handle_listeners(void *args);



// HELPERS

/**
 * Read key pair from binary file or generate and create new file if does not exists.
 * @param filename - The filename.
 * @param pk - An allocated space for the public key.
 * @param sk - An allocated space for the secret key.
 */
void z_helpers_read_kp(const char *filename, unsigned char pk[ED25519_PK_LENGTH], unsigned char sk[ED25519_SK_LENGTH]);

/**
 * Write a key pair to a file.
 * @param filename - The filename.
 * @param sk - The secret key to write.
 */
void z_helpers_write_kp(const char *filename, const unsigned char sk[ED25519_SK_LENGTH]);


void z_helpers_sk_to_pk(unsigned char pk[ED25519_PK_LENGTH], const unsigned char sk[ED25519_SK_LENGTH]);


void z_helpers_generate_kp(unsigned char pk[ED25519_PK_LENGTH], unsigned char sk[ED25519_SK_LENGTH]);


void z_helpers_pk_bin_to_bs64(const unsigned char pk[ED25519_PK_LENGTH], char pk_bs64[PK_BS64_LENGTH]);


void z_helpers_sk_bin_to_bs64(const unsigned char sk[ED25519_SK_LENGTH], char sk_bs64[SK_BS64_LENGTH]);


void z_helpers_pk_bs64_to_bin(const char pk_bs64[PK_BS64_LENGTH], unsigned char pk[ED25519_PK_LENGTH]);


void z_helpers_sk_bs64_to_bin(const char sk_bs64[SK_BS64_LENGTH], unsigned char sk[ED25519_SK_LENGTH]);

#endif
