#include <string.h>
#include "../src/zprotocol.h"


void on_connection(RemotePeer *server) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(server->pk, client_pk_bs64);
    printf("[+] Server '%s' connected.\n", client_pk_bs64);

    Message *reply = NULL;
    char request[] = "Hello world!";
    z_send(server, request, strlen(request)+1, 2, &reply);
    if (reply != NULL) {
        printf("Receive reply (%db) : %s\n", reply->content_length, reply->content);
        z_cleanup_message(reply);
    }
    z_disconnect(server);
}


void on_message(RemotePeer *server, Message *message) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(server->pk, client_pk_bs64);
    printf("[%s] Says : %s\n", client_pk_bs64, message->content);
    z_cleanup_message(message);
}


void on_disconnect(RemotePeer *server) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(server->pk, client_pk_bs64);
    printf("[-] Server '%s' disconnected.\n", client_pk_bs64);
}


int main() {
    unsigned char pk[ED25519_PK_LENGTH];
    unsigned char sk[ED25519_SK_LENGTH];
    unsigned char server_pk[ED25519_PK_LENGTH];
    z_helpers_pk_bs64_to_bin("yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU", pk);
    z_helpers_sk_bs64_to_bin("7AweZshFG13B-Hkch8Rny4rEKRofaBJFafpXy_s-lmTJ9PSu6YjsAwii54AJr8QAu3ppGFctlcKoQsBFVZG-JQ", sk);
    z_helpers_pk_bs64_to_bin("5Ti_m_HxFu0CWUaIJKcoGORLtJxE3PajGM86pj4QhWw", server_pk);

    LocalPeer client;
    RemotePeer server;
    z_initialize_local_peer(&client, pk, sk, on_message, on_connection, on_disconnect);
    z_connect(&client, &server, "0.0.0.0", 6339, server_pk);
    printf("Server disconnected.\n");
    return 0;
}