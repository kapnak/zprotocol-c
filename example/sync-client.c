#include <string.h>
#include "../src/zprotocol.h"


int main() {
    unsigned char pk[ED25519_PK_LENGTH];
    unsigned char sk[ED25519_SK_LENGTH];
    unsigned char server_pk[ED25519_PK_LENGTH];
    z_helpers_pk_bs64_to_bin("yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU", pk);
    z_helpers_sk_bs64_to_bin("7AweZshFG13B-Hkch8Rny4rEKRofaBJFafpXy_s-lmTJ9PSu6YjsAwii54AJr8QAu3ppGFctlcKoQsBFVZG-JQ", sk);
    z_helpers_pk_bs64_to_bin("5Ti_m_HxFu0CWUaIJKcoGORLtJxE3PajGM86pj4QhWw", server_pk);

    LocalPeer client;
    RemotePeer server;
    Message reply;
    char request[] = "Hello world!";

    z_initialize_local_peer(&client, pk, sk, NULL, NULL, NULL);
    z_connect(&client, &server, "127.0.0.1", 6339, server_pk);

    z_send(&server, request, strlen(request)+1, 0, NULL);
    z_receive(&server, &reply);
    printf("SERVER REPLY (%db) : %s\n", reply.content_length, reply.content);
    free(reply.content);

    z_disconnect(&server);
}