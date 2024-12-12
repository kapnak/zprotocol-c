#include <string.h>
#include "../src/zprotocol.h"


int main() {
    unsigned char pk[ED25519_PK_LENGTH];
    unsigned char sk[ED25519_SK_LENGTH];
    z_helpers_pk_bs64_to_bin("5Ti_m_HxFu0CWUaIJKcoGORLtJxE3PajGM86pj4QhWw", pk);
    z_helpers_sk_bs64_to_bin("4axNsumJG5NOvfXVTS88L3_vW8CGlc6EvjfYriv8RJXlOL-b8fEW7QJZRogkpygY5Eu0nETc9qMYzzqmPhCFbA", sk);

    LocalPeer server;
    z_initialize_local_peer(&server, pk, sk, NULL, NULL, NULL);
    if (z_listen(&server, "0.0.0.0", 6339))
        perror("Failed to listen:");

    RemotePeer client;
    while (z_accept(&server, &client) == 0) {
        z_stop(&server);

        char client_pk_bs64[PK_BS64_LENGTH];
        z_helpers_pk_bin_to_bs64(client.pk, client_pk_bs64);
        printf("[+] Server '%s' connected.\n", client_pk_bs64);

        Message request;
        if (z_receive(&client, &request))
            continue;
        printf("Receive (%db) : %s\n", request.content_length, request.content);
        free(request.content);

        if (z_reply(&client, "ok.", 4, request.id))
            continue;

        z_disconnect(&client);
        printf("[-] Server '%s' disconnected.\n", client_pk_bs64);
    }

    printf("Server stopped.\n");
}
