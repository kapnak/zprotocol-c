#include <string.h>
#include <unistd.h>
#include "../src/zprotocol.h"


void on_connection(RemotePeer *client) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(client->pk, client_pk_bs64);
    printf("[+] Server '%s' connected.\n", client_pk_bs64);
}


void on_message(RemotePeer *client, Message *message) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(client->pk, client_pk_bs64);
    printf("[%s] Says : %s\n", client_pk_bs64, message->content);

    char reply[] = "ok.";
    z_reply(client, reply, strlen(reply)+1, message->id);
    z_cleanup_message(message);
}


void on_disconnect(RemotePeer *client) {
    char client_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(client->pk, client_pk_bs64);
    printf("[-] Server '%s' disconnected.\n", client_pk_bs64);
    z_stop(client->local_peer);
}


int main() {
    unsigned char pk[ED25519_PK_LENGTH];
    unsigned char sk[ED25519_SK_LENGTH];
    //z_helpers_pk_bs64_to_bin("5Ti_m_HxFu0CWUaIJKcoGORLtJxE3PajGM86pj4QhWw", pk);
    //z_helpers_sk_bs64_to_bin("4axNsumJG5NOvfXVTS88L3_vW8CGlc6EvjfYriv8RJXlOL-b8fEW7QJZRogkpygY5Eu0nETc9qMYzzqmPhCFbA", sk);
    z_helpers_read_kp("server.sk", pk, sk);
    LocalPeer server;
    z_initialize_local_peer(&server, pk, sk, on_message, on_connection, on_disconnect);
    z_listen(&server, "0.0.0.0", 6339);
    printf("Server stopped.\n");
    return 0;
}
