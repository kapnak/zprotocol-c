#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../src/zprotocol.h"


void on_connection_server(RemotePeer *peer) {
    char peer_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(peer->pk, peer_pk_bs64);
    printf("[+] Peer '%s' connected.\n", peer_pk_bs64);
}


void on_message_server(RemotePeer *remotePeer, Message *message) {
    char remote_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(remotePeer->pk, remote_pk_bs64);
    printf("[%s] Says : %s\n", remote_pk_bs64, message->content);
    if (z_reply(remotePeer, "I got your message.", 20, message->id) < 0)
        printf("Can't send the reply :/\n");
    z_cleanup_message(message);
}


void on_disconnect_server(RemotePeer *peer) {
    static int count = 0;
    char peer_pk_bs64[PK_BS64_LENGTH];
    z_helpers_pk_bin_to_bs64(peer->pk, peer_pk_bs64);
    printf("[-] Peer '%s' disconnected.\n", peer_pk_bs64);
    count++;
    if (count == 2)
        z_stop(peer->local_peer);
    sleep(2);
}


void wait_all() {
    int status;
    pid_t pid;
    int n = 0;
    while (n < 10) {
        pid = wait(&status);
        n++;
    }
}

int main() {
    // Server public key
    unsigned char server_pk[ED25519_PK_LENGTH];
    z_helpers_pk_bs64_to_bin("5Ti_m_HxFu0CWUaIJKcoGORLtJxE3PajGM86pj4QhWw", server_pk);

    if (fork() == 0) {
        // Server
        unsigned char server_sk[ED25519_SK_LENGTH];
        LocalPeer server;

        z_helpers_sk_bs64_to_bin("4axNsumJG5NOvfXVTS88L3_vW8CGlc6EvjfYriv8RJXlOL-b8fEW7QJZRogkpygY5Eu0nETc9qMYzzqmPhCFbA", server_sk);
        z_initialize_local_peer(&server, server_pk, server_sk, on_message_server, on_connection_server, on_disconnect_server);
        if (z_listen(&server, "127.0.0.1", 5000) < 0)
            perror("listen");
        printf("Server stop listening.\n");
    } else {
        sleep(1);
        unsigned char pk[ED25519_PK_LENGTH];
        unsigned char sk[ED25519_SK_LENGTH];
        z_helpers_pk_bs64_to_bin("yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU", pk);
        z_helpers_sk_bs64_to_bin("7AweZshFG13B-Hkch8Rny4rEKRofaBJFafpXy_s-lmTJ9PSu6YjsAwii54AJr8QAu3ppGFctlcKoQsBFVZG-JQ", sk);

        Message reply;
        char request[] = "Hello world!";
        LocalPeer client;
        RemotePeer server;
        z_initialize_local_peer(&client, pk, sk, NULL, NULL, NULL);

        z_connect(&client, &server, "127.0.0.1", 5000, NULL);
        z_send(&server, request, strlen(request)+1, 0, NULL);
        if (z_receive(&server, &reply) < 0)
            return 1;
        printf("Receive reply (%db) : %s\n", reply.content_length, reply.content);
        free(reply.content);
        z_disconnect(&server);

        z_connect(&client, &server, "127.0.0.1", 5000, server_pk);
        z_send(&server, request, strlen(request)+1, 0, NULL);
        z_send(&server, request, strlen(request)+1, 0, NULL);
        if (z_receive(&server, &reply) < 0)
            return 1;
        printf("Receive reply (%db) : %s\n", reply.content_length, reply.content);
        free(reply.content);
        if (z_receive(&server, &reply) < 0)
            return 1;
        printf("Receive reply (%db) : %s\n", reply.content_length, reply.content);
        free(reply.content);
        z_send(&server, request, strlen(request)+1, 0, NULL);
        z_disconnect(&server);
    }

    wait_all();

    return 0;
}
