#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include "../src/zprotocol.h"


void on_connection_client(RemotePeer *remote_peer) {
    Message *reply;
    clock_t t;
    char request[] = "ping";
    t = clock();
    z_send(remote_peer, request, strlen(request)+1, -1, &reply);
    if (reply == NULL) {
        printf("Can't receive reply.\n");
    } else {
        t = clock() - t;
        printf("Encrypted : %f s\n", ((double)t)/CLOCKS_PER_SEC);
        printf("Reply : %s\n", reply->content);
        z_cleanup_message(reply);
        z_disconnect(remote_peer);
    }

}


void on_message_client(RemotePeer *remote_peer, Message *message) {
    z_cleanup_message(message);
}


void on_message_server(RemotePeer *remotePeer, Message *message) {
    if (z_reply(remotePeer, "Pong!", 5, message->id) < 0)
        printf("Can't send the reply :/\n");
    z_cleanup_message(message);
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

    if (fork() != 0) {
        // Server
        unsigned char server_sk[ED25519_SK_LENGTH];
        LocalPeer server;

        z_helpers_sk_bs64_to_bin("4axNsumJG5NOvfXVTS88L3_vW8CGlc6EvjfYriv8RJXlOL-b8fEW7QJZRogkpygY5Eu0nETc9qMYzzqmPhCFbA", server_sk);
        z_initialize_local_peer(&server, server_pk, server_sk, on_message_server, NULL, NULL);
        if (z_listen(&server, "127.0.0.1", 5000) < 0)
            printf("Cant't listen");
    } else {
        sleep(1);
        unsigned char pk[ED25519_PK_LENGTH];
        unsigned char sk[ED25519_SK_LENGTH];
        z_helpers_pk_bs64_to_bin("yfT0rumI7AMIoueACa_EALt6aRhXLZXCqELARVWRviU", pk);
        z_helpers_sk_bs64_to_bin("7AweZshFG13B-Hkch8Rny4rEKRofaBJFafpXy_s-lmTJ9PSu6YjsAwii54AJr8QAu3ppGFctlcKoQsBFVZG-JQ", sk);

        LocalPeer client;
        RemotePeer server;
        z_initialize_local_peer(&client, pk, sk, on_message_client, on_connection_client, NULL);

        z_connect(&client, &server, "127.0.0.1", 5000, NULL);
    }

    wait_all();

    return 0;
}
