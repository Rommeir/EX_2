#include "decrypter.h"
#include "log_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include "mta_crypt.h"
#include "shared_data.h"
#define PRINTABLE_ASCII_START 32
#define PRINTABLE_ASCII_END 126
#define DECRYPT_OUTPUT_BUFFER_MULTIPLIER 2
#define CLIENT_LABEL_SIZE 32

void copy_encrypted_password(shared_data_t* shared, int* version_out, char** encrypted_out, int* len_out, int* key_len_out) {
    pthread_mutex_lock(&shared->mutex);
    *version_out = shared->password_version;
    *len_out = shared->password_len;
    *key_len_out = shared->key_len;
    *encrypted_out = (char*)malloc(*len_out);
    memcpy(*encrypted_out, shared->encrypted_password, *len_out);
    pthread_mutex_unlock(&shared->mutex);
}

void generate_random_key(char* key, int key_len) {
    for (int i = 0; i < key_len; ++i) {
        key[i] = (rand() % (PRINTABLE_ASCII_END - PRINTABLE_ASCII_START + 1)) + PRINTABLE_ASCII_START;
    }
    key[key_len] = '\0';
}

int is_printable_ascii(const char* str, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i) {
        if (!isprint(str[i])) return 0;
    }
    return 1;
}

int handle_successful_decryption(shared_data_t* shared, int client_id, int version, const char* key, const char* encrypted, int encrypted_len, const char* output, unsigned int plain_len, unsigned long iter) {
    pthread_mutex_lock(&shared->mutex);

    if (version == shared->password_version && !shared->found) {
        char client_label[CLIENT_LABEL_SIZE];
        snprintf(client_label, sizeof(client_label), "CLIENT #%d", client_id);

        if (strcmp(output, shared->plain_password) == 0) {
            print_log(client_label, "INFO", "After decryption(");
            for (int i = 0; i < encrypted_len; ++i) printf("%02X", (unsigned char)encrypted[i]);
            printf("), key guessed(%s), sending to server after %lu iterations\n", key, iter);

            print_log("SERVER", "OK", "Password decrypted successfully by client %d, received(", client_id);
            for (int i = 0; i < encrypted_len; ++i) printf("%02X", (unsigned char)encrypted[i]);
            printf("), is (%.*s)\n", (int)plain_len, output);

            shared->found = 1;
            pthread_cond_signal(&shared->cond_found);
            pthread_mutex_unlock(&shared->mutex);
            return 1;
        } else {
            print_log("SERVER", "ERROR", "Wrong password received from client #%d(%.*s), should be (%s)\n",
                      client_id, (int)plain_len, output, shared->plain_password);
        }
    }

    pthread_mutex_unlock(&shared->mutex);
    return 0;
}

void attempt_decryption_loop(shared_data_t* shared, int client_id, int version,  char* encrypted, int len, int key_len) {
    char* key = (char*)malloc(key_len + 1);
    char* output = (char*)malloc(len * DECRYPT_OUTPUT_BUFFER_MULTIPLIER);
    unsigned long iter = 0;

    while (true) {
        pthread_mutex_lock(&shared->mutex);
        if (shared->found || version != shared->password_version) {
            pthread_mutex_unlock(&shared->mutex);
            break;
        }
        pthread_mutex_unlock(&shared->mutex);

        generate_random_key(key, key_len);

        unsigned int plain_len = 0;
        MTA_CRYPT_RET_STATUS ret = MTA_decrypt(
            key, (unsigned int)key_len,
            encrypted, (unsigned int)len,
            output, &plain_len
        );

        iter++;

        if (ret != MTA_CRYPT_RET_OK) continue;

        if (is_printable_ascii(output, plain_len)) {
            if (handle_successful_decryption(shared, client_id, version, key, encrypted, len, output, plain_len, iter)) {
                break;
            } else {
                break;  // even if wrong password, we stop
            }
        }
    }

    free(key);
    free(output);
}

void* decrypter_thread(void* arg) {
    decrypter_args_t* args = (decrypter_args_t*)arg;
    shared_data_t* shared = args->shared;
    int client_id = args->client_id;
    srand(time(NULL) ^ (getpid() + client_id));

    int my_version = 0;

    while (true) {
        pthread_mutex_lock(&shared->mutex);
        while (my_version == shared->password_version) {
            pthread_cond_wait(&shared->cond_new_password, &shared->mutex);
        }
        pthread_mutex_unlock(&shared->mutex);

        char* encrypted = NULL;
        int len = 0, key_len = 0;
        copy_encrypted_password(shared, &my_version, &encrypted, &len, &key_len);
        attempt_decryption_loop(shared, client_id, my_version, encrypted, len, key_len);
        free(encrypted);
    }

    return NULL;
}
