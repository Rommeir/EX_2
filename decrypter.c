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

void* decrypter_thread(void* arg) {
    decrypter_args_t* args = (decrypter_args_t*)arg;
    shared_data_t* shared = args->shared;
    int client_id = args->client_id;
    srand(time(NULL) ^ (getpid() + client_id));

    int my_version = 0;

    while (1) {
        pthread_mutex_lock(&shared->mutex);
        while (my_version == shared->password_version) {
            pthread_cond_wait(&shared->cond_new_password, &shared->mutex);
        }
        my_version = shared->password_version;
        int len = shared->password_len;
        int key_len = shared->key_len;
        char* encrypted = (char*)malloc(len);
        memcpy(encrypted, shared->encrypted_password, len);
        pthread_mutex_unlock(&shared->mutex);

        char* key = (char*)malloc(key_len + 1);
        char* output = (char*)malloc(len * DECRYPT_OUTPUT_BUFFER_MULTIPLIER);

        unsigned long iter = 0;
        while (1) {
            pthread_mutex_lock(&shared->mutex);
            if (shared->found || my_version != shared->password_version) {
                pthread_mutex_unlock(&shared->mutex);
                break;
            }
            pthread_mutex_unlock(&shared->mutex);

            for (int i = 0; i < key_len; ++i) {
                key[i] = (rand() % (PRINTABLE_ASCII_END - PRINTABLE_ASCII_START + 1)) + PRINTABLE_ASCII_START;
            }
            key[key_len] = '\0';

            unsigned int actual_plain_len = 0;
            MTA_CRYPT_RET_STATUS dec_ret = MTA_decrypt(
                key, (unsigned int)key_len,
                encrypted, (unsigned int)len,
                output, &actual_plain_len);

            iter++;

            if (dec_ret != MTA_CRYPT_RET_OK) {
                continue;
            }

            int printable = 1;
            for (unsigned int i = 0; i < actual_plain_len; ++i) {
                if (!isprint(output[i])) {
                    printable = 0;
                    break;
                }
            }

            if (printable) {
                pthread_mutex_lock(&shared->mutex);

                if (my_version == shared->password_version && !shared->found) {
                    char client_label[CLIENT_LABEL_SIZE];
                    snprintf(client_label, sizeof(client_label), "CLIENT #%d", client_id);

                    if (strcmp(output, shared->plain_password) == 0) {
                        print_log(client_label, "INFO", "After decryption(");
                        for (int i = 0; i < len; ++i) printf("%02X", (unsigned char)encrypted[i]);
                        printf("), key guessed(%s), sending to server after %lu iterations\n", key, iter);

                        print_log("SERVER", "OK", "Password decrypted successfully by client %d, received(", client_id);
                        for (int i = 0; i < len; ++i) printf("%02X", (unsigned char)encrypted[i]);
                        printf("), is (%.*s)\n", (int)actual_plain_len, output);

                        shared->found = 1;
                        pthread_cond_signal(&shared->cond_found);
                    } else {
                        print_log("SERVER", "ERROR", "Wrong password received from client #%d(%.*s), should be (%s)\n",
                            client_id, (int)actual_plain_len, output, shared->plain_password);
                    }
                }

                pthread_mutex_unlock(&shared->mutex);
                break;
            }
        }

        free(encrypted);
        free(key);
        free(output);
    }

    return NULL;
}