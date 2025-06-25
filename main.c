#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "mta_crypt.h"
#include "shared_data.h"
#include "encrypter.h"
#include "decrypter.h"
#include "log_utils.h"

#define DEFAULT_TIMEOUT 30

void print_usage(const char* prog) {
    printf("Usage: %s -n num_of_decrypters -l password_len [-t timeout_sec]\n", prog);
    printf("  -n, --num-of-decrypters : number of decrypter threads (required)\n");
    printf("  -l, --password-length   : password length (multiple of 8, required)\n");
    printf("  -t, --timeout           : timeout in seconds (default 30)\n");
}

void parse_arguments(int argc, char* argv[], int* num_decrypters, int* password_len, int* timeout_sec) {
    int opt;
    *timeout_sec = DEFAULT_TIMEOUT;

    while ((opt = getopt(argc, argv, "n:l:t:")) != -1) {
        switch (opt) {
            case 'n': *num_decrypters = atoi(optarg); break;
            case 'l': *password_len = atoi(optarg); break;
            case 't': *timeout_sec = atoi(optarg); break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (*num_decrypters <= 0 || *password_len <= 0) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (*password_len % 8 != 0) {
        printf("Password length must be a multiple of 8!\n");
        exit(EXIT_FAILURE);
    }
}

void init_shared_data(shared_data_t* shared_data, int password_len, int timeout_sec) {
    memset(shared_data, 0, sizeof(shared_data_t));
    shared_data->password_len = password_len;
    shared_data->key_len = password_len / 8;
    shared_data->timeout_sec = timeout_sec;

    pthread_mutex_init(&shared_data->mutex, NULL);
    pthread_cond_init(&shared_data->cond_new_password, NULL);
    pthread_cond_init(&shared_data->cond_found, NULL);
}

void create_threads(shared_data_t* shared_data, int num_decrypters, pthread_t* enc_thread, pthread_t** dec_threads,  decrypter_args_t** dec_args) {
    *dec_threads = malloc(sizeof(pthread_t) * num_decrypters);
    *dec_args = malloc(sizeof(decrypter_args_t) * num_decrypters);

    pthread_create(enc_thread, NULL, encrypter_thread, shared_data);
    for (int i = 0; i < num_decrypters; ++i) {
        (*dec_args)[i].shared = shared_data;
        (*dec_args)[i].client_id = i;
        pthread_create(&(*dec_threads)[i], NULL, decrypter_thread, &(*dec_args)[i]);
    }
}

void wait_for_threads(pthread_t enc_thread, pthread_t* dec_threads, int num_decrypters) {
    pthread_join(enc_thread, NULL);
    for (int i = 0; i < num_decrypters; ++i) {
        pthread_join(dec_threads[i], NULL);
    }
}

void cleanup(shared_data_t* shared_data, pthread_t* dec_threads, decrypter_args_t* dec_args) {
    free(dec_threads);
    free(dec_args);

    pthread_mutex_destroy(&shared_data->mutex);
    pthread_cond_destroy(&shared_data->cond_new_password);
    pthread_cond_destroy(&shared_data->cond_found);
}

int main(int argc, char* argv[]) {
    int num_decrypters = 0, password_len = 0, timeout_sec;

    parse_arguments(argc, argv, &num_decrypters, &password_len, &timeout_sec);

    if (MTA_crypt_init() != MTA_CRYPT_RET_OK) {
        printf("Failed to init encryption library!\n");
        return 1;
    }

    shared_data_t shared_data;
    init_shared_data(&shared_data, password_len, timeout_sec);

    pthread_t enc_thread;
    pthread_t* dec_threads = NULL;
    decrypter_args_t* dec_args = NULL;

    create_threads(&shared_data, num_decrypters, &enc_thread, &dec_threads, &dec_args);
    wait_for_threads(enc_thread, dec_threads, num_decrypters);
    cleanup(&shared_data, dec_threads, dec_args);

    return 0;
}
