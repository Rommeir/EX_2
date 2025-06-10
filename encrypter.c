#include "encrypter.h"
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
#define PASSWORD_KEY_RATIO 8
#define ENCRYPTED_BUFFER_MARGIN 2

#ifndef HAVE_STRDUP
char* strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char* copy = malloc(len);
    if (copy) memcpy(copy, s, len);
    return copy;
}
#endif

void generate_random_printable(char* buf, int len) {
    for (int i = 0; i < len; ++i) {
        buf[i] = (rand() % (PRINTABLE_ASCII_END - PRINTABLE_ASCII_START + 1)) + PRINTABLE_ASCII_START;
    }
}

int allocate_buffers(shared_data_t* shared, char** password, char** key, char** encrypted) {
    *password = malloc(shared->key_len * PASSWORD_KEY_RATIO + 1);
    *key = malloc(shared->key_len + 1);
    *encrypted = malloc((shared->password_len + PASSWORD_KEY_RATIO) * ENCRYPTED_BUFFER_MARGIN);
    if (!*password || !*key || !*encrypted) {
        print_log("SERVER", "ERROR", "Memory allocation failed\n");
        free(*password);
        free(*key);
        free(*encrypted);
        return 0;
    }
    return 1;
}

int generate_password_and_key(shared_data_t* shared, char* password, char* key) {
    generate_random_printable(password, shared->password_len);
    generate_random_printable(key, shared->key_len);
    password[shared->password_len] = '\0';
    key[shared->key_len] = '\0';
    return 1;
}

int encrypt_password(shared_data_t* shared, const char* password, const char* key, char* encrypted, unsigned int* actual_encrypted_len) {
    MTA_CRYPT_RET_STATUS enc_ret = MTA_encrypt(
        key, (unsigned int)shared->key_len,
        password, (unsigned int)shared->password_len,
        encrypted, actual_encrypted_len
    );

    if (enc_ret != MTA_CRYPT_RET_OK) {
        print_log("SERVER", "ERROR", "Encryption failed (code %d)\n", enc_ret);
        return 0;
    }

    print_log("SERVER", "INFO", "New password generated: %s, key: %s, After encryption: ", password, key);
    for (unsigned int i = 0; i < *actual_encrypted_len; ++i) {
        printf("%02X", (unsigned char)encrypted[i]);
    }
    printf("\n");

    return 1;
}

void update_shared_data(shared_data_t* shared, const char* password, const char* encrypted, unsigned int encrypted_len) {
    pthread_mutex_lock(&shared->mutex);

    if (shared->encrypted_password) free(shared->encrypted_password);
    if (shared->plain_password) free(shared->plain_password);

    shared->encrypted_password = malloc(encrypted_len);
    shared->plain_password = strdup(password);

    if (!shared->encrypted_password || !shared->plain_password) {
        print_log("SERVER", "ERROR", "Memory allocation failed\n");
        pthread_mutex_unlock(&shared->mutex);
        exit(EXIT_FAILURE);
    }

    memcpy(shared->encrypted_password, encrypted, encrypted_len);
    shared->password_len = encrypted_len;
    shared->password_version += 1;
    shared->found = 0;
    pthread_cond_broadcast(&shared->cond_new_password);
    pthread_mutex_unlock(&shared->mutex);
}

void wait_for_password_use(shared_data_t* shared) {
    time_t start = time(NULL);
    while (true) {
        pthread_mutex_lock(&shared->mutex);
        if (shared->found) {
            pthread_mutex_unlock(&shared->mutex);
            break;
        }

        struct timespec ts;
        ts.tv_sec = time(NULL) + 1;
        ts.tv_nsec = 0;
        pthread_cond_timedwait(&shared->cond_found, &shared->mutex, &ts);
        pthread_mutex_unlock(&shared->mutex);

        if (time(NULL) - start >= shared->timeout_sec) {
            print_log("SERVER", "ERROR", "No password received during the configured timeout period (%d seconds), regenerating password\n", shared->timeout_sec);
            break;
        }
    }
}

void* encrypter_thread(void* arg) {
    shared_data_t* shared = (shared_data_t*)arg;
    srand(time(NULL) ^ getpid());

    while (true) {
        char *password = NULL, *key = NULL, *encrypted = NULL;
        if (!allocate_buffers(shared, &password, &key, &encrypted)) exit(EXIT_FAILURE);

        generate_password_and_key(shared, password, key);

        unsigned int encrypted_len = 0;
        if (!encrypt_password(shared, password, key, encrypted, &encrypted_len)) {
            free(password); free(key); free(encrypted);
            continue;
        }

        update_shared_data(shared, password, encrypted, encrypted_len);
        wait_for_password_use(shared);

        free(password); free(key); free(encrypted);
    }

    return NULL;
}
