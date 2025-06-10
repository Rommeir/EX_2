#ifndef DECRYPTER_H
#define DECRYPTER_H

#include "shared_data.h"

typedef struct {
    shared_data_t* shared;
    int client_id;
} decrypter_args_t;

void* decrypter_thread(void* arg);
void copy_encrypted_password(shared_data_t* shared, int* version_out, char** encrypted_out, int* len_out, int* key_len_out);
void generate_random_key(char* key, int key_len);
int is_printable_ascii(const char* str, unsigned int len);
int handle_successful_decryption(shared_data_t* shared, int client_id, int version, const char* key, const char* encrypted, int encrypted_len, const char* output, unsigned int plain_len, unsigned long iter);
void attempt_decryption_loop(shared_data_t* shared, int client_id, int version, const char* encrypted, int len, int key_len);

#endif
