#ifndef ENCRYPTER_H
#define ENCRYPTER_H

#include "shared_data.h"

void* encrypter_thread(void* arg);
void generate_random_printable(char* buf, int len);
int allocate_buffers(shared_data_t* shared, char** password, char** key, char** encrypted);
int generate_password_and_key(shared_data_t* shared, char* password, char* key);
int encrypt_password(shared_data_t* shared,  char* password,  char* key, char* encrypted, unsigned int* actual_encrypted_len);
void update_shared_data(shared_data_t* shared, const char* password, const char* encrypted, unsigned int encrypted_len);
void wait_for_password_use(shared_data_t* shared);

#endif
