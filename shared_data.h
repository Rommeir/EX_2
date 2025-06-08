#ifndef SHARED_DATA_H
#define SHARED_DATA_H

#include <pthread.h>

typedef struct {
    char* encrypted_password;
    char* plain_password;    
    int password_len;
    int key_len;
    int password_version;
    int found;
    int timeout_sec;
    pthread_mutex_t mutex;
    pthread_cond_t cond_new_password;
    pthread_cond_t cond_found;
} shared_data_t;

typedef struct {
    shared_data_t* shared;
    int client_id;
} decrypter_args_t;



#endif 
