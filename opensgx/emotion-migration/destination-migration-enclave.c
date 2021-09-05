/*
    author:yyx
    time:2021.9.3 21:30
*/

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>
#include <sgx-lib.h>
#include <sgx-utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EXPONENT 3
#define KEY_SIZE 128

void enclave_main()
{
    int listen_port = 8025, quote_port=8027, ret;		//listen and connect ports
    char *conf = "./destination-quote-enclave.conf";
    char *msg1="this is destination migration enclave";

    ret = emotion_sgx_remote_attest_me(listen_port, quote_port, conf);
    if(ret == 1) {
        puts("Remote Attestaion Success!");
    } else {
        puts("Remote Attestation Fail!");
    }
    
    sgx_exit(NULL);
}

