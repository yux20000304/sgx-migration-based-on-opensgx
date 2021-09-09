/*
    author:yyx
    time:2021.9.3 21:30
*/

#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void enclave_main()
{
    const char *target_ip = "127.0.0.1";
    int target_port = 8025, quote_port= 8026, ret;
    char *conf = "./source-quote-enclave.conf";
    const char *msg2 = "this is source migration enclave";          //generate first msg

    ret = emotion_sgx_remote_attest_challenger(target_ip, target_port);
    if(ret == 1) {
        puts("Remote Attestaion Success!");
    } else {
        puts("Remote Attestation Fail!");
    }
    ret=source_emotion_sgx_remote_attest_me(target_port, quote_port, conf, msg2);
    sgx_exit(NULL);
}

