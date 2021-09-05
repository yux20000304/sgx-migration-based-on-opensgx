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
    int target_port = 8025, ret;
    const char *msg1 = "Are you SGX enclave?";          //generate first msg

    ret = sgx_remote_attest_challenger(target_ip, target_port, msg1);
    if(ret == 1) {
        puts("Remote Attestaion Success!");
    } else {
        puts("Remote Attestation Fail!");
    }

    sgx_exit(NULL);
}