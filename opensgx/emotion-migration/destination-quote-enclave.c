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
    int target_port = 8027, ret;		//listening destination ME on 8027 port

    ret = emotion_sgx_remote_attest_quote(target_port);
    if(ret == 1) {
        puts("Remote Attestaion Success!");
    } else {
        puts("Remote Attestation Fail!");
    }
    
    sgx_exit(NULL);
}


int emotion_sgx_remote_attest_quote(int target_port)
{
    report_t report;
    report_t report_send;
    targetinfo_t targetinfo;
    unsigned char nonce[64];
    char read_buf[512];
    int client_fd;    
    keyrequest_t keyreq;
    unsigned char report_key[DEVICE_KEY_LENGTH];
    const char *pers = "rsa_genkey";
    unsigned char *rsa_N, *rsa_E;
    
    rsa_N       = malloc(sizeof(mpi));
    rsa_E       = malloc(sizeof(mpi));

    printf("Listening to ME on %d ...",target_port);
    client_fd = sgx_make_server(target_port);
    if(client_fd < 0) {
        puts("sgx_make_server error\n");
        return -1;
    }
    puts("Target enclave accepted");
      
    //Get REPORT from Target enclave
    if(sgx_get_report(client_fd, &report) < 0) {
        puts("sgx_get_report error\n");
        goto failed;
    }
    puts("Received REPORT from ME");
    
    //Get Report key from QEMU
    keyreq.keyname = REPORT_KEY;
    memcpy(&keyreq.keyid, &report.keyid, 16);
    memcpy(&keyreq.miscmask, &report.miscselect, 4);    
    sgx_getkey(&keyreq, report_key);
    puts("Received Report Key");

    //Check MAC matching
    if(sgx_match_mac(report_key, &report) < 0) {
        puts("Mac not match!\n");
        goto failed;
    }
    puts("MAC match, PASS!");

    //EREPORT with given report
    puts("Sending REPORT to Target enclave ...");
    memcpy(&targetinfo.measurement, &report.mrenclave, 32);
    memcpy(&targetinfo.attributes, &report.attributes, 16);
    memcpy(&targetinfo.miscselect, &report.miscselect, 4);
    sgx_report(&targetinfo, nonce, &report_send);
    if(sgx_write_sock(client_fd, &report_send, sizeof(report_t)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    
    //Get intra attestation result of Target enclave
    memset(read_buf, 0, sizeof(read_buf));
    if(sgx_read_sock(client_fd, read_buf, sizeof(read_buf)) <= 0) {
        puts("sgx_read_sock error\n");
        goto failed;
    }
    printf("Target enclave msg: %s\n", read_buf);
    if(strcmp(read_buf, "Good") != 0) {
        puts("Target enclave denied");
        goto failed;
    }

    //Make RSA & QUOTE
    sgx_make_quote(pers, &report, rsa_N, rsa_E);

    //Send quote
    if(sgx_write_sock(client_fd, rsa_N, sizeof(mpi)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    if(sgx_write_sock(client_fd, rsa_E, sizeof(mpi)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    if(sgx_write_sock(client_fd, &report, sizeof(report_t)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    
    close(client_fd);
    puts("Quoting enclave end");
    return 1;
failed:
    close(client_fd);
    return -1;
}