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


int source_emotion_sgx_remote_attest_me(int listen_port, int quote_port, char *conf, char *msg2)
{
    // Quoting enclave in same platform
    const char *quote_ip = "127.0.0.1";

    targetinfo_t targetinfo;
    unsigned char nonce[64];
    char read_buf[512];

    report_t report;
    report_t report_send;
    report_t quote;
    
    int client_fd, quote_fd;
    sigstruct_t *sigstruct; 
    char *resultmsg;
    keyrequest_t keyreq;
    unsigned char report_key[DEVICE_KEY_LENGTH];
    unsigned char *rsa_N, *rsa_E;

    rsa_N = malloc(sizeof(mpi));
    rsa_E = malloc(sizeof(mpi));
        

    //listening to source ME
    printf("Listening to source ME on %d ...\n",listen_port);
    client_fd = sgx_make_server(listen_port);
    if(client_fd < 0) {
        puts("sgx_make_server error\n");
        return -1;
    }
    
    //msg1 has already been generated
    puts("Generating msg2 ...");

    
    //Connect to Quoting enclave
    printf("Connecting to QE on %d ...\n",quote_port);
    quote_fd = sgx_connect_server(quote_ip, quote_port);
    if(quote_fd < 0) {
        puts("sgx_connect_server error\n");
        close(client_fd);
        return -1;
    }

     //Get SIGSTRUCT of Quoting enclave
    sigstruct = sgx_load_sigstruct(conf);
    puts("Got SIGSTRUCT!\n");


     puts("Generating REPORT for msg2 ..."); 
    
    puts("Sending request of REPORT for msg2 ...");
     //EREPORT with sigstruct
    memcpy(&targetinfo.measurement, &sigstruct->enclaveHash, 32);
    memcpy(&targetinfo.attributes, &sigstruct->attributes, 16);
    memcpy(&targetinfo.miscselect, &sigstruct->miscselect, 4);
    sgx_report(&targetinfo, nonce, &report_send);
    if(sgx_write_sock(quote_fd, &report_send, sizeof(report_t)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }

     //Get REPORT from Quoting enclave   
    if(sgx_get_report(quote_fd, &report) < 0) {
        puts("sgx_get_report error\n");
        goto failed;
    }
    puts("Received REPORT from Quoting enclave");

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

    //Send intra attestaion result to Quoting enclave
    puts("Sending result message to Quoting enclave ...");
    resultmsg = "Good";
    if(sgx_write_sock(quote_fd, resultmsg, strlen(resultmsg)) < 0) {
        puts("sgx_write_sock error\n");
    }

    puts("Waiting for RSA key and QUOTE ...");
    //Receive rsa_N
    memset(rsa_N, 0, sizeof(mpi));
    if(sgx_read_sock(quote_fd, rsa_N, sizeof(mpi)) <= 0) {
        puts("sgx_read_sock error\n");
        goto failed;
    }
    puts("Received rsa_N from Quoting enclave");

    //Receive rsa_E
    memset(rsa_E, 0, sizeof(mpi));
    if(sgx_read_sock(quote_fd, rsa_E, sizeof(mpi)) <= 0) {
        puts("sgx_read_sock error\n");
        goto failed;
    }
    puts("Received rsa_E from Quoting enclave");
    
    //Receive QUOTE
    memset(&quote, 0, sizeof(quote));
    if(sgx_get_report(quote_fd, &quote) < 0) {
        goto failed;
    }
    puts("Received QUOTE from Quoting enclave");

    //send to host ME
    puts("Sending RSA & QUOTE & msg2 to destination ME\n");
    if(sgx_write_sock(client_fd, rsa_N, sizeof(mpi)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    if(sgx_write_sock(client_fd, rsa_E, sizeof(mpi)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    if(sgx_write_sock(client_fd, &quote, sizeof(report_t)) < 0) {
        puts("sgx_write_sock error\n");
        goto failed;
    }
    if(sgx_write_sock(client_fd,&msg1, strlen(msg1)) < 0){
        puts("sgx_write_sock error\n");
    }


    close(quote_fd);
    close(client_fd);
    puts("Target enclave end");
    return 1;
failed:
    close(quote_fd);
    close(client_fd);
    return -1;
}