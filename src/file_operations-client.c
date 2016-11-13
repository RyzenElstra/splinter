#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/sha256.h"

#include "splinter-client.h"

void upload_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    FILE* local_file = NULL;
    char *first_file = NULL, *put_file = NULL;
    unsigned int remain_data = 0, i = 0;
    struct stat st;
    int fd = 0;
    size_t file_size = 0, sent_bytes = 0, total_sent = 0;
    mbedtls_sha256_context file_hash;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];

    put_file = (char*)compress->orig_buffer;
    strsep(&put_file, " ");
    first_file = strsep(&put_file, " ");
    printf("File upload: %s\n", first_file);

    if (access(first_file, F_OK) == -1){
        printf("File not found\n");
        return;
    }

    if (access(first_file, R_OK) == -1) {
        printf("Access denied\n");
        return;
    }

    local_file = fopen(first_file, "rb");
    if (local_file == NULL) {
        perror("error opening file");
        return;
    }

    fd = fileno(local_file);
    if (fd == -1) {
        perror("Unable to get fileno");
    }

    //Get local file size
    memset(&st, 0, sizeof(struct stat));
    if (stat(first_file, &st) == -1) {
        perror("stat error");
    }

    //Get the file size
    file_size = st.st_size;
    printf("File size %zd bytes\n", file_size);

    //Send file size for the other side to receive
    if ( mbedtls_ssl_write(&ssl, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
        printf("Error: %s", strerror(errno));
        return;
    }

    remain_data = file_size;
    sent_bytes = 0;
    total_sent = 0;

    //Initialize for SHA256 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    compress->orig_size = 0;
    compress->transformed_size = 0;
    // Sending file data
    while ((compress->orig_size = fread(compress->orig_buffer, 1, BUFFER_SIZE, local_file)) > 0) {
        printf("Read: %d\n", compress->orig_size);
        mbedtls_sha256_update(&file_hash, compress->orig_buffer, compress->orig_size);
        compress_buffer(compress);
        sent_bytes += mbedtls_ssl_write(&ssl, compress->transformed_buffer, compress->transformed_size);
        fprintf(stdout, "Sent %zu bytes from file's data, remaining data = %d\n", sent_bytes, remain_data);
        total_sent += compress->orig_size;
        remain_data -= compress->orig_size;
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    }

    if (total_sent < file_size) {
        fprintf(stderr, "incomplete transfer from sendfile: %zu of %zu bytes\n", total_sent, file_size);
    } else {
        printf("Finished transferring %s\n", first_file);
    }
    printf("Compressed: %f%%\n", ((sent_bytes / (double)total_sent)*100));

    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    mbedtls_sha256_free(&file_hash);
    fclose(local_file);

    return;
}

void download_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    char* command = malloc(BUFFER_SIZE);
    int offset = 0;
    size_t file_size = 0, size_recv = 0 ;
    FILE* local_file = NULL;
    char *first_file = NULL, *second_file = NULL, *command_start = NULL;
    unsigned int remain_data = 0, i = 0;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];
    mbedtls_sha256_context file_hash;

    command_start = strncpy(command, (char*)compress->orig_buffer, BUFFER_SIZE);
    if (strsep(&command, " ") == NULL){
        perror("Error parsing download");
    }
    first_file = strsep(&command, " ");
    second_file = strsep(&command, " ");
    printf("File download: %s -> %s\n", first_file, second_file);

    if (second_file == NULL){
        printf("Second file is null\n");
        second_file = first_file;
    }

    local_file = fopen(second_file, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        exit(-1);
    }

    file_size = 0;
    size_recv = 0;
    if ((size_recv = mbedtls_ssl_read(&ssl, (unsigned char*) &file_size, sizeof(size_t))) > 0) {
        if (size_recv == (unsigned int)-1) {
            perror("Error recving");
        }
    }
    printf("File size %zd\n", file_size);

    if (file_size == 0){
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE);
        decompress_buffer(compress);
        printf("File download error: %s\n", compress->transformed_buffer);
        free(command_start);
        fclose(local_file);
        return;
    }

    //Initialize SHA1 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    remain_data = 0;
    offset = 0;
    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    while (((compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE)) > 0) || (remain_data < file_size)) {
        decompress_buffer(compress);
        mbedtls_sha256_update(&file_hash, compress->transformed_buffer, compress->transformed_size);
        offset = fwrite(compress->transformed_buffer, 1, compress->transformed_size, local_file);
        remain_data += offset;
        fprintf(stdout, "Received %d bytes out of %d bytes\n", remain_data, (int)file_size);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        if (remain_data == file_size) {
            break;
        }
    }
    printf("Finished writing file %s\n", second_file);

    //Hash check
    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    printf("Changing permissions to 644\n");
    if (chmod(second_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) == -1) {
        printf("Unable to chmod\n");
    }

    free(command_start);
    fclose(local_file);

    return;
}
