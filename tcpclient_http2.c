/* 
 * tcpclient.c - A simple TCP client
 * usage: tcpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

#define BUFSIZE 102400

#include "http2.h"
#include "linklist.h"

char read_buff[BUFSIZE];
char hex_buff[BUFSIZE];

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

void print_hex(char *data, int len, char *buff)
{
    int i = 0;
    int b_len = 0;
    for(i = 0; i < len; i++)
    {
        b_len += sprintf(buff + b_len, "%02x ", (data[i] & 0xff));
    }
}

void create_msg(STREAM_INFO *info)
{
    char err[1024];
    http2_add_header(info, ":authority", "www.example.com", err);
    http2_add_header(info, ":method", "POST", err);
    http2_add_header(info, ":path", "/", err);
    http2_add_header(info, ":scheme", "http", err);
    http2_add_header(info, "user-agent", "Equinox-HTTP2-Ngine-v.1.0.0xxxxxvvvvvvvvvvvv;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;;;;;;x", err);
    http2_add_header(info, "accept-encoding", "gzip, deflate", err);
    http2_add_header(info, "accept", "*/*", err);
    http2_add_header(info, "www-authenticate", "Basic", err);
    //http2_add_header(info, "Equinox-server-version", "1.5.1", err);
    
    http2_add_data(info, "12345678910101010", 17, err);
    
    http2_create_msg(info, 1, err);
}
//index.html
int main(int argc, char **argv) {
    int sockfd, portno, n, r, wflag = 0 ;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[10240];
    fd_set rfd,wfd;
    int max_connection = 1000;
        
    struct timeval tv;
    FD_ZERO(&wfd);
    FD_ZERO(&rfd);
    
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    
    /*ff = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, ff | O_NONBLOCK);*/
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){}
      //error("ERROR connecting");
    struct sockaddr_in sin;
    bzero((char *) &sin, sizeof(sin));
    socklen_t len = sizeof(sin);
    if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
        perror("getsockname");
    else
    {
        char buff[256];
        inet_ntop(AF_INET, &(sin.sin_addr), buff, sizeof(buff)-1);
        printf("Address number %s\n", buff);
        printf("port number %d\n", ntohs(sin.sin_port));
        
    }
    printf("Sock is %d\n", sockfd);
    int seq = 0;
    HTTP2_CONNECTION *conn = http2_init(HTTP2_MODE_CLIENT, sockfd, NULL,NULL,&(max_connection),NULL,NULL,NULL,buf);
    while(1)
    {
        FD_SET(conn->sock, &wfd);
        FD_SET(conn->sock, &rfd);
        r = select (conn->sock +1, &rfd, &wfd, NULL, &tv);
        printf("r = %d\n", r);
        if(FD_ISSET(conn->sock, &wfd)){
            /* get message line from the user */
            wflag++;
            //if(seq >= 1)FD_CLR(conn->sock, &wfd);
            
            if(seq <= 1){
                STREAM_INFO *info = http2_init_stream_info_send(conn, HTTP2_ID_CLIENT_INIT, buf);
                create_msg(info);
            }
            else
            {
                //http2_goaway_build(conn, conn->last_stream_id_recv, HTTP2_ERROR_CODE_NO_ERROR, "Hello");
            }
            seq++;
            while(http2_need_write(conn))
            {
                /* send the message line to the server */
                http2_write(conn, buf);
            }
            //http2_stream_info_destroy(&info);
        }
        if(wflag > 0){
            /* print the server's reply */
            bzero(read_buff, BUFSIZE);
            printf("Before read\n");
            n = http2_read(conn, read_buff);
            printf("After read[%d]\n", n);
            if (n < 0) 
            {
              printf("ERROR reading from socket [%s]\n", read_buff);
              break;
            }
            STREAM_INFO *infox = NULL;
            int len = 0;
decode_again:
            read_buff[0] = 0x0;
            n = http2_decode(conn, &infox, &len, read_buff);
            switch(n)
            {
                case HTTP2_RETURN_SUCCESS:
                case HTTP2_RETURN_SKIP_DATA:
                goto decode_again;
                break;
                case HTTP2_RETURN_CONNECTION_CLOSE:
                goto exit_loop;
                break;
                default:
                break;
            }
            //print_hex(read_buff, n, hex_buff);
            printf("Echo from server:\n");
            HTTP2_HEADER *hh = NULL;
            while(infox && infox->data_recv.first_header_list)
            {
                POP_HEADER(infox->data_recv.first_header_list, hh);
                printf("Header name [%s] value [%s]\n", hh->name, hh->value);
                free(hh);
            }
            printf("ERR %s\n", read_buff);
        }
        //sleep(1);
    }
exit_loop:
    http2_destroy(&conn);
    
    close(sockfd);
    return 0;
}