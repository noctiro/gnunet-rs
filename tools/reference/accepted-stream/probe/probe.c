/* Public original libgnunetutil API probe, never a replacement network backend.
 * The optional inherited-fd query child only reads the duplicated owned socket. */
#include "gnunet_util_lib.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int value(int fd,int level,int option){int v=-1;socklen_t n=sizeof(v);if(getsockopt(fd,level,option,&v,&n)||n!=sizeof(v)){perror("query getsockopt");exit(95);}return v;}
static void options(int fd){int file_flags=fcntl(fd,F_GETFL),descriptor_flags=fcntl(fd,F_GETFD);if(file_flags<0||descriptor_flags<0){perror("query fcntl");exit(96);}struct linger linger;socklen_t len=sizeof(linger);if(getsockopt(fd,SOL_SOCKET,SO_LINGER,&linger,&len)||len!=sizeof(linger)){perror("query linger");exit(97);}printf("{\"nodelay\":%d,\"nonblocking\":%d,\"cloexec\":%d,\"keepalive\":%d,\"reuseaddr\":%d,\"type\":%d,\"linger_on\":%d,\"linger_seconds\":%d,\"nosigpipe\":",value(fd,IPPROTO_TCP,TCP_NODELAY),!!(file_flags&O_NONBLOCK),!!(descriptor_flags&FD_CLOEXEC),value(fd,SOL_SOCKET,SO_KEEPALIVE),value(fd,SOL_SOCKET,SO_REUSEADDR),value(fd,SOL_SOCKET,SO_TYPE),linger.l_onoff,linger.l_linger);
#ifdef SO_NOSIGPIPE
printf("%d",value(fd,SOL_SOCKET,SO_NOSIGPIPE));
#else
printf("null");
#endif
printf("}");}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--inspect")){options(STDIN_FILENO);putchar('\n');return 0;}
 if(argc!=4)return 90;int af=!strcmp(argv[1],"v4")?AF_INET:!strcmp(argv[1],"v6")?AF_INET6:0;int preset=!strcmp(argv[2],"default")?-1:!strcmp(argv[2],"off")?0:!strcmp(argv[2],"on")?1:-2;int address=!strcmp(argv[3],"address")?1:!strcmp(argv[3],"null-address")?0:-1;if(!af||preset==-2||address<0)return 91;
 GNUNET_log_setup("accepted-native-observer","WARNING",NULL);
 struct GNUNET_NETWORK_Handle *listener=GNUNET_NETWORK_socket_create(af,SOCK_STREAM,IPPROTO_TCP);if(!listener)return 2;
 if(preset!=-1){if(GNUNET_OK!=GNUNET_NETWORK_socket_setsockopt(listener,IPPROTO_TCP,TCP_NODELAY,&preset,sizeof(preset)))return 3;
#ifdef SO_NOSIGPIPE
 if(GNUNET_OK!=GNUNET_NETWORK_socket_setsockopt(listener,SOL_SOCKET,SO_NOSIGPIPE,&preset,sizeof(preset)))return 4;
#endif
 }
 struct sockaddr_storage local={0};socklen_t len;
 if(af==AF_INET){struct sockaddr_in *v=(void*)&local;v->sin_family=AF_INET;
#ifdef __APPLE__
v->sin_len=sizeof(*v);
#endif
v->sin_addr.s_addr=htonl(INADDR_LOOPBACK);len=sizeof(*v);}else{struct sockaddr_in6 *v=(void*)&local;v->sin6_family=AF_INET6;
#ifdef __APPLE__
v->sin6_len=sizeof(*v);
#endif
v->sin6_addr=in6addr_loopback;len=sizeof(*v);}
 if(GNUNET_OK!=GNUNET_NETWORK_socket_bind(listener,(const struct sockaddr*)&local,len)||GNUNET_OK!=GNUNET_NETWORK_socket_listen(listener,5))return 5;
 int fd=GNUNET_NETWORK_get_fd(listener);len=sizeof(local);if(getsockname(fd,(struct sockaddr*)&local,&len))return 6;
 printf("{\"actor\":\"normal-c\",\"family\":\"%s\",\"preset\":\"%s\",\"accept_mode\":\"%s\",\"listener\":",argv[1],argv[2],argv[3]);options(fd);
 int client=socket(af,SOCK_STREAM,IPPROTO_TCP);if(client<0||connect(client,(struct sockaddr*)&local,len))return 7;
 struct pollfd ready={fd,POLLIN,0};if(poll(&ready,1,3000)!=1)return 8;
 struct sockaddr_storage peer;socklen_t peerlen=sizeof(peer);struct GNUNET_NETWORK_Handle *accepted=GNUNET_NETWORK_socket_accept(listener,address?(struct sockaddr*)&peer:NULL,address?&peerlen:NULL);if(!accepted)return 9;
 int accepted_fd=GNUNET_NETWORK_get_fd(accepted);printf(",\"accepted_fd\":%d,\"fd_setsize\":%d,\"accepted\":",accepted_fd,FD_SETSIZE);options(accepted_fd);
 const char input='q';if(send(client,&input,1,0)!=1)return 10;ready.fd=accepted_fd;if(poll(&ready,1,3000)!=1)return 11;char got=0;if(GNUNET_NETWORK_socket_recv(accepted,&got,1)!=1||got!='q')return 12;
 printf(",\"actual_payload\":true}\n");close(client);if(GNUNET_OK!=GNUNET_NETWORK_socket_close(accepted)||GNUNET_OK!=GNUNET_NETWORK_socket_close(listener))return 13;return 0;
}
