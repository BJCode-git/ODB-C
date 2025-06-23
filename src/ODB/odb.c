#include <ODB/odb.h>

// Declare ODB Global Variables
// HashMaps
ConnectionTable*                 up_connections   	= NULL;
ConnectionTable*                 down_connections 	= NULL;
ODB_RemoteAccessBuffer*          intern_RAB       	= NULL;
ODB_ProtectedMemoryTable*        intern_PMT       	= NULL;
ODB_FailedRemoteAccessBuffer*    intern_Failed_RAB  = NULL;

// Configuration
ODB_Config ODB_conf = ODB_Config_INITIALIZER;

// Original functions

ssize_t (*original_recv)(int, void*, ssize_t,int ) = NULL;
ssize_t (*original_recvfrom)(int, void *, size_t, int,struct sockaddr*, socklen_t*) = NULL;
ssize_t (*original_recvmsg)(int , struct msghdr*, int) = NULL;
ssize_t (*original_read)(int, void *, size_t) = NULL;
ssize_t (*original_readv)(int, const struct iovec *, int) = NULL;
ssize_t (*original_write)(int, const void *, size_t) = NULL;
ssize_t (*original_writev)(int, const struct iovec *, int) = NULL;
ssize_t (*original_send)(int, const void *, size_t , int) = NULL;
ssize_t (*original_sendto)(int, const void *, size_t , int ,const struct sockaddr *, socklen_t ) = NULL;
ssize_t (*original_sendmsg)(int, const struct msghdr *, int) = NULL;
ssize_t (*original_sendfile)(int, int, off_t *, size_t) = NULL;
int     (*original_close)(int fd) = NULL;
int     (*original_accept)(int sockfd, struct sockaddr *adr, socklen_t *len) = NULL;
ssize_t (*original_splice)(int fd_in, loff_t *off_in, int fd_out,loff_t *off_out, size_t len, unsigned int flags) = NULL;
pid_t 	(*original_fork)(void) = NULL;

