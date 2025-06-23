#ifndef ODB_IO_H
#define ODB_IO_H

#define _GNU_SOURCE
#include <ODB/odb.h>
#include <ODB/odb-utils.h>
#include <ODB/odb-remote.h>


// For using RTLD_NEXT with dlsym


//ConnectionTable*            up_connections  = NULL;
//ConnectionTable*            down_connections= NULL;
//ODB_RemoteAccessBuffer*     intern_RAB      = NULL;
//ODB_ProtectedMemoryTable*   intern_PMT      = NULL;



/*** 
    In case of error we will try to call the original functions and abort the ODB process
***/


void init_original_functions();

//ssize_t strict_send(int fd,const void *buf, size_t count, int flags);

//ssize_t strict_recv(int fd, void *buf, size_t count,int flags);


// ************************************
// *                                  *
// *          close section           *
// *                                  *
// ************************************

int close(int fd);


// ************************************
// *                                  *
// *          accept section          *
// *                                  *
// ************************************

int accept(int sockfd, struct sockaddr *adr, socklen_t *len);

// ************************************
// *                                  *
// *            send section          *
// *                                  *
// ************************************

ssize_t send(int socket, const void *buf, size_t buf_len, int flags);

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

// ************************************
// *                                  *
// *          write section           *
// *                                  *
// ************************************

ssize_t write(int fd, const void *buf, size_t len);

ssize_t writev(int socket, const struct iovec *iov, int iovcnt);


// ************************************
// *                                  *
// *            Recv section          *
// *                                  *
// ************************************

ssize_t recv(int socket, void *buffer, size_t length, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

// ************************************
// *                                  *
// *           Read section           *
// *                                  *
// ************************************


ssize_t read(int fd, void *buf, size_t count);

ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

// ************************************
// *                                  *
// *          Sendfile section        *
// *                                  *
// ************************************

// if connection is an ODB connection, send data as it is, else call recv/writev to send data 
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);


#endif //ODB_IO_H