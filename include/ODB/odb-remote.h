#ifndef ODB_REMOTE_H
#define ODB_REMOTE_H

#include <ODB/odb.h>
#include <ODB/odb-utils.h>
#include <ODB/odb-config-parser.h>
#include <pthread.h>
#include <time.h>

typedef struct Thread_args{
    struct sockaddr_in server_addr;
    pthread_cond_t     cond;
}Thread_args;

extern uint8_t         ODB_server_created;

ssize_t strict_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t strict_sendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t strict_send(int file_desc,const void *buf, size_t count, int flags);

ssize_t strict_recv(int file_desc, void *buf, size_t count,int flags);

/****************************************
*                                       *
*      ODB signal handler functions     *
*                                       *
*****************************************/

void sighandler(int signo, siginfo_t *info, void *context);
void install_handler(void);


/****************************************
*                                       *
*       ODB RAB cleaner functions       *
*                                       *
*****************************************/

//void start_garbage_collector(ODB_Config *conf);

//void stop_garbage_collector();

/****************************************
*                                       *
*      ODB Remote Buffer Services       *
*                                       *
*****************************************/
int         is_ODB_server_created(void);
void        reset_ODB_server(void);

ODB_ERROR   create_ODB_Server_if_not_exist(struct sockaddr_in *net_addr, ODB_Config *conf);
ODB_ERROR   receive_request(int file_desc,ODB_Query_Desc *query);
ODB_ERROR   answer_client(int file_desc, ODB_Query_Desc *query);
ODB_ERROR   handle_client(void* argv);
//ODB_ERROR   ODB_get_remote_data(ODB_Query_Desc *desc,struct sockaddr_in *serv_addr, const ODB_Local_Buffer *buffer,size_t local_buff_offset, size_t *tot_bytes_read);


/***********************************
*                                  *
*          ODB RAB access          *
*                                  *
************************************/

ODB_ERROR ODB_get_remote_data(ODB_Query_Desc *query,struct sockaddr_in *server_addr, const ODB_Local_Buffer *buffer, size_t local_buff_offset,size_t *tot_bytes_read);

//ODB_ERROR ODB_getv_virtual_data(ODB_Query_Desc *query,struct sockaddr_in *server_addr, struct iovec *iovec, int iovcnt, size_t *tot_bytes_read);

ODB_ERROR handle_remote_error(ODB_Config *conf,ODB_Local_Buffer *buf,size_t *bytes_read);



#endif //ODB_REMOTE_H