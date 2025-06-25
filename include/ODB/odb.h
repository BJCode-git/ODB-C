#ifndef ODB_H
#define ODB_H

#define _GNU_SOURCE 

// std
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
// Types
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <limits.h>
// file
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <execinfo.h>
//sys
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>

// Networking
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

//struct
#include <uthash.h>
//#include <iterator.h> //iovec iterator

//check errors
#include "check.h"

#ifndef MIN
    #define MIN(a,b) (a) < (b) ? (a) : (b)
#endif
#ifndef MAX
    #define MAX(a,b) (a) > (b) ? (a) : (b)
#endif
#ifndef ABS
    #define ABS(a) a < 0 ? -a : a
#endif

#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define ODB_UNALIGNED_MAX_SIZE (PAGE_SIZE - 1)

#ifndef ODB_STANDALONE
    #define ODB_STANDALONE 1
#endif

#ifndef USE_ODB_HTTP
    #define USE_ODB_HTTP 0
#endif

#if USE_ODB_HTTP
    #include <ODB/odb-http.h>
#endif

#ifndef ADAPTIVE_MEMORY_METHOD
    #define ADAPTIVE_MEMORY_METHOD 1
#endif

#if ADAPTIVE_MEMORY_METHOD
    #define VIRTUAL_THRESHOLD 2*PAGE_SIZE
#else
    #define VIRTUAL_THRESHOLD 3*PAGE_SIZE
#endif

#ifndef SEND_UNALIGNED_DATA
    #define SEND_UNALIGNED_DATA 1
#endif

#ifndef EQU_ALIGN
	#define EQU_ALIGN 1
#endif

#ifndef DEBUG
    #define DEBUG 0
#endif

#ifndef LOG_STATUS
    #define LOG_STATUS "ODB"
#endif

#ifndef ODB
    #define ODB 1
#endif

// ODB server addr config
#ifndef ODB_SERVER_PORT 
    #define ODB_SERVER_PORT 42000
#endif

#ifndef ODB_SERVER_ADDR
    #define ODB_SERVER_ADDR "127.0.0.1"
    #define LOOK_FOR_SERVER_ADDR 1
#endif


// Compilation warnings
#ifndef ODB_MESSAGE
    #define ODB_MESSAGE

    #if ODB
        #pragma message("Using ODB")
    #else
        #pragma message("Not Using ODB")
    #endif

    #if USE_ODB_HTTP
        #pragma message("Using ODB-HTTP")
    #endif

    #if ODB_STANDALONE
        #pragma message("ODB_STANDALONE")
    #else
        #pragma message("Use ODB with a conf file")
    #endif

#endif

/* Memory :
┌─────────────────────────────────────────────────────────────────────────────────────────────¬
|…………unligned head (Rstart)|aligned part i.e body (Virtual)|Unaligned tail (Rend)…………………………………|
──────────────────────────────────────────────────────────────────────────────────────────────┘
*/


typedef enum{
    ODB_SUCCESS                 =  1,
    ODB_INCOMPLETE              =  0,
    ODB_PARSE_ERROR             = -1,
    ODB_WRONG_MSG_TYPE          = -2,
    ODB_NULL_PTR                = -3,
    ODB_BUFFER_OVERFLOW         = -4,
    ODB_MEMORY_ALLOCATION_ERROR = -5,
    ODB_MPROTECT_ERROR          = -6,
    ODB_SOCKET_CREATE_ERROR     = -7,
    ODB_SOCKET_WRITE_ERROR      = -8,
    ODB_SOCKET_READ_ERROR       = -9,
    ODB_NOT_A_SOCKET            = -10,
    ODB_THREAD_CREATE           = -11,
    ODB_INVALID_REQUEST         = -12,
    ODB_NOT_FOUND               = -13,
    ODB_UNKNOWN_ERROR           = -14
} ODB_ERROR;


// used to indicate the demand of a client to the RAB
typedef enum{
    NONE = 0,
    ODB_MSG_GET_PAYLOAD,
    ODB_MSG_GET_BODY,
    ODB_MSG_GET_UNALIGNED_DATA,
    ODB_MSG_GET_FILE,
    ODB_MSG_SEND_UNALIGNED_DATA,
    ODB_MSG_SEND_REAL,
    ODB_MSG_SEND_VIRTUAL,
} ODB_MSG_Type;

typedef enum {
    ODB_NONE = 0,
    ODB_RESTORE_FROM_HEADER,
    ODB_RESTORE_FROM_DESC,
    ODB_RESTORE_FROM_HEADER_AND_DESC,
    ODB_HEADER_IN_PROGRESS,
    ODB_DESC_IN_PROGRESS,
    ODB_PAYLOAD_IN_PROGRESS,
    ODB_SENDFILE_IN_PROGRESS,
    ODB_RECEIVING_HEAD,
    ODB_DOWNLOAD_PAYLOAD,
    ODB_DOWNLOAD_PAYLOAD_ONLY,
    ODB_RECEIVING_TAIL,
    ODB_RECEIVING_FILE,
    ODB_SEND_REAL,
    ODB_SEND_VIRTUAL,
    ODB_SEND_VIRTUAL_TRANSMIT,
    ODB_SEND_CLIENT_REAL,
    ODB_SEND_CLIENT_VIRTUAL,
    ODB_UNKNOWN_STATE
}ODB_ProgressState;


#define ODB_MAGIC_NUMBER 0X5A
#define ODB_INVALID_NUMBER 0XFF

// desc types
#define ODB_DESC_VIRTUAL    0
#define ODB_DESC_REAL       1
#define ODB_DESC_QUERY_BODY 2

// frame
#define ODB_frame_header 0
#define ODB_frame_desc   1
#define ODB_frame_head   2
//#define ODB_frame_body   3
#define ODB_frame_tail   3
#define ODB_FRAME_SIZE   4
typedef struct iovec ODB_Frame[ODB_FRAME_SIZE];



/****************************************
*                                       *
*              ODB_Header               *
*                                       *
****************************************/

#if ODB_STANDALONE
     typedef struct ODB_Header{
        uint8_t             magic_number;
        ODB_MSG_Type        type;
        size_t              total_size;
        uint8_t             crc;
    } ODB_Header;

    #define ODB_Header_INITIALIZER {.magic_number=ODB_INVALID_NUMBER,.type=NONE,.total_size=0,.crc=0}
    #define INIT_ODB_Header(header,_type,_total_size)    \
    if((header) != NULL){                                  \
        (header)->magic_number    = ODB_MAGIC_NUMBER;      \
        (header)->type            = _type;                 \
        (header)->total_size      = _total_size;           \
        compute_ODB_crc(header,NULL);                    \
    }
#else
    typedef struct ODB_Header{
        ODB_MSG_Type        type;
        size_t              total_size;
    } ODB_Header;
    #define ODB_Header_INITIALIZER {.type=NONE,.total_size=0}
    #define INIT_ODB_Header( header,_type,_total_size)\
    if(header != NULL){                               \
        (header)->type            = _type;             \
        (header)->total_size      = _total_size;       \
    }
#endif
#define ODB_HEADER_SIZE sizeof(ODB_Header)


/*****************************************
*                                        *
*             ODB_Data_Desc              *
*                                        *
*****************************************/

typedef struct {
    size_t fd;
    size_t head_size; 
    size_t body_size;
    size_t tail_size;
}ODB_Data_Desc;
#define ODB_DATA_DESC_SIZE sizeof(ODB_Data_Desc)

#define ODB_Data_Desc_INITIALIZER {.fd=0,.head_size =0,.body_size =0,.tail_size =0}
#define serialize_ODB_Data_Desc( d_desc)                    \
    do{                                                     \
        (d_desc).fd = htobe64((d_desc).fd);                 \
        (d_desc).head_size = htobe64((d_desc).head_size);   \
        (d_desc).body_size = htobe64((d_desc).body_size);   \
        (d_desc).tail_size = htobe64((d_desc).tail_size);   \
    }while(0)

#define deserialize_ODB_Data_Desc( d_desc)                  \
    do{                                                     \
        (d_desc).fd = be64toh((d_desc).fd);                 \
        (d_desc).head_size = be64toh((d_desc).head_size);   \
        (d_desc).body_size = be64toh((d_desc).body_size);   \
        (d_desc).tail_size = be64toh((d_desc).tail_size);   \
    }while(0)


/****************************************
*                                       *
*               ODB_DESC                *
*                                       *
****************************************/

typedef struct {
    ODB_Data_Desc       d_desc;
    struct sockaddr_in  source_addr;
    //uint8_t crc;
}ODB_Desc;
#define ODB_DESC_SIZE sizeof(ODB_Desc)

#define ODB_Desc_INITIALIZER {.fd=0,.head_size =0,.body_size =0,.tail_size =0,.source_addr=INADDR_NONE}
#define INIT_ODB_Desc( d,_fd,_head_size,_body_size, _tail_size, _local_ip)\
    do{                                                                   \
        (d).d_desc.fd            = _fd;                                   \
        (d).d_desc.head_size     = _head_size;                            \
        (d).d_desc.body_size     = _body_size;                            \
        (d).d_desc.tail_size     = _tail_size;                            \
        (d).source_addr   = _local_ip;                                    \
    }while(0)


/****************************************
*                                       *
*             ODB_Query_Desc            *
*                                       *
****************************************/
typedef struct {
    ODB_MSG_Type        type;
    ODB_Data_Desc       d_desc;
}ODB_Query_Desc;
#define ODB_QUERY_DESC_SIZE sizeof(ODB_Query_Desc)

#define INIT_ODB_Query(q,_type,_fd,_head_size,_body_size, _tail_size)   \
    do{                                                                 \
        (q).type                 = _type;                               \
        (q).d_desc.fd            = _fd;                                 \
        (q).d_desc.head_size     = _head_size;                          \
        (q).d_desc.body_size     = _body_size;                          \
        (q).d_desc.tail_size     = _tail_size;                          \
    }while(0)

/****************************************
*                                       *
*             ODB_Local_Desc            *
*                                       *
****************************************/

typedef struct{
    uint8_t  magic_number;
    ODB_Desc desc;
    uint8_t  crc;
}ODB_Local_Desc;
#define ODB_LOCAL_DESC_SIZE sizeof(ODB_Local_Desc)


/****************************************
*                                       *
*           ODB_Local_Buffer            *
*                                       *
*****************************************/
typedef struct {
    void*   buffer;     // bytes
    void*   body;
    void*   tail;
    size_t  head_size;  // bytes
    size_t  body_size;  // bytes
    size_t  tail_size;  // bytes
}ODB_Local_Buffer;

#define INIT_ODB_Local_Buffer(buff_ptr,_buf,_buf_len) \
    if( NULL != (buff_ptr)){                          \
        (buff_ptr)->buffer    = (void*) (_buf);       \
        (buff_ptr)->body      = NULL;                 \
        (buff_ptr)->tail      = NULL;                 \
        (buff_ptr)->head_size = (size_t) (_buf_len);  \
        (buff_ptr)->body_size = 0;                    \
        (buff_ptr)->tail_size = 0;                    \
        get_buffer_parts(buff_ptr);                   \
    }\

#define ODB_Local_Buffer_INITIALIZER {.buffer=NULL,.body=NULL,.tail=NULL,.head_size=0,.body_size=0,.tail_size=0}

/****************************************
*                                       *
*            ConnectionInfo             *
*                                       *
****************************************/

typedef struct {
    uint8_t             is_ODB;
    ODB_ProgressState   progress;
    size_t              bytes_read_write;

    // ODB frame
    ODB_Header          odb_header;
    ODB_Desc            desc;
    ODB_Local_Buffer    payload;

    // for http parsing
#if USE_ODB_HTTP
    ODB_Http            http_parser;
#endif

}ConnectionInfo;

#define ConnectionInfo_INITIALIZER {.is_ODB=1,.progress=ODB_NONE,.bytes_read_write=0,.odb_header=ODB_Header_INITIALIZER,.desc=ODB_Desc_INITIALIZER,.payload=ODB_Local_Buffer_INITIALIZER}

/****************************************
*                                       *
*           Global HashMaps             *
*                                       *
****************************************/

//              Connections
// *********************                 *********************                 *********************
// *                   * down_connection *                   * up_connection   *                   *
// *        IS         * <-------------- *        IS         * ------------->  *        BE         *
// *                   *                 *                   *                 *                   *
// *********************                 *********************                 *********************

typedef struct {
    int sockfd;
    ConnectionInfo info;
    UT_hash_handle hh;
} ConnectionTable;

typedef struct {
    size_t              fd;
    ODB_Local_Buffer    buffer;
    uint8_t             accessed;
    UT_hash_handle      hh;
}ODB_RemoteAccessBuffer;

typedef struct {
    // buffer head address
    void*           addr;
    // pointer to the desc located in the protected memory
    ODB_Desc*       desc;
    // buffer total_size 
    size_t          payload_offset;
    size_t          size;
    UT_hash_handle  hh;
}ODB_ProtectedMemoryTable;

typedef struct {
    void*           addr;
    size_t          size;
    UT_hash_handle  hh;
}ODB_FailedRemoteAccessBuffer;

extern ConnectionTable*                 up_connections  ;
extern ConnectionTable*                 down_connections;
extern ODB_RemoteAccessBuffer*          intern_RAB      ;
extern ODB_ProtectedMemoryTable*        intern_PMT      ;
extern ODB_FailedRemoteAccessBuffer*    intern_Failed_RAB;

/****************************************
*                                       *
*           ODB Configuration           *
*                                       *
*****************************************/

#ifndef DEFAULT_COUNTDOWN
    #define DEFAULT_COUNTDOWN 3000
#endif
#ifndef MAX_PORTS
    #define MAX_PORTS 16
#endif
#ifndef MAX_LINE_LENGTH
    #define MAX_LINE_LENGTH 256
#endif

typedef enum {
    ABORT=0,
    CORRUPT,
    BEST_EFFORT,
    FAKE_SEND
} ODB_Remote_Error_Policy;

typedef enum {
    PASS_THROUGH=0,
    VIRTUAL
} ODB_Sendfile_From_Sock_Policy;

typedef struct {
    uint16_t                        no_odb_ports[MAX_PORTS];
    uint8_t                         n_ports;
    int8_t                          corrupt_value;
    ODB_Remote_Error_Policy         r_err_strat;
    ODB_Sendfile_From_Sock_Policy   sf_so_strat;
    uint16_t                        ms_countdown;
    struct sockaddr_in              ODB_serv_addr;
} ODB_Config;

// global config
extern ODB_Config ODB_conf;

#define ODB_Config_INITIALIZER {.no_odb_ports={80},.n_ports=1,.corrupt_value=-1,.r_err_strat=0,.sf_so_strat=1,.ms_countdown=DEFAULT_COUNTDOWN,.ODB_serv_addr={0}}

/****************************************
*                                       *
*            Network related            *
*                                       *
*****************************************/

#define INIT_MSGHDR_P(msg_p,iov,iovcnt) \
    if(msg_p != NULL){              \
    msg_p->msg_name       = NULL;   \
    msg_p->msg_namelen    = 0;      \
    msg_p->msg_iov        = iov;    \
    msg_p->msg_iovlen     = iovcnt; \
    msg_p->msg_control    = NULL;   \
    msg_p->msg_controllen = 0;      \
    msg_p->msg_flags      = 0;      \
}

#define INIT_MSGHDR(msg)            \
    do{                             \
        msg.msg_name       = NULL;  \
        msg.msg_namelen    = 0;     \
        msg.msg_iov        = NULL;  \
        msg.msg_iovlen     = 0;     \
        msg.msg_control    = NULL;  \
        msg.msg_controllen = 0;     \
        msg.msg_flags      = 0;     \
    }while(0)

#define MSGHDR_INITIALIZER(iov, iovcnt,flags)   \
    ((struct msghdr){                           \
        .msg_name       = NULL,                 \
        .msg_namelen    = 0,                    \
        .msg_iov        = (void*)(iov),         \
        .msg_iovlen     = (iovcnt),             \
        .msg_control    = NULL,                 \
        .msg_controllen = 0,                    \
        .msg_flags      = flags                 \
    })

/****************************************
*                                       *
*               IO related              *
*                                       *
*****************************************/
extern int     (*original_shutdown)(int sockfd, int how);
extern ssize_t (*original_recv)(int, void*, ssize_t,int );
extern ssize_t (*original_recvfrom)(int, void *, size_t, int,struct sockaddr*, socklen_t*);
extern ssize_t (*original_recvmsg)(int , struct msghdr*, int);
extern ssize_t (*original_read)(int, void *, size_t);
extern ssize_t (*original_readv)(int, const struct iovec *, int);
extern ssize_t (*original_write)(int, const void *, size_t);
extern ssize_t (*original_writev)(int, const struct iovec *, int);
extern ssize_t (*original_send)(int, const void *, size_t , int);
extern ssize_t (*original_sendto)(int, const void *, size_t , int ,const struct sockaddr *, socklen_t );
extern ssize_t (*original_sendmsg)(int, const struct msghdr *, int);
extern ssize_t (*original_sendfile)(int, int, off_t *, size_t);
extern int     (*original_close)(int fd);
extern int     (*original_accept)(int sockfd, struct sockaddr *adr, socklen_t *len);
extern ssize_t (*original_splice)(int fd_in, loff_t *off_in, int fd_out,loff_t *off_out, size_t len, unsigned int flags);
extern pid_t   (*original_fork)(void);


#endif // ODB_H