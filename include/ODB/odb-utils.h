#ifndef NEWSUTILS_H
#define NEWSUTILS_H

#include <ODB/odb.h>


/****************************************
*                                       *
*           CRC computing               *
*                                       *
****************************************/
#define CRC_INIT 0x00

// CRC code extracted and adapted from https://github.com/lammertb/libcrc/blob/master/src/crc8.c

uint8_t crc8_ptr(const uint8_t *input_ptr, size_t num_bytes, uint8_t crc);


/****************************************
*                                       *
*          ODB_Header functions         *
*                                       *
****************************************/

ODB_ERROR parse_ODB_Header(ODB_Header *header);

/****************************************
*                                       *
*           ODB_DESC functions          *
*                                       *
****************************************/

void compute_ODB_Local_Desc_crc(ODB_Local_Desc *ptr);

void serialize_odb_desc_inplace(ODB_Desc *desc);

void deserialize_odb_desc_inplace(ODB_Desc *desc);

//ODB_ERROR parse_ODB_Desc(ODB_Desc *desc);

/*
ODB_ERROR it_parse_Local_Desc(IO_Iterator *start, ODB_Local_Desc **desc);

ODB_ERROR search_for_a_descv(const struct iovec *buff, const int iocount, const size_t max_it, ODB_Desc *desc);

ODB_ERROR search_for_a_descv_offset(const struct iovec *buff, const int iocount,const size_t offset, const size_t max_it, ODB_Desc *desc);

ODB_ERROR search_for_a_desc(const void *buff,size_t max_it, ODB_Desc *desc);

ODB_ERROR search_for_a_desc_offset(const void *buff,const size_t offset,size_t max_it, ODB_Desc *desc);
*/
/****************************************
*                                       *
*       ODB_Query_Desc functions        *
*                                       *
****************************************/

void serialize_odb_query_desc_inplace(ODB_Query_Desc *desc);

void deserialize_odb_query_desc_inplace(ODB_Query_Desc *desc);

/****************************************
*                                       *
*           ODB crc functions           *
*                                       *
****************************************/

#if ODB_STANDALONE
    void compute_ODB_crc(ODB_Header *header,ODB_Desc *desc);
    ODB_ERROR parse_ODB_Header_Desc(ODB_Header *header, ODB_Desc *desc);
#else
    #define compute_ODB_crc(header,desc)
    #define parse_ODB_Header_Desc(header, desc) ODB_SUCCESS
#endif

/****************************************
*                                       *
*            ODB log functions          *
*                                       *
*****************************************/

#if DEBUG

    #define DEBUG_LOG(fmt, ...) \
    do { \
        char filename[FILENAME_MAX]; \
        pid_t pid = getpid(), tid = gettid(); \
        snprintf(filename, sizeof(filename), "debug/" LOG_STATUS "_debug_P%ld_T%ld.log", (long)pid, (long)tid); \
        mode_t old_umask = umask(0000); \
        int debug_fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666); \
        umask(old_umask); \
        if (debug_fd != -1) { \
            FILE *file = fdopen(debug_fd, "a"); \
            if (file) { \
                flock(debug_fd, LOCK_EX); \
                fprintf(file, "DEBUG %s(): " fmt "\n", __func__, ##__VA_ARGS__); \
                flock(debug_fd, LOCK_UN); \
                fclose(file); \
            } else { \
                close(debug_fd); \
                fprintf(stderr, "[ERROR] fdopen failed for: %s (%s)\n", filename, strerror(errno)); \
            } \
        } else { \
            fprintf(stderr, "[ERROR] Could not open debug file: %s due to: %s\n", filename, strerror(errno)); \
            fprintf(stderr, "Line: %d, File: %s, Function: %s\n", __LINE__, __FILE__, __func__); \
        } \
    } while (0)

    #define ERROR_LOG(fmt, ...) \
    do { \
        char filename[FILENAME_MAX]; \
        pid_t pid = getpid(), tid = gettid(); \
        snprintf(filename, sizeof(filename), "debug/" LOG_STATUS "_debug_P%ld_T%ld.log", (long)pid, (long)tid); \
        mode_t old_umask = umask(0000); \
        int debug_fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666); \
        umask(old_umask); \
        if (debug_fd != -1) { \
            FILE *file = fdopen(debug_fd, "a"); \
            if (file) { \
                flock(debug_fd, LOCK_EX); \
                int saved_errno = errno; \
                fprintf(file, "ERROR %s(): " fmt ", cause : %s\n", __func__, ##__VA_ARGS__, strerror(errno)); \
                errno = saved_errno; \
                flock(debug_fd, LOCK_UN); \
                fclose(file); \
            } else { \
                close(debug_fd); \
                fprintf(stderr, "[ERROR] fdopen failed for: %s (%s)\n", filename, strerror(errno)); \
            } \
        } else { \
            fprintf(stderr, "[ERROR] Could not open debug file: %s due to: %s\n", filename, strerror(errno)); \
            fprintf(stderr, "Line: %d, File: %s, Function: %s\n", __LINE__, __FILE__, __func__); \
        } \
    } while (0)

    #define DEBUG_LOG_CH(fmt, ...) \
        do { \
            char filename[FILENAME_MAX]; \
            pid_t pid = getpid(), tid = gettid(); \
            snprintf(filename, sizeof(filename), "debug/" LOG_STATUS "_debug_P%ld_T%ld.log", (long)pid, (long)tid); \
            mode_t old_umask = umask(0000); \
            int debug_fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666); \
            umask(old_umask); \
            if (debug_fd != -1) { \
                FILE *file = fdopen(debug_fd, "a"); \
                if (file) { \
                    flock(debug_fd, LOCK_EX); \
                    fprintf(file, fmt, ##__VA_ARGS__); \
                    fflush(file); \
                    flock(debug_fd, LOCK_UN); \
                    fclose(file); \
                } else { \
                    close(debug_fd); \
                    fprintf(stderr, "[ERROR] fdopen failed for: %s (%s)\n", filename, strerror(errno)); \
                } \
            } else { \
                fprintf(stderr, "[ERROR] Could not open debug file: %s due to: %s\n", filename, strerror(errno)); \
                fprintf(stderr, "Line: %d, File: %s, Function: %s\n", __LINE__, __FILE__, __func__); \
            } \
        } while (0)

void Buffer_log(const void *buf,size_t buflen);

void IOV_log(const struct iovec *iov, size_t iovcnt);

void ODB_DESC_log(ODB_Desc *desc);

void ODB_HEADER_log(ODB_Header *header);

void ODB_Query_log(ODB_Query_Desc *q);

void ODB_Local_Buffer_log(ODB_Local_Buffer *buffer);

void ODB_Config_log(ODB_Config *config);

void ODB_ERROR_log(ODB_ERROR err);

void ODB_State_log(ODB_ProgressState state);

void MSGHDR_log(const struct msghdr *msg);

#else

    #define DEBUG_LOG(fmt, ...) 
    #define ERROR_LOG(fmt, ...)
    #define DEBUG_LOG_CH(fmt, ...) 

    #define Buffer_log(buf,buflen)
    #define IOV_log(iov, iovcnt)
    #define ODB_DESC_log(desc)
    #define ODB_HEADER_log(header)
    #define ODB_Query_log(query)
    #define ODB_Local_Buffer_log(buffer)
    #define ODB_Config_log(config)
    #define ODB_ERROR_log(err)
    #define ODB_State_log(state)
    #define MSGHDR_log(msg)
    
#endif


/****************************************
*                                       *
*       Network related functions       *
*                                       *
*****************************************/

/*
char * get_peer_addr(int fd);

int get_peer_info(int fd, struct sockaddr_in *addr);
*/

int is_socket(int socket_fd);

#if !ODB_STANDALONE
int is_ODB_allowed(int socket_fd);
#endif

int is_address_available(const struct sockaddr_in* addr);

int get_random_port(void);

void create_peer_addr(struct sockaddr_in *peer_addr);

int getlocalip(int socket_fd, struct sockaddr_in *addr);


/****************************************
*                                       *
*        Memory related functions       *
*                                       *
*****************************************/

ODB_ERROR get_buffer_parts(ODB_Local_Buffer *buf);
/*
#define INIT_ODB_Local_Buffer(buff_ptr,_buf,_buf_len) \
    if( NULL != (buff_ptr)){                          \
        (buff_ptr)->buffer    = (void*) (_buf);       \
        (buff_ptr)->body      = NULL;                 \
        (buff_ptr)->tail      = NULL;                 \
        (buff_ptr)->head_size = (_buf_len);           \
        (buff_ptr)->body_size = 0;                    \
        (buff_ptr)->tail_size = 0;                    \
        get_buffer_parts(buff_ptr);                   \
    }\
*/

/****************************************
*                                       *
*    Custom malloc  (for perfs tests)   *
*                                       *
*****************************************/
void* Buffer_malloc(size_t hd_size,size_t bd_size,size_t tl_size, void **full_memory_ptr);

void *Buffer_malloc_equitable_split(size_t buflen,char **full_memory_ptr);

/****************************************
*                                       *
*     Connections Hashmaps functions    *
*                                       *
*****************************************/

//ConnectionTable *add_connection(ConnectionTable **connections, int sockfd, struct sockaddr_in *addr);

void remove_connection(ConnectionTable **connections, int sockfd);

ConnectionTable *get_connection(ConnectionTable **connections, int sockfd);//struct sockaddr_in *addr

void reset_connections(ConnectionTable **connections); 

/****************************************
*                                       *
*    Remote Buffer Hashmaps functions   *
*                                       *
*****************************************/

// for Remote Access Buffer
ODB_Local_Buffer* create_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t size, size_t *rab_fd);
ODB_Local_Buffer *find_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t fd);

// for Remote Access File (hold a file descriptor to the file)
ODB_ERROR create_ODB_Remote_sendfile(ODB_RemoteAccessBuffer **RAB, int sendfile_fd, size_t *rab_fd);
ODB_ERROR find_ODB_Remote_sendfile(ODB_RemoteAccessBuffer **RAB, int sendfile_fd, size_t *rab_fd);

//Remove an entry from the Remote Access HashMap
ODB_ERROR remove_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t fd);

//Reset all entries in the Remote Access HashMap
void reset_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB);

// Garbage collector -> remove periodically unused entries
void garbage_collect_ODB_RAB();

/****************************************
*                                       *
*       ODB RAB cleaner functions       *
*                                       *
*****************************************/

void start_garbage_collector(ODB_Config *conf);

void stop_garbage_collector();

/****************************************
*                                       *
*  Protected Memory Hashmaps functions  *
*                                       *
*****************************************/

ODB_ERROR add_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT,void *addr,size_t size,const ODB_Desc *vdesc);
ODB_ERROR remove_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT, ODB_ProtectedMemoryTable *entry,ODB_Desc *vdesc);
ODB_ProtectedMemoryTable* find_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT,const void *addr, size_t size);
void reset_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT);


#endif // NEWSUTILS_H