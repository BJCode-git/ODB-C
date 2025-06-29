#include <ODB/odb.h>
#include <ODB/odb-io.h>
#include <ODB/odb-utils.h>
#include <ODB/odb-remote.h>
#include <dlfcn.h>


void init_original_functions(){
    //static int init = 0;
    //if (init == 0) {
        if((original_recv = dlsym(RTLD_NEXT, "recv")) == NULL) {
            perror("init_original_functions : dlsym(recv)");
            exit(EXIT_FAILURE);
        }
        if((original_recvfrom = dlsym(RTLD_NEXT, "recvfrom")) == NULL) {
            perror("init_original_functions : dlsym(recvfrom)");
            exit(EXIT_FAILURE);
        }
        if((original_recvmsg = dlsym(RTLD_NEXT, "recvmsg")) == NULL) {
            perror("init_original_functions : dlsym(recvmsg)");
            exit(EXIT_FAILURE);
        }
        if((original_read = dlsym(RTLD_NEXT, "read")) == NULL) {
            perror("init_original_functions : dlsym(read)");
            exit(EXIT_FAILURE);
        }
        if((original_readv = dlsym(RTLD_NEXT, "readv")) == NULL) {
            perror("init_original_functions : dlsym(readv)");
            exit(EXIT_FAILURE);
        }
        if((original_write = dlsym(RTLD_NEXT, "write")) == NULL) {
            perror("init_original_functions : dlsym(write)");
            exit(EXIT_FAILURE);
        }
        if((original_writev = dlsym(RTLD_NEXT, "writev")) == NULL) {
            perror("init_original_functions : dlsym(writev)");
            exit(EXIT_FAILURE);
        }
        if((original_send = dlsym(RTLD_NEXT, "send")) == NULL) {
            perror("init_original_functions : dlsym(original_send)");
            exit(EXIT_FAILURE);
        }
        if((original_sendto = dlsym(RTLD_NEXT, "sendto")) == NULL) {
            perror("init_original_functions : dlsym(original_sendto)");
            exit(EXIT_FAILURE);
        }
        if((original_sendmsg = dlsym(RTLD_NEXT, "sendmsg")) == NULL) {
            perror("init_original_functions : dlsym(original_sendmsg)");
            exit(EXIT_FAILURE);
        }
        if((original_sendfile = dlsym(RTLD_NEXT, "sendfile")) == NULL) {
            perror("init_original_functions : dlsym(sendfile)");
            exit(EXIT_FAILURE);
        }
        if((original_close = dlsym(RTLD_NEXT, "close")) == NULL) {
            perror("init_original_functions : dlsym(close)");
            exit(EXIT_FAILURE);
        }
        if( (original_accept = dlsym(RTLD_NEXT, "accept")) == NULL){
            perror("init_original_functions : dlsym(accept)");
            exit(EXIT_FAILURE);
        }
        if( (original_splice = dlsym(RTLD_NEXT, "splice")) == NULL){
            perror("init_original_functions : dlsym(splice)");
            exit(EXIT_FAILURE);
        }
        if( (original_fork = dlsym(RTLD_NEXT, "fork")) == NULL){
            perror("init_original_functions : dlsym(fork)");
            exit(EXIT_FAILURE);
        }
        if( (original_shutdown = dlsym(RTLD_NEXT, "shutdown")) == NULL){
            perror("init_original_functions : dlsym(shutdown)");
            exit(EXIT_FAILURE);
        }
    //    init = 1;
    //}
}

static void ODB_init(){
    
    static int init = 0;
    if(init == 1){
        DEBUG_LOG("ODB : Called init, multiple times."); 
        return;
    }
    // init random seed
    srand(time( NULL ));
    // init original functions
    init_original_functions();
    // create the ODB server address
    create_peer_addr(&ODB_conf.ODB_serv_addr);
    // load the configuration, 
    // can overwrite server address
    load_ODB_config(&ODB_conf);
    // install the SIGSEGV handler
    install_handler();
    DEBUG_LOG("ODB : Initiated !");
    // Debug configuration
    ODB_Config_log(&ODB_conf);
    init = 1;

}

// ----------------------------
// Auto initialization
// ----------------------------

// For Linux/macOS with GCC/Clang
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((constructor))
    static void odb_auto_init(void) {
        ODB_init();
    }
#endif

// ************************************
// *                                  *
// *          fork section           *
// *                                  *
// ************************************
pid_t fork(void){
    ODB_init();
    #if DEBUG
    const pid_t parent_pid = getpid();
    #endif
    const pid_t child_pid = original_fork();

    if(child_pid > 0){
        // we are in the parent
        DEBUG_LOG("ODB : I'm %i, and my forked child is %i", parent_pid,child_pid);
    }
    // install the handler in the child
    else if(child_pid == 0){
        // we are in the child
        DEBUG_LOG("ODB : I'm newly forked process %i, my parent is %i", getpid(), parent_pid);
        install_handler();
        reset_connections(&up_connections);
        reset_connections(&down_connections);
        reset_ODB_Protected_Memory(&intern_PMT);
        reset_ODB_Remote_Buffer(&intern_RAB);
        reset_ODB_server();
    }
    else{
        DEBUG_LOG("ODB : fork failed");
    }
    return child_pid;
}

// ************************************
// *                                  *
// *          close section           *
// *                                  *
// ************************************

int shutdown(int sockfd, int how){
    DEBUG_LOG("shutdown(socket=%d,how=%d)",sockfd,how);
    return original_shutdown(sockfd,how);
}

int close(int fd){
    #if !ODB
    DEBUG_LOG("close(file=%d)",fd);
    return original_close(fd);
    #endif
    const int socket_fd = fd;
    DEBUG_LOG("close(fd=%d)",fd);
    if(is_socket(fd) > 0){
        DEBUG_LOG("Remove socket %d from Up connections...", socket_fd);
        remove_connection(&up_connections,socket_fd);
        DEBUG_LOG("Remove socket %d from Down connections...", socket_fd);
        remove_connection(&down_connections,socket_fd);
    }
    DEBUG_LOG("fd closed %d !",fd);
    return original_close(fd);
}


// ************************************
// *                                  *
// *          accept section          *
// *                                  *
// ************************************

int accept(int sockfd, struct sockaddr *adr, socklen_t *len){

    #if !ODB
        DEBUG_LOG("accept(socket=%d,adr=%p,len=%p)",sockfd,adr,len);
        return original_accept(sockfd,adr,len);
    #elif !ODB_STANDALONE
        return original_accept(sockfd,adr,len);
    #else
        int fd = original_accept(sockfd,adr,len); 
        if(fd <0) return fd;

        ConnectionTable *up_entry   = get_connection(&up_connections, fd);
        // By default, the new up connection is not ODB
        if(up_entry != NULL) up_entry->info.is_ODB = 0;
    
        return fd;
    #endif
}

// ************************************
// *                                  *
// *            send section          *
// *                                  *
// ************************************

#if USE_ODB_HTTP

    static ODB_ERROR send_real(int sockfd,ConnectionInfo *info,ODB_Http *parser,int flags, size_t *bytes_written){
    }

    static ODB_ERROR send_virtual(int sockfd,ConnectionInfo *info,ODB_Http *parser,int flags, size_t *bytes_written){
    }

#endif

static ODB_ERROR setup_send_info(const void * buf, size_t len,ConnectionInfo *info){
    if(buf == NULL || len == 0 || info == NULL) return ODB_NULL_PTR;

    if( info->progress != ODB_NONE ) return ODB_SUCCESS;

    // default values for info
    info->bytes_read_write      = 0;
    info->progress              = ODB_SEND_REAL;
    info->odb_header.total_size = len;
    memset(&info->desc, 0, ODB_DESC_SIZE);

    // try to find a protected memory
    ODB_ProtectedMemoryTable* entry = NULL;
    entry = find_ODB_Protected_Memory(&intern_PMT,buf,len);

    if(entry != NULL){

        DEBUG_LOG("Overlapping with protected memory %p of size %zu",entry->addr,entry->size);

        // check if the given addr is in the protected memory
        if( entry->addr <= buf && (ptrdiff_t) buf < (ptrdiff_t) entry->addr + (ptrdiff_t) entry->size){
            DEBUG_LOG("Adress is in the protected memory, body address %p of size %zu",entry->addr,entry->size);
            info->progress = ODB_SEND_VIRTUAL_TRANSMIT;
            info->odb_header.total_size = entry->size;
            INIT_ODB_Local_Buffer(&(info->payload), entry->addr, entry->size);
            remove_ODB_Protected_Memory(&intern_PMT,entry,&info->desc);
            //DEBUG_LOG("Protected memory entry %p vs payload %p",(void*)entry->addr,(void*)info->payload.buffer);
        }
        
        else if(buf < entry->addr){
            ptrdiff_t diff = (ptrdiff_t) entry->addr - (ptrdiff_t) buf;
            info->odb_header.total_size = (size_t) diff;
            DEBUG_LOG("Adress is before the protected memory, copying %zu bytes",info->odb_header.total_size);
            INIT_ODB_Local_Buffer(&info->payload, buf, info->odb_header.total_size);
        }

    }
    else{
        INIT_ODB_Local_Buffer(&info->payload, buf, len);
    }

    if(info->is_ODB == 0)
        info->progress = info->progress == ODB_SEND_VIRTUAL_TRANSMIT ? ODB_SEND_CLIENT_VIRTUAL : ODB_SEND_CLIENT_REAL;

    return ODB_SUCCESS;
}

static void setup_send_hdr(ODB_Frame *frame,ConnectionInfo *info){
    if(info == NULL || frame == NULL) return;
    
    if(info->bytes_read_write >= ODB_HEADER_SIZE + ODB_DESC_SIZE){
        (*frame)[ODB_frame_header].iov_base = NULL;
        (*frame)[ODB_frame_header].iov_len  = 0;
        (*frame)[ODB_frame_desc].iov_base = NULL;
        (*frame)[ODB_frame_desc].iov_len  = 0;
        return;
    }

    size_t hdr_off  = info->bytes_read_write < ODB_HEADER_SIZE ? info->bytes_read_write : ODB_HEADER_SIZE;
    size_t desc_off = info->bytes_read_write > ODB_HEADER_SIZE ? info->bytes_read_write - ODB_HEADER_SIZE : 0;
   
    (*frame)[ODB_frame_header].iov_base = (void *)((uint8_t *)&info->odb_header + hdr_off);
    (*frame)[ODB_frame_header].iov_len  = ODB_HEADER_SIZE - hdr_off;
    (*frame)[ODB_frame_desc].iov_base = (void *)((uint8_t *)&info->desc + desc_off);
    (*frame)[ODB_frame_desc].iov_len  = ODB_DESC_SIZE - desc_off;
}

static void setup_send_virtual_transmit(ODB_Frame *frame,ConnectionInfo *info){
    if(info == NULL || frame == NULL) return;

    //if( info->bytes_read_write < ODB_HEADER_SIZE + ODB_DESC_SIZE)
    setup_send_hdr(frame,info);

    size_t unaligned_send = 0;
    size_t desc_len       = info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size;

    if( info->bytes_read_write > ODB_HEADER_SIZE + ODB_DESC_SIZE)
        unaligned_send = info->bytes_read_write - ODB_HEADER_SIZE - ODB_DESC_SIZE;

    (*frame)[ODB_frame_head].iov_len = MIN(info->odb_header.total_size,info->desc.d_desc.head_size);
    (*frame)[ODB_frame_tail].iov_len = MIN(info->odb_header.total_size,info->desc.d_desc.tail_size);

    size_t hd_off = unaligned_send < (*frame)[ODB_frame_head].iov_len ? unaligned_send : (*frame)[ODB_frame_head].iov_len;
    size_t tl_off = unaligned_send > (*frame)[ODB_frame_head].iov_len ? unaligned_send - (*frame)[ODB_frame_head].iov_len : 0;
    size_t tl_len = MIN(info->odb_header.total_size - (*frame)[ODB_frame_head].iov_len, desc_len - info->desc.d_desc.head_size);

    (*frame)[ODB_frame_head].iov_base   = (void*) ((uint8_t*) info->payload.buffer + hd_off);
    (*frame)[ODB_frame_tail].iov_base   = (void*) ((uint8_t*) info->payload.buffer + tl_len);
    (*frame)[ODB_frame_tail].iov_base   = (void*) ((uint8_t*) (*frame)[ODB_frame_tail].iov_base + tl_off);

    (*frame)[ODB_frame_head].iov_len -= hd_off;
    (*frame)[ODB_frame_tail].iov_len -= tl_off;

}

static void setup_send_virtual(ODB_Frame *frame,ConnectionInfo *info){
    if( frame == NULL || info == NULL) return;
    
    //if( info->bytes_read_write < ODB_HEADER_SIZE + ODB_DESC_SIZE)
    setup_send_hdr(frame,info);

    #if !SEND_UNALIGNED_DATA
        (*frame)[ODB_frame_head].iov_len = 0;
        (*frame)[ODB_frame_head].iov_base = NULL;
        (*frame)[ODB_frame_tail].iov_len = 0;
        (*frame)[ODB_frame_tail].iov_base = NULL;
        return;
    #else
        size_t unaligned_send = 0;
        if( info->bytes_read_write > ODB_HEADER_SIZE + ODB_DESC_SIZE)
            unaligned_send = info->bytes_read_write - ODB_HEADER_SIZE - ODB_DESC_SIZE;

        #if ADAPTIVE_MEMORY_METHOD 
        size_t hd_off = unaligned_send < info->payload.head_size ? unaligned_send :  info->payload.head_size;
        size_t td_off = unaligned_send > info->payload.head_size ? unaligned_send - info->payload.head_size : 0;
        td_off = MIN(td_off,info->payload.tail_size);
        (*frame)[ODB_frame_head].iov_len = info->payload.head_size - hd_off;
        (*frame)[ODB_frame_tail].iov_len = info->payload.tail_size - td_off;
        #elif !ADAPTIVE_MEMORY_METHOD
        size_t hd_off = unaligned_send < ODB_UNALIGNED_MAX_SIZE ? unaligned_send : ODB_UNALIGNED_MAX_SIZE;
        size_t td_off = unaligned_send > ODB_UNALIGNED_MAX_SIZE ? unaligned_send - ODB_UNALIGNED_MAX_SIZE : 0;
        td_off = MIN(td_off,ODB_UNALIGNED_MAX_SIZE);
        td_off = MIN(td_off,info->payload.body_size + info->payload.tail_size);
        (*frame)[ODB_frame_head].iov_len = ODB_UNALIGNED_MAX_SIZE - hd_off;
        (*frame)[ODB_frame_tail].iov_len = ODB_UNALIGNED_MAX_SIZE - td_off;
        #endif

        // point head and tail to the rab head and tail
        (*frame)[ODB_frame_head].iov_base = info->payload.buffer + hd_off;
        (*frame)[ODB_frame_tail].iov_base = (void*) ((uint8_t*) info->payload.tail + info->payload.tail_size - (*frame)[ODB_frame_tail].iov_len);

    #endif
}

static ODB_ERROR sendfile_to_client(int out_fd,ConnectionInfo *info, size_t *bytes_written){
    //ODB_init();
    if(info == NULL || bytes_written == NULL) return ODB_NULL_PTR;

    ODB_Query_Desc query;
    INIT_ODB_Query(query,ODB_MSG_GET_FILE,info->desc.d_desc.fd,info->bytes_read_write,0, 0);
    *bytes_written = 0;

    // connect to server
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) return ODB_SOCKET_WRITE_ERROR;
    if(connect(sockfd,(struct sockaddr *) &info->desc.source_addr,sizeof(struct sockaddr_in)) < 0){
        close(sockfd);
        return ODB_SOCKET_WRITE_ERROR;
    }

    // send query
    serialize_odb_query_desc_inplace(&query);
    if(strict_send(sockfd,&query,sizeof(ODB_Query_Desc),0) < 0){
        close(sockfd);
        return ODB_SOCKET_WRITE_ERROR;
    }

    // use sendfile to transfer data to client 
    // max size transferrable by sendfile is 0x7ffff000
    ssize_t ret = 0;
    info->progress = ODB_SENDFILE_IN_PROGRESS;
    while(ret == 0){
        ret = original_sendfile(out_fd, sockfd, NULL, 0x7ffff000);
        *bytes_written = ret < 0 ? 0 : (size_t) ret + *bytes_written;
        if(ret == -1 && (errno == EINTR || errno == EAGAIN)){
            return ODB_INCOMPLETE;
        }
        // update bytes_written -> use as file offset
        info->bytes_read_write += *bytes_written;
    }
    // if sendfile return 0, we are done
    info->progress = ODB_NONE;

    close(sockfd);

    return ODB_SUCCESS;
}

static ODB_ERROR send_to_client(int sockfd,ConnectionInfo *info,int flags,size_t *bytes_written){
    if( info == NULL || bytes_written == NULL) return ODB_NULL_PTR;

    ssize_t    ret = 0;
    *bytes_written = 0;

    // if protection is enabled, remove it else, 
    // it must be real data, so send it
    if( ODB_SEND_CLIENT_REAL == info->progress){
        ssize_t ret = original_send(sockfd,info->payload.buffer,info->odb_header.total_size,flags);
        if(ret < 0){
            ERROR_LOG("ODB_SOCKET_WRITE_ERROR");
            return ODB_SOCKET_WRITE_ERROR;
        }
        *bytes_written = ret < 0 ? 0 : (size_t) ret;
        DEBUG_LOG("Send %zu bytes :",*bytes_written);
        return info->odb_header.total_size == *bytes_written ? ODB_SUCCESS : ODB_INCOMPLETE;
    }

        // if desc give 0 sizes, it's an error
    if( info->desc.d_desc.head_size == 0 && info->desc.d_desc.body_size == 0 && info->desc.d_desc.tail_size == 0){
        //errno = 0;
        ERROR_LOG("Desc with sizes 0");
        return ODB_UNKNOWN_ERROR;
    }

    // if body size is 0, it means that its a Remote File
    // transmit data using original sendfile (from a socket to a socket ) 
    if(info->desc.d_desc.body_size == 0 ){
        DEBUG_LOG("Using sendfile through socket %d ", sockfd); 
        return sendfile_to_client(sockfd,info,bytes_written);
    }
    
    ODB_Local_Buffer buf;
    INIT_ODB_Local_Buffer((&buf),info->payload.buffer,info->odb_header.total_size);

    DEBUG_LOG("Desc found -> download and send data");
    ODB_DESC_log(&info->desc);

    // download data and write to client
    // 1st step, send head data
    if(info->desc.d_desc.head_size > 0){
        DEBUG_LOG("Will send %zu head bytes through socket %d ",info->desc.d_desc.head_size, sockfd);
        ret = original_send(sockfd,buf.buffer,MIN(info->desc.d_desc.head_size,info->odb_header.total_size),flags);
        if( ret < 0 ){
            ERROR_LOG("head strict_send failed");
            return ODB_SOCKET_WRITE_ERROR;
        }
        DEBUG_LOG("Head writev -> wrote %zu bytes",(size_t)ret);
        *bytes_written += (size_t) ret;
    }

    // 2nd step, get all body payload data from RAB and send it back

    DEBUG_LOG("Will send %zu body bytes through socket %d ",info->desc.d_desc.body_size, sockfd);
    size_t high_part_size = info->desc.d_desc.head_size + info->desc.d_desc.body_size;
    if(high_part_size > 0 && *bytes_written < info->odb_header.total_size){
        ODB_Query_Desc query;
        INIT_ODB_Query(query,ODB_MSG_GET_PAYLOAD,info->desc.d_desc.fd,0,high_part_size,0);

        while(*bytes_written < high_part_size){
            size_t downloaded = 0;
            query.d_desc.head_size  = *bytes_written;
            query.d_desc.body_size -= *bytes_written;
    
            if( ODB_SUCCESS != ODB_get_remote_data(&query,&info->desc.source_addr,&buf,*bytes_written,&downloaded)){
                DEBUG_LOG("ODB_get_remote_data failed");
                return ODB_SOCKET_WRITE_ERROR;
            }
            DEBUG_LOG("Downloaded %zu bytes",downloaded);
            DEBUG_LOG("Writting Body to socket %d...",sockfd);
            //IOV_log(sub_io,sub_iocnt);
            //ret = strict_send(sockfd,(uint8_t *)buf.buffer+*bytes_written,downloaded,flags);
            ret = original_send(sockfd,(uint8_t *)buf.buffer+*bytes_written,downloaded,flags);
            if( ret < 0 ){
                ERROR_LOG("Body send failed");
                return ODB_SOCKET_WRITE_ERROR;
            }
            DEBUG_LOG("Body send -> wrote %zu bytes",(size_t)ret);
            *bytes_written += (size_t) ret;
        }
    }

    //3rd step, send tail_data
    if(info->desc.d_desc.tail_size > 0 && *bytes_written < info->odb_header.total_size){
        //ret = strict_send(sockfd,buf.buffer+*bytes_written,MIN(info->desc.d_desc.tail_size,info->odb_header.total_size -*bytes_written),flags);
        ret = original_send(sockfd,buf.buffer+*bytes_written,MIN(info->desc.d_desc.tail_size,info->odb_header.total_size -*bytes_written),flags);
        if( ret < 0 ){
            ERROR_LOG("Tail writev failed");
            return ODB_SOCKET_WRITE_ERROR;
        }
        DEBUG_LOG("Tail Writev -> wrote %zu bytes",(size_t)ret);
        *bytes_written += (size_t) ret;
    }
    DEBUG_LOG("Wrote %zu real bytes to client %d",*bytes_written,sockfd);

    return ODB_SUCCESS;
}

static ODB_ERROR send_real(int sockfd,ConnectionInfo *info,int flags, size_t *bytes_written){
    //ODB_init();
    if( info == NULL  || bytes_written == NULL) return ODB_NULL_PTR;
    
    ssize_t ret = 0;
    struct iovec frame[2] = {{&info->odb_header,ODB_HEADER_SIZE},
                                  {info->payload.buffer,info->odb_header.total_size}};
    struct msghdr      msg      = MSGHDR_INITIALIZER(frame,2,flags);
    *bytes_written = 0;

    // resume header transmission if needed
    if(0 < info->bytes_read_write && info->bytes_read_write < ODB_HEADER_SIZE){
        frame[0].iov_len = ODB_HEADER_SIZE - info->bytes_read_write;
        frame[0].iov_base =(void*) ((uint8_t*) &(info->odb_header) + info->bytes_read_write);
    }
    DEBUG_LOG("Sending Real payload of size %zu ...",info->odb_header.total_size);

    // update header
    INIT_ODB_Header((&info->odb_header), ODB_MSG_SEND_REAL,info->odb_header.total_size);
    compute_ODB_crc(&info->odb_header,NULL);
    DEBUG_LOG("Header to send :");
    ODB_HEADER_log(&info->odb_header);

    // prepare frame to be write
    DEBUG_LOG("Call to original sendmsg...");
    ret = original_sendmsg(sockfd,&msg,2);
    if(ret < 0){
        ERROR_LOG("send real");
        return ODB_SOCKET_WRITE_ERROR;
    }
    else if(ret == 0){ ERROR_LOG("send real returned 0 bytes");}
    

    const size_t should_have_written = ODB_HEADER_SIZE + info->odb_header.total_size;
    *bytes_written = (size_t) ret;
     DEBUG_LOG("Transmit %zu real bytes (including header)",*bytes_written);
    if(*bytes_written < should_have_written){
        info->bytes_read_write += *bytes_written;
        *bytes_written = 0;
        return ODB_INCOMPLETE;
    }
    *bytes_written -= ODB_HEADER_SIZE;
    DEBUG_LOG("Wrote %zu real bytes : ",*bytes_written);

    return ODB_SUCCESS;
}

static ODB_ERROR send_virtual_transmit(int sockfd,ConnectionInfo *info,int flags,size_t *bytes_written){
    //ODB_init();
    (void) flags;
    if( info == NULL || bytes_written == NULL) return ODB_NULL_PTR;
    
    ODB_Frame frame;
    struct  msghdr msg = MSGHDR_INITIALIZER(frame,ODB_FRAME_SIZE,flags);
    //size_t  desc_len   = info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size;
    ssize_t ret        = 0;
    *bytes_written     = 0;

    DEBUG_LOG("Will send %zu head bytes || %zu tail bytes through socket %d ",info->desc.d_desc.head_size, info->desc.d_desc.tail_size, sockfd);
    DEBUG_LOG("Associated Buffer to write :");  ODB_Local_Buffer_log(&info->payload);
    DEBUG_LOG("Associated Desc :"); ODB_DESC_log(&info->desc);

    // Prepare frame to be written

    if( info->bytes_read_write == 0){
        setup_send_virtual_transmit(&frame,info);
        INIT_ODB_Header((&info->odb_header),ODB_MSG_SEND_VIRTUAL,info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size);
        DEBUG_LOG("Frame to write :");
        DEBUG_LOG("(head) : %zu || (head_desc): %zu ",frame[2].iov_len,info->desc.d_desc.head_size);
        DEBUG_LOG("(tail) : %zu || (tail_desc): %zu ",frame[3].iov_len,info->desc.d_desc.tail_size);
        DEBUG_LOG("(head) %p (tail) %p",frame[2].iov_base,frame[3].iov_base);
        compute_ODB_crc(&info->odb_header,&info->desc);
        serialize_odb_desc_inplace(&info->desc);
    }
    else{
        setup_send_virtual_transmit(&frame,info);
        DEBUG_LOG("Frame to write :");
        DEBUG_LOG("(head) : %zu || (head_desc): %zu ",frame[2].iov_len,info->desc.d_desc.head_size);
        DEBUG_LOG("(tail) : %zu || (tail_desc): %zu ",frame[3].iov_len,info->desc.d_desc.tail_size);
        DEBUG_LOG("(head) %p (tail) %p",frame[2].iov_base,frame[3].iov_base);
        serialize_odb_desc_inplace(&info->desc);
    }

    // send ODB message
    ret = original_sendmsg(sockfd,&msg,flags);
    if( ret < 0 ){
        ERROR_LOG("virtualised sendmsg failed");
        return ODB_SOCKET_WRITE_ERROR;
    }
    else if( ret == 0 ){ ERROR_LOG("virtualised sendmsg returned 0 bytes"); }

    *bytes_written = (size_t) ret;
    deserialize_odb_desc_inplace(&info->desc);

    #if DEBUG
        size_t tmp = *bytes_written;
    #endif
    DEBUG_LOG("Virtually transmitted %zu bytes, send %zu real bytes",*bytes_written,tmp);

    const size_t should_have_written = ODB_HEADER_SIZE + ODB_DESC_SIZE + info->desc.d_desc.head_size + info->desc.d_desc.tail_size;
    if( info->bytes_read_write + *bytes_written < should_have_written ){
        ERROR_LOG("Virtually transmitted %zu bytes, should have written %zu",*bytes_written,should_have_written);
        if(info->bytes_read_write + *bytes_written < ODB_HEADER_SIZE + ODB_DESC_SIZE){
            info->bytes_read_write += *bytes_written;
            *bytes_written = 0;
        }
        return ODB_INCOMPLETE;
    }
    *bytes_written = *bytes_written - ODB_DESC_SIZE - ODB_HEADER_SIZE + info->desc.d_desc.body_size;
    

    return ODB_SUCCESS;
}

static ODB_ERROR send_virtual(int sockfd,ConnectionInfo *info,int flags, size_t *bytes_written){
    if( info == NULL || bytes_written == NULL) return ODB_NULL_PTR;
    DEBUG_LOG("Sending Virtual payload of size %zu ...",info->odb_header.total_size);

    ODB_Frame        frame;
    struct msghdr    msg         = MSGHDR_INITIALIZER(frame,ODB_FRAME_SIZE,flags);
    ODB_Local_Buffer *rab_buffer = NULL;
    size_t odb_fd;

    if(info->bytes_read_write == 0){
        rab_buffer = create_ODB_Remote_Buffer(&intern_RAB,info->odb_header.total_size, &odb_fd);
        if(NULL == rab_buffer || NULL == rab_buffer->buffer){
            DEBUG_LOG("create_ODB_Remote_Buffer NOT created ! \n");
            return ODB_MEMORY_ALLOCATION_ERROR;
        }
        DEBUG_LOG("create_ODB_Remote_Buffer created with id : %zu ! \n", odb_fd);

        // try to create a sever thread, 
        // if not exists and, update server address for desc
        ODB_ERROR err = create_ODB_Server_if_not_exist(&info->desc.source_addr,&ODB_conf);
        if(ODB_SUCCESS != err){
            ERROR_LOG("Unable to create RAB !");
            remove_ODB_Remote_Buffer(&intern_RAB, odb_fd);
            return err;
        }
        DEBUG_LOG("ODB server thread created ! \n");

        // copy data to the new RAB 
        memcpy(rab_buffer->buffer,info->payload.buffer,info->odb_header.total_size);
        DEBUG_LOG("Data copied to RAB :\n");
        ODB_Local_Buffer_log(rab_buffer);
        memcpy(&info->payload, rab_buffer, sizeof(ODB_Local_Buffer));

        // prepare the frame
        setup_send_virtual(&frame,info);

        INIT_ODB_Desc(info->desc,odb_fd,rab_buffer->head_size,rab_buffer->body_size,rab_buffer->tail_size,info->desc.source_addr);
        INIT_ODB_Header((&info->odb_header),ODB_MSG_SEND_VIRTUAL,info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size);
        compute_ODB_crc(&info->odb_header,&info->desc);
    }
    else{
        setup_send_virtual(&frame,info);
    }

    DEBUG_LOG(  "Bytes sent : %zu \n"
                "frame[odb_header]      = %p : %zu \n"
                "frame[odb_desc]        = %p : %zu \n"
                "frame[payload_header]  = %p : %zu \n"
                "frame[payload_tail]    = %p : %zu ",
                info->bytes_read_write,
                frame[0].iov_base,frame[0].iov_len,
                frame[1].iov_base,frame[1].iov_len,
                frame[2].iov_base,frame[2].iov_len,
                frame[3].iov_base,frame[3].iov_len);


    DEBUG_LOG("Writting virtual data ...\n");
    DEBUG_LOG("Virtual Desc :"); ODB_DESC_log(&info->desc);
    DEBUG_LOG("Virtual Header :"); ODB_HEADER_log(&info->odb_header);
    DEBUG_LOG("Remote Buffer : ");  ODB_Local_Buffer_log(&info->payload);
    serialize_odb_desc_inplace(&info->desc);
    ssize_t ret = original_sendmsg(sockfd,&msg,flags);
    if( ret < 0 ){
        ERROR_LOG("Error with virtualized sendmsg");
        deserialize_odb_desc_inplace(&info->desc);
        return ODB_SOCKET_WRITE_ERROR;
    }
    if( ret == 0 ){ERROR_LOG("Error with virtualized sendmsg");}
    
    *bytes_written = (size_t) ret;
    deserialize_odb_desc_inplace(&info->desc);

    const size_t should_have_written = info->desc.d_desc.head_size + info->desc.d_desc.tail_size + ODB_HEADER_SIZE + ODB_DESC_SIZE;
    if(should_have_written > info->bytes_read_write + *bytes_written ) {
        ERROR_LOG("Wrote %zu / %zu real bytes",*bytes_written,should_have_written);
        // copy rab info to the connection info (in order to be able to resume sending)
        //memcpy(&info->payload, rab_buffer, sizeof(ODB_Local_Buffer));
        if(info->bytes_read_write + *bytes_written < ODB_HEADER_SIZE + ODB_DESC_SIZE){
            info->bytes_read_write += *bytes_written;
            *bytes_written = 0;
        }
        return ODB_INCOMPLETE;
    }
    
    DEBUG_LOG("Wrote unaligned %zu bytes, %zu virtual bytes",*bytes_written - (ODB_HEADER_SIZE + ODB_DESC_SIZE) ,info->odb_header.total_size);
    *bytes_written = *bytes_written + info->desc.d_desc.body_size - (ODB_HEADER_SIZE + ODB_DESC_SIZE);
    
    return ODB_SUCCESS;
}

ssize_t send(int socket, const void *buf, size_t buf_len, int flags){
    #if !ODB
        DEBUG_LOG("send(socket:%d,buf:%p,buf_len:%zu,flags:%d)",socket,buf,buf_len,flags);
        return original_send(socket,buf,buf_len,flags);
    #endif

    if( buf == NULL || buf_len == 0 ){
        errno = EINVAL;
        return -1;
    }

    // test if it's a tcp socket
    if( is_socket(socket) <= 0){
        ssize_t o_ret = original_send(socket,buf,buf_len,flags);
        if(o_ret>0){
            DEBUG_LOG("Sent :");Buffer_log(buf,(size_t) o_ret);
        }
        return o_ret;
    }

    #if DEBUG
        static uint64_t frame_count = 0;
        static uint64_t tot_bytes_send = 0;
        DEBUG_LOG("send(socket:%d,buf:%p,buf_len:%zu,flags:%d)",socket,buf,buf_len,flags);
        DEBUG_LOG("[SEND FRAME %lu] // bytes sent so far : %zu",frame_count++,tot_bytes_send);
    #endif
    
    // If no connection is found, create a new one and set headerInprogress to 1
    // No entry for this socket => Request send or Backend 
    ConnectionTable *entry          = get_connection(&up_connections, socket);
    size_t          bytes_written   = 0;
    ODB_ERROR       err             = ODB_SUCCESS;

    if (entry == NULL){
        DEBUG_LOG("SEND : get_connection -> no connection found or created");
        errno = ENOSPC;
        return -1;
    }

    // setup info 
    err = setup_send_info(buf,buf_len,&entry->info);
    //errno = 0;
    if ( ODB_SUCCESS != err ){
        ERROR_LOG("SEND : setup_info -> error %d",err);
        return -1;
    }

    switch(entry->info.progress){
        // if connection is not ODB, send all real data
        case ODB_SEND_CLIENT_REAL:
        case ODB_SEND_CLIENT_VIRTUAL:
            DEBUG_LOG("Sending to client ...");
            err = send_to_client(socket,&entry->info, flags, &bytes_written);
        break;
        case ODB_SEND_VIRTUAL_TRANSMIT:
            // Transfer virtual data
            err = send_virtual_transmit(socket,&entry->info, flags, &bytes_written);
        break;
        case ODB_SEND_REAL:
            if( entry->info.odb_header.total_size <= (size_t) VIRTUAL_THRESHOLD){
                err = send_real(socket,&entry->info, flags, &bytes_written);
            }
            // Virtual payload
            else{
                entry->info.progress = ODB_SEND_VIRTUAL;
                err = send_virtual(socket,&entry->info, flags, &bytes_written);
                if ( ODB_SUCCESS != err && ODB_INCOMPLETE != err){
                    // try to send data in real if Failed
                    ERROR_LOG("send_virtual failed -> call send_real");
                    err = send_real(socket,&entry->info, flags, &bytes_written);
                }
            }
        break;
        case ODB_SEND_VIRTUAL:
            err = send_virtual(socket,&entry->info, flags, &bytes_written);
        break;
        default:
        break;
    }
    
    entry->info.bytes_read_write += (size_t) bytes_written;
    
    switch(err){
        case ODB_SUCCESS:
            entry->info.progress         = ODB_NONE;
            entry->info.bytes_read_write = 0;
        break;
        case ODB_INCOMPLETE:
            if(bytes_written == 0){
                errno = ENOSPC;
                ERROR_LOG("Didn't write application data");
                return -1;
            }
        break;
        case ODB_SOCKET_WRITE_ERROR:
            ERROR_LOG("ODB_SOCKET_WRITE_ERROR with socket %d",socket);
            return -1;
        break;
        default:
            DEBUG_LOG("send failed ! calling original_send");
            ssize_t original_ret = original_send(socket, buf, buf_len,flags);
            if(original_ret > 0)
                entry->info.bytes_read_write += (size_t) original_ret;
            return original_ret;
    }

    #if DEBUG
        tot_bytes_send += bytes_written;
    #endif
    ODB_State_log(entry->info.progress);
    //sleep(1);

    DEBUG_LOG("send(socket=%d, buf=%p, len=%zu, flags=%d) = %zu bytes",socket,buf,buf_len,flags,bytes_written);
    return bytes_written;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,const struct sockaddr *dest_addr, socklen_t addrlen){
    //ODB_init();
    #if !ODB
        DEBUG_LOG("sendto(socket=%d, buf=%p, len=%zu, flags=%d)",sockfd,buf,len,flags);
        //Buffer_log(buf,len);
        return original_sendto(sockfd,buf,len,flags,dest_addr,addrlen);
    #endif
    
    if(buf == NULL || len == 0) return original_sendto(sockfd,buf,len,flags,dest_addr,addrlen);

    //DEBUG_LOG("sendto being intercepted");
    return send(sockfd,buf,len,flags);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){
    ssize_t ret = 0;
    DEBUG_LOG("sendmsg(socket=%d, msg=%p, flags=%d)",sockfd,msg,flags);
    MSGHDR_log(msg);
    #if !ODB
        ret = original_sendmsg(sockfd,msg,flags);
    #else
        if(msg ==NULL || msg->msg_iov == NULL || msg->msg_iovlen == 0) 
            ret = original_sendmsg(sockfd,msg,flags);
        else{
            for(size_t i = 0; i < msg->msg_iovlen; i++){
                ssize_t local_ret = send(sockfd,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len,flags);
                if(local_ret < 0){
                    ERROR_LOG("send(%d, %p, %zu, %d)",sockfd,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len,flags);
                    if(ret == 0) ret = -1;
                    break;
                }
                ret += local_ret;
                // if we didn't write all the iov, stop
                if((size_t) local_ret < msg->msg_iov[i].iov_len) break;
            }
        }
    #endif

    DEBUG_LOG("sendmsg(socket=%d, msg=%p, flags=%d) = %zd bytes",sockfd,msg,flags,ret);

    return ret;
}

// ************************************
// *                                  *
// *          write section           *
// *                                  *
// ************************************

ssize_t write(int fd, const void *buf, size_t len){
    ssize_t ret = 0;
    errno = 0;
    DEBUG_LOG("write(fd=%d, buf=%p, len=%zu)",fd,buf,len);
    #if !ODB
        ret = original_write(fd,buf,len);
    #else
        if(buf == NULL || len == 0 || is_socket(fd) <= 0){
            ret = original_write(fd,buf,len);
        }
        else{
            ret = send(fd,buf,len,0);
            DEBUG_LOG("write(socket=%d, buf=%p, len=%zu) = %zd bytes",fd,buf,len,ret);
        }
    #endif
    if(ret > 0){Buffer_log(buf,ret);}
    DEBUG_LOG("write(fd=%d, buf=%p, len=%zu) = %zd bytes",fd,buf,len, ret);
    return ret;
}

ssize_t writev(int socket, const struct iovec *iov, int iovcnt) {
    ssize_t ret = 0;
    errno = 0;
    DEBUG_LOG("ODB writev(socket=%d, iov=%p, iovcnt=%d)",socket,iov,iovcnt);
    #if !ODB
        ret = original_writev(socket,iov,iovcnt);
    #else
        if(iov == NULL || iovcnt == 0 || is_socket(socket)<=0){
            ret = original_writev(socket,iov,iovcnt);
        }
        else{
            size_t tot_len   = 0;
            for(int i=0; i<iovcnt; i++){
                errno = 0;
                tot_len += iov[i].iov_len;
                ssize_t local_ret = write(socket,iov[i].iov_base,iov[i].iov_len);
                if(local_ret<0){
                    ERROR_LOG("writev");
                    if(ret == 0) ret = -1;
                    break;
                }
                Buffer_log(iov[i].iov_base,(size_t) local_ret);
                ret += local_ret;
                // if we didn't write all the iov, stop
                if((size_t) local_ret < iov[i].iov_len) break;
            }
            DEBUG_LOG("writev %zd / %zu bytes ", ret,tot_len);
        }
    #endif

    //if(ret > 0){ IOV_log(iov,iovcnt);}
    if(ret < 0){ERROR_LOG("writev");}
    if(errno==EAGAIN || errno==EWOULDBLOCK){
        //determine if FNDELAY is set
        int flags = fcntl(socket,F_GETFL,0);
        if(flags & FNDELAY){
            errno = 0;
            ret = 0;
        }
    }
    DEBUG_LOG("writev(socket=%d, iov=%p, iovcnt=%d) = %zd bytes",socket,iov,iovcnt,ret);
    return ret;
}

// ************************************
// *                                  *
// *            Recv section          *
// *                                  *
// ************************************

static void restore_from_cache(ConnectionInfo *info,void *buffer, size_t length, size_t *read_bytes){
    if( info == NULL || buffer == NULL || length == 0 || read_bytes == NULL) return;

    size_t  offset        = 0;
    size_t  to_read       = MIN(length,info->bytes_read_write);
    uint8_t *restore_from = NULL, *copy_to = (uint8_t*) buffer;
            *read_bytes   = 0;


    DEBUG_LOG("restore_from_cache : %zu bytes read",to_read);
    ODB_State_log(info->progress);
    
    if(info->bytes_read_write == 0){
        info->progress = ODB_NONE;
        return;
    }
    
    switch(info->progress){
        // in this case, use info->odb_header.total_size as offset
        case ODB_RESTORE_FROM_HEADER_AND_DESC:
            // copy desc to buffer
            offset = MIN(info->is_ODB,ODB_HEADER_SIZE + ODB_DESC_SIZE);
            if(offset < ODB_HEADER_SIZE){
                to_read  = MIN(to_read,ODB_HEADER_SIZE-offset);
                restore_from = ((uint8_t*) &info->odb_header) + offset;
                DEBUG_LOG("copying %zu bytes from header, with offset %zu (ODB_HEADER_SIZE = %zu)",to_read,offset,ODB_HEADER_SIZE);
                DEBUG_LOG("copying from %p, header at %p",restore_from,&info->odb_header);
                Buffer_log(restore_from,to_read);
                memcpy((void*)copy_to,(void*) restore_from,to_read);
                DEBUG_LOG("Copied buffer:");
                Buffer_log(copy_to,to_read);
                info->bytes_read_write -= to_read;
                info->is_ODB           += (uint8_t) to_read;
                *read_bytes            += to_read;
                copy_to                += to_read;
            }
            DEBUG_LOG("copied %zu bytes from header",to_read);
            // if we copied back all the header
            if(info->is_ODB >= ODB_HEADER_SIZE){
                offset   = info->is_ODB - ODB_HEADER_SIZE;
                to_read  = MIN(length,info->bytes_read_write);
                to_read  = MIN(to_read,ODB_DESC_SIZE-offset);
                restore_from   = (uint8_t*) &info->desc;
                DEBUG_LOG("copying %zu bytes from desc, with offset %zu",to_read,offset);
                info->progress = ODB_RESTORE_FROM_DESC;
                // reset to no ODB status
                info->is_ODB   = 0;
            }
            else return;
        break;
        case ODB_RESTORE_FROM_DESC:
            offset       = ODB_DESC_SIZE >= info->bytes_read_write ? ODB_DESC_SIZE - info->bytes_read_write : 0;
            to_read      = MIN(to_read,ODB_DESC_SIZE-offset); 
            restore_from = (uint8_t*) &info->desc;
        break;
        case ODB_RESTORE_FROM_HEADER:
            offset       = ODB_HEADER_SIZE >= info->bytes_read_write ? ODB_HEADER_SIZE - info->bytes_read_write : 0;
            to_read      = MIN(to_read,ODB_HEADER_SIZE-offset);
            restore_from = (uint8_t*) &info->odb_header;
        break;
        default:
        return;
    }
    
    DEBUG_LOG("Will copy %zu bytes to buffer...",to_read);
    restore_from += offset;
    *read_bytes  += to_read;
    memcpy((void*)copy_to,(void*) restore_from,to_read);
    DEBUG_LOG("Copied buffer:");
    Buffer_log(copy_to,to_read);
    //update info
    info->bytes_read_write -= to_read;
    info->progress = info->bytes_read_write == 0 ? ODB_NONE : info->progress;
    // complete buffer with recv
}

static ODB_ERROR recv_ODB_Header_and_Desc(int socket, void *buffer, size_t length,size_t *read_bytes, int flags,ConnectionInfo *info){
    if(read_bytes == NULL || info == NULL ) return ODB_NULL_PTR;

    uint8_t   *copy_to     = NULL;
    size_t    bytes_to_rec = 0;
    ssize_t   bytes_rec    = 0;

    
    // determine wether the sock is connected or not
    int is_blocking_sock = fcntl(socket, F_GETFL);
    if(is_blocking_sock < 0){
        ERROR_LOG("fcntl");
    }
    // if fcntl failed, will treat the socket as blocking
    is_blocking_sock = is_blocking_sock < 0 ? 1 : (!(is_blocking_sock & O_NONBLOCK) && !(flags & MSG_DONTWAIT));
    #if DEBUG
        if(is_blocking_sock) DEBUG_LOG("Socket %d is blocking",socket);
        else DEBUG_LOG("Socket %d is not blocking",socket);
    #endif

    //if(is_blocking_sock){
    //    DEBUG_LOG("Set_wait_all flag");
    //    flags |= MSG_WAITALL;
    //}

    // try to recv Header
    while(info->bytes_read_write < ODB_HEADER_SIZE){

        // Receiving Header
        copy_to      = ((uint8_t *) &(info->odb_header)) + info->bytes_read_write;
        bytes_to_rec = ODB_HEADER_SIZE - info->bytes_read_write;
        
        bytes_rec    = original_recv(socket, copy_to, bytes_to_rec, flags);
        
        if(bytes_rec < 0){
            if((errno == EAGAIN || errno == EWOULDBLOCK)){
                if(!is_blocking_sock) return ODB_INCOMPLETE;
                else  continue;
            }
            return ODB_SOCKET_READ_ERROR;
        }

        info->bytes_read_write  += (size_t) bytes_rec;
        
        // if we did not recv enough data -> blocking -> error, or not blocking -> incomplete 
        if( info->bytes_read_write < ODB_HEADER_SIZE ){
            if( is_blocking_sock ){
                info->progress = ODB_RESTORE_FROM_HEADER;
                ERROR_LOG("recveived %zu bytes, expected %zu",info->bytes_read_write,ODB_HEADER_SIZE);
                restore_from_cache(info,buffer,length,read_bytes);
                return ODB_PARSE_ERROR;
            }
            else{
                errno = EAGAIN; 
                return ODB_INCOMPLETE;
            }
        }

        // check if header is valid
        compute_ODB_crc(&info->odb_header,NULL);
        if(parse_ODB_Header_Desc(&info->odb_header,&info->desc) != ODB_SUCCESS){
            ERROR_LOG("parse_ODB_Header_Desc failed");
            info->is_ODB = 0;
            restore_from_cache(info,buffer,length,read_bytes);
            return ODB_PARSE_ERROR;
        }

        // if we're receiving real data, no need to recv a desc, parsing is done
        if(ODB_MSG_SEND_REAL == info->odb_header.type ){
            info->desc.d_desc.head_size    = 0;
            info->desc.d_desc.body_size    = info->odb_header.total_size;
            info->desc.d_desc.tail_size    = 0;
            goto parse_header_desc_done;
        }
        break;

    }


    // try to recv DESC
    while(info->bytes_read_write < ODB_HEADER_SIZE + ODB_DESC_SIZE){
        
        // Receiving Desc
        copy_to      = ((uint8_t *) &(info->desc)) + info->bytes_read_write - ODB_HEADER_SIZE;
        bytes_to_rec = ODB_DESC_SIZE + ODB_HEADER_SIZE - info->bytes_read_write;
        bytes_rec    = original_recv(socket, copy_to, bytes_to_rec, flags);

        if(bytes_rec < 0){
            if((errno == EAGAIN || errno == EWOULDBLOCK)){
                if(!is_blocking_sock)
                    return ODB_INCOMPLETE;
                else continue;
            }
            return ODB_SOCKET_READ_ERROR;
        }

        info->bytes_read_write  += (size_t) bytes_to_rec;


        // if we did not recv enough data -> blocking -> error, or not blocking -> incomplete 
        if( info->bytes_read_write < ODB_HEADER_SIZE + ODB_DESC_SIZE ){
            if( is_blocking_sock ){
                info->progress = ODB_RESTORE_FROM_HEADER_AND_DESC;
                restore_from_cache(info,buffer,length,read_bytes);
                return ODB_PARSE_ERROR;
            }
            else{
                errno = EAGAIN; 
                return ODB_INCOMPLETE;
            }
        }

        // check if DESC is valid
        deserialize_odb_desc_inplace(&info->desc);
        compute_ODB_crc(&info->odb_header,&info->desc);
        if(parse_ODB_Header_Desc(&info->odb_header,&info->desc) != ODB_SUCCESS){
            info->is_ODB = 0;
            info->progress = ODB_RESTORE_FROM_HEADER_AND_DESC;
            restore_from_cache(info,buffer,length,read_bytes);
            return ODB_PARSE_ERROR;
        }
        else{
            break;
        }
    }

parse_header_desc_done:
    info->is_ODB           = 1;
    info->bytes_read_write = 0;
    info->progress         = ODB_PAYLOAD_IN_PROGRESS;
    
    return ODB_SUCCESS;
}

static ODB_ERROR recv_real_payload(int socket,size_t *bytes_read, int flags,ConnectionInfo *info){
    if(bytes_read == NULL || info == NULL || info->payload.buffer == NULL ) return ODB_NULL_PTR;
    DEBUG_LOG("ODB : Receiving real data... \n");

    size_t buf_size      = info->payload.head_size + info->payload.body_size + info->payload.tail_size;
    size_t payload_size  = info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size;

    size_t bytes_to_read = payload_size > info->bytes_read_write ? payload_size - info->bytes_read_write : 0;
           bytes_to_read = MIN(bytes_to_read,buf_size);
    ssize_t recv_bytes  = 0;

    // make rest of buffer unusable (not necessary but useful for debugging)
    #if DEBUG
        memset((uint8_t*)info->payload.buffer,0,buf_size);
    #endif

    recv_bytes = original_recv(socket, (uint8_t*)info->payload.buffer, bytes_to_read, flags);

    if(recv_bytes < 0){
        *bytes_read = 0;
        return ODB_SOCKET_READ_ERROR;
    }
    info->bytes_read_write += (size_t) recv_bytes;
    *bytes_read             = (size_t) recv_bytes;


    DEBUG_LOG("Received %zu bytes of real data : \n",*bytes_read);
    Buffer_log(info->payload.buffer,*bytes_read);

    return ODB_SUCCESS;
}

static ODB_ERROR recv_virtual_to_real(int socket,size_t *bytes_read, int flags,ConnectionInfo *info){
    if(bytes_read == NULL || info == NULL || info->payload.buffer == NULL ) return ODB_NULL_PTR;

    const size_t buf_size       = info->payload.head_size + info->payload.body_size + info->payload.tail_size;
    const size_t hd_and_bd_size = info->desc.d_desc.head_size + info->desc.d_desc.body_size;
    const size_t payload_size   = info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size;
    *bytes_read                 = 0;

    DEBUG_LOG("Local Buffer where data will be stored : \n");
    ODB_Local_Buffer_log(&info->payload);
    DEBUG_LOG("Virtual Desc to receive : \n");
    ODB_DESC_log(&info->desc);
    DEBUG_LOG("Received %zu / %zu bytes ",info->bytes_read_write,payload_size);

    if(info->desc.d_desc.head_size == 0 && ODB_RECEIVING_HEAD == info->progress )
        info->progress = ODB_DOWNLOAD_PAYLOAD;
    if(info->desc.d_desc.body_size == 0 && ODB_DOWNLOAD_PAYLOAD == info->progress )
        info->progress = ODB_RECEIVING_TAIL;
    if(info->desc.d_desc.tail_size == 0 && ODB_RECEIVING_TAIL == info->progress )
        info->progress = ODB_NONE;
    

    if(ODB_RECEIVING_HEAD == info->progress && info->bytes_read_write < info->desc.d_desc.head_size){
        DEBUG_LOG("ODB : Receiving header... \n");
        size_t bytes_to_read = info->bytes_read_write < info->desc.d_desc.head_size ? info->desc.d_desc.head_size - info->bytes_read_write : 0;
               bytes_to_read = MIN(bytes_to_read,buf_size);
        ssize_t recv_bytes = original_recv(socket, (uint8_t*)info->payload.buffer, bytes_to_read, flags | MSG_WAITALL);

        if(recv_bytes < 0){
            ERROR_LOG("Receiving head data");
            return ODB_SOCKET_READ_ERROR;
        }
        if((size_t) recv_bytes < bytes_to_read){
            ERROR_LOG("Received %zu / %zu",recv_bytes,bytes_to_read);
        }
        DEBUG_LOG("Received %zu bytes of header data : \n",(size_t) recv_bytes);
        Buffer_log(info->payload.buffer,(size_t) recv_bytes);

        info->bytes_read_write += (size_t) recv_bytes;
        *bytes_read             = (size_t) recv_bytes;

        if(info->bytes_read_write >= info->desc.d_desc.head_size)
            info->progress = ODB_DOWNLOAD_PAYLOAD;
    }

    // download data from remote if we met undesired conditions to apply ODB correctly
    if(ODB_DOWNLOAD_PAYLOAD == info->progress && *bytes_read < buf_size && info->bytes_read_write < hd_and_bd_size){
        DEBUG_LOG("ODB : Downloading body ... !!");
        // create query to download payload
        ODB_Query_Desc     query;
        size_t            real_read = 0;
        query.type        = ODB_MSG_GET_PAYLOAD;
        query.d_desc.fd   = info->desc.d_desc.fd;
        // head_size is use as an offset to read new data till we download all data
        query.d_desc.head_size   = info->bytes_read_write;
        // tell we be receive later, so don't download it now
        query.d_desc.body_size   = MIN(buf_size-*bytes_read, hd_and_bd_size- info->bytes_read_write);
        query.d_desc.tail_size   = 0;

        DEBUG_LOG("ODB getting Payload : %zu bytes with %zu offset",query.d_desc.body_size,query.d_desc.head_size);
        if( ODB_SUCCESS != ODB_get_remote_data(&query,&info->desc.source_addr,&info->payload,*bytes_read,&real_read) ){
            DEBUG_LOG("Didn't get remote data !!");
            return ODB_UNKNOWN_ERROR;
        }
        info->bytes_read_write  += real_read;
        *bytes_read             += real_read;
        DEBUG_LOG("Received %zu bytes of payload data : \n",real_read);
        if(info->bytes_read_write >= info->desc.d_desc.head_size + info->desc.d_desc.body_size){
            info->progress = ODB_RECEIVING_TAIL;
        }
    }

    if(ODB_RECEIVING_TAIL == info->progress && *bytes_read < buf_size && info->bytes_read_write < payload_size){
        DEBUG_LOG("ODB : Receiving tail... \n");
        size_t bytes_to_read = MIN(payload_size - info->bytes_read_write,buf_size - *bytes_read);
        ssize_t recv_bytes = original_recv(socket, (uint8_t*)info->payload.buffer + *bytes_read, bytes_to_read, flags | MSG_WAITALL);
        if(recv_bytes < 0){
            ERROR_LOG("Receiving tail data");
            *bytes_read = 0;
            return ODB_SOCKET_READ_ERROR;
        }
        if((size_t)recv_bytes < bytes_to_read){
            ERROR_LOG("Received %zu / %zu",recv_bytes,bytes_to_read);
        }
        DEBUG_LOG("Received %zu bytes of tail data : \n",(size_t) recv_bytes);
        Buffer_log(info->payload.buffer + *bytes_read,(size_t) recv_bytes);

        info->bytes_read_write += (size_t) recv_bytes;
        *bytes_read            += (size_t) recv_bytes;
    }

    if(info->bytes_read_write >= payload_size){
        info->progress = ODB_NONE;
        DEBUG_LOG("ODB : Receiving finished... \n");
    }
    
    // Print received data :
    DEBUG_LOG("All bytes received here : %zu, Total : %zu",*bytes_read,info->bytes_read_write);

    return ODB_SUCCESS;
}

static ODB_ERROR recv_virtual_payload(int socket, size_t *bytes_read, int flags,ConnectionInfo *info){
    if(bytes_read == NULL || info == NULL || info->payload.buffer == NULL) return ODB_NULL_PTR;

    const size_t unaligned_size = info->desc.d_desc.head_size + info->desc.d_desc.tail_size;
    const size_t payload_size   = info->desc.d_desc.head_size + info->desc.d_desc.body_size + info->desc.d_desc.tail_size;
    const size_t buf_size       = info->payload.head_size + info->payload.body_size + info->payload.tail_size;

    struct iovec iov[2]         = {{NULL,0},{NULL,0}};
    struct msghdr msg           = MSGHDR_INITIALIZER(iov,2,flags);
    *bytes_read                 = 0;

    DEBUG_LOG("ODB : Receiving virtual data... \n");
    DEBUG_LOG("ODB local buffer: "); ODB_Local_Buffer_log(&info->payload);
    DEBUG_LOG("ODB Desc : "); ODB_DESC_log(&info->desc);

    // apparently gives bad adress error
    if(info->bytes_read_write < info->desc.d_desc.head_size){
        // receive the head in the head part of the buffer
        iov[0].iov_len = MIN(buf_size,info->desc.d_desc.head_size - info->bytes_read_write);
        iov[0].iov_base = (void*) ((uint8_t*)info->payload.buffer + info->bytes_read_write);
        // receive the tail and put it at the end of the buffer
        iov[1].iov_len = MIN(buf_size,info->desc.d_desc.tail_size);
        iov[1].iov_base = (void*) ((uint8_t*)info->payload.buffer + (buf_size - iov[1].iov_len));
    }
    else if(info->desc.d_desc.head_size <= info->bytes_read_write && info->bytes_read_write < unaligned_size){
        // only have to receive the tail
        iov[0].iov_len = MIN(buf_size,unaligned_size - info->bytes_read_write);
        iov[0].iov_base = (void*) ((uint8_t*)info->payload.buffer + (buf_size - iov[0].iov_len));
    }

    if(info->bytes_read_write < unaligned_size){
        DEBUG_LOG("Receiving %zu head_bytes + %zu tail_bytes...\n",iov[0].iov_len,iov[1].iov_len);
        ssize_t recv_bytes = original_recvmsg(socket, &msg, flags);
        if(recv_bytes < 0){
            ERROR_LOG("Received %zd/%zu bytes",recv_bytes,unaligned_size);
            return ODB_SOCKET_READ_ERROR;
        }
        info->bytes_read_write += (size_t) recv_bytes;
        *bytes_read             = (size_t) recv_bytes;
        DEBUG_LOG("Received %zu / %zu bytes of unaligned data : \n",*bytes_read,unaligned_size);
    }

    if( unaligned_size <= info->bytes_read_write ){

        // compute new desc for the payload
        ODB_Desc *desc_in_body_p = NULL;
        size_t new_head_size     = MAX(info->payload.head_size,info->desc.d_desc.head_size);
        size_t new_tail_size     = MAX(info->payload.tail_size,info->desc.d_desc.tail_size);
        size_t delta_size        = new_head_size + new_tail_size - info->desc.d_desc.head_size - info->desc.d_desc.tail_size;
        size_t new_body_size     = info->desc.d_desc.body_size - delta_size;

        // update header/ desc info
        size_t desc_offset = MIN(new_head_size,info->payload.head_size + info->payload.body_size - ODB_DESC_SIZE);
        desc_in_body_p =(ODB_Desc*) ((uint8_t*) info->payload.buffer + desc_offset);
        desc_in_body_p->d_desc.head_size = new_head_size;
        desc_in_body_p->d_desc.body_size = new_body_size;
        desc_in_body_p->d_desc.tail_size = new_tail_size;
        desc_in_body_p->d_desc.fd        = info->desc.d_desc.fd;
        desc_in_body_p->source_addr      = info->desc.source_addr;

        DEBUG_LOG("Copy Desc to protected body :");
        ODB_DESC_log(desc_in_body_p);

        #if ADAPTIVE_MEMORY_METHOD
        // if we received all the head and tail, download
        // data if necessary to complete local head and tail
            if(info->payload.head_size > info->desc.d_desc.head_size || info->payload.tail_size > info->desc.d_desc.tail_size){
                // use to query head/tail data to the remote server
                ODB_Query_Desc         query;
                // nb of bytes downloaded to complete local head and/or tail
                size_t            downloaded_bytes= 0;
                INIT_ODB_Query( query,ODB_MSG_GET_UNALIGNED_DATA,
                                info->desc.d_desc.fd,
                                info->desc.d_desc.head_size, 
                                new_head_size + new_body_size,
                                info->desc.d_desc.tail_size);
                DEBUG_LOG("Getting more data...");
                ODB_Query_log(&query);
                ODB_get_remote_data(&query,&info->desc.source_addr,&info->payload,0,&downloaded_bytes);
                DEBUG_LOG("ADAPTIVE_MEMORY_METHOD : Got  %zu / %zu tail bytes from RAB",downloaded_bytes,info->desc.d_desc.tail_size);
            }
        #endif

        // if body, not protected -> should be protected after receiving data, 
        // try to add mprotection
        DEBUG_LOG("ODB : adding mprotect to the body of the payload...");
        // on failure, download the real data
        if( ODB_SUCCESS != add_ODB_Protected_Memory(&intern_PMT,info->payload.buffer,buf_size,desc_in_body_p)){
            ERROR_LOG("mprotect error -> call get_remote_payload !!");
            info->progress = ODB_RECEIVING_HEAD;
            return recv_virtual_to_real(socket,bytes_read,flags,info);
        }

        // trick to tell that we have read the body
        info->bytes_read_write = unaligned_size + info->desc.d_desc.body_size;
        *bytes_read           += info->desc.d_desc.body_size;
    }

    DEBUG_LOG("ODB : virtual recv %zu bytes over %zu total",info->bytes_read_write,payload_size);

    return ODB_SUCCESS;
}

static ODB_ERROR recv_payload(int socket, void *buffer, size_t *length, int flags,ConnectionInfo *info){
    if( buffer == NULL || length == NULL || *length == 0 || info == NULL ) return ODB_NULL_PTR;

    DEBUG_LOG("ODB : Receiving payload... \n");
    ODB_DESC_log(&info->desc);
    const size_t unaligned_size = info->desc.d_desc.head_size + info->desc.d_desc.tail_size;
    const size_t payload_size   = unaligned_size +  info->desc.d_desc.body_size;
    ODB_ERROR    err            = ODB_SUCCESS;

    //init payload buffer if no bytes read yet or buffer changed (i.e *buffer out of payload bound)
    if(  info->bytes_read_write == 0 || 
       ( info->payload.buffer != NULL && 
        ( buffer < info->payload.buffer || (void*) ((uint8_t*)info->payload.tail + info->payload.tail_size) < buffer )
       )
    )
    {
        //DEBUG_LOG("ODB Payload Buffer: init size to choose among %zu and %zu",buff_size,payload_size);
        INIT_ODB_Local_Buffer((&info->payload),buffer,MIN(*length, payload_size));
        DEBUG_LOG("ODB Payload Buffer: head %zu / body %zu / tail %zu || Payload_size %zu",info->payload.head_size,info->payload.body_size,info->payload.tail_size,payload_size);
    }

    // if we are receiving payload normally
    if(ODB_PAYLOAD_IN_PROGRESS == info->progress ){
        const size_t buff_size = info->payload.head_size + info->payload.body_size + info->payload.tail_size;
        
        // if receiving real data
        if( info->odb_header.type == ODB_MSG_SEND_REAL){
            err = recv_real_payload(socket,length,flags,info);
        }
        //  if buffer size is not large enough or can't protect desc for virtual receiving
        // i.e no full page mprotectable in the buffer
        else if ( info->payload.body_size < (size_t) PAGE_SIZE || buff_size < payload_size ){
            DEBUG_LOG("Local Buffer is too small (%zu / %zu) for the virtual data, downloading remote payload...\n",buff_size,payload_size);
            // in this case we expect virtual data but we don't have enough buffer to store it
            // so we will receive the header, download the body from remote, and then receive the tail
            // set state to header receiving
            info->progress = ODB_RECEIVING_HEAD;
            // call recv_virtual_to_real
            err = recv_virtual_to_real(socket,length,flags,info);
        }
        // else we can receive virtual data normally 
        else{
            err = recv_virtual_payload(socket,length,flags,info);
        }
    }

    else{
        err = recv_virtual_to_real(socket,length,flags,info);
    }

    if(ODB_SUCCESS != err) return err;


    // if we've read all data
    if( payload_size <= info->bytes_read_write ){
        DEBUG_LOG("ODB : all bytes received !");
        info->progress          = ODB_NONE;
        info->bytes_read_write  = 0;
        //ODB_Local_Buffer_log(&info->payload);
        return ODB_SUCCESS;
    }

    return ODB_INCOMPLETE;
}

//err = recv_file(socket,buffer,&length,flags,&entry->info);
static ODB_ERROR recv_file(void *buffer, size_t *bytes_read, ConnectionInfo *info){
    if(bytes_read == NULL || info == NULL ) return ODB_NULL_PTR;
    
    ODB_Query_Desc query;
    *bytes_read = 0;
    INIT_ODB_Query(query,ODB_MSG_GET_FILE,info->desc.d_desc.fd,info->bytes_read_write,0, 0);
            
    ODB_ERROR err = ODB_get_remote_data(&query,&info->desc.source_addr,buffer,0,bytes_read);

    if( ODB_SUCCESS != err) return err;

    // should have finished downloading
    if (bytes_read == 0){
        DEBUG_LOG("ODB : all bytes received !");
        info->progress          = ODB_NONE;
        info->bytes_read_write  = 0;
    }
    else{
        DEBUG_LOG("ODB : %zu bytes received !",*bytes_read);
        //info->bytes_read_write += *bytes_read;
    }

    return ODB_SUCCESS;
}

ssize_t recv(int socket, void *buffer, size_t length, int flags) {
    DEBUG_LOG("ODB recv(socket=%d, buffer=%p, length=%zu, flags=%d)", socket, buffer, length, flags);
    #if !ODB
        ssize_t no_odb_ret = original_recv(socket,buffer,length,flags);
        DEBUG_LOG("recv(socket=%d, buffer=%p, length=%zu, flags=%d) = %zd bytes",socket,buffer,length,flags,no_odb_ret);
        if(no_odb_ret > 0){Buffer_log(buffer, (size_t) no_odb_ret);}
        return no_odb_ret;
    #endif

    // called to recv are re-entrant for a given socket.
    // Its state is saved and data are copied in the buffer.
    if( buffer == NULL || length == 0){
        errno = ENOMEM;
        ERROR_LOG("recv : buffer == NULL || length == 0");
        return -1;
    }

    // it's not a TCP socket
    if (is_socket(socket) <= 0){
        DEBUG_LOG("recv : %d not a socket",socket);
        ssize_t o_ret = original_recv(socket,buffer,length,flags);
        if(o_ret >0){
            DEBUG_LOG("Received : "); Buffer_log(buffer, (size_t) o_ret);
        }
        return o_ret;
    }

    #if DEBUG
        static uint64_t frame_count     = 0;
        static uint64_t tot_bytes_recv  = 0;
        DEBUG_LOG("[READ FRAME %lu on socket %d] // bytes received so far : %zu",frame_count,socket,tot_bytes_recv);
    #endif

    ODB_ERROR err = ODB_SUCCESS;
    ssize_t   ret = 0;

    // Check whether there is an entry associated with this socket.
    // If no connection is found, create a new one and set headerInprogress to 1
    ConnectionTable *entry    = get_connection(&down_connections, socket),
                    *up_entry = get_connection(&up_connections, socket);
    
    // if we didn't get or create connection
    if (entry == NULL || up_entry == NULL){
        ERROR_LOG("recv : get_connection no connection found or created");
        errno = ENOMEM;
        return -1;
    }

    // if it's not an ODB_Connection and we have not enough queried bytes to try to read header
    // we'll abort ODB read
    // && entry->info.bytes_read_write + length < ODB_HEADER_SIZE
    if(entry->info.is_ODB == 0 && entry->info.progress == ODB_NONE){
        DEBUG_LOG("%d not an ODB connection, original_recv",socket);
        ssize_t ret = original_recv(socket, buffer, length, flags);
        if(ret>0){
            DEBUG_LOG("Received : "); Buffer_log(buffer,(size_t) ret);
        }
        return ret;
    }

    // update progress state if needed (i.e if ODB_NONE state is set)
    entry->info.bytes_read_write = entry->info.progress == ODB_NONE ? 0 : entry->info.bytes_read_write;
    entry->info.progress         = entry->info.progress == ODB_NONE ? ODB_HEADER_IN_PROGRESS : entry->info.progress;
    
    switch(entry->info.progress){
        // if we tried to parsed header but failed, 
        // restore data from cache to the buffer
        case ODB_RESTORE_FROM_HEADER: 
        case ODB_RESTORE_FROM_DESC: 
        case ODB_RESTORE_FROM_HEADER_AND_DESC:
            size_t read = 0;
            restore_from_cache(&entry->info,buffer,length,&read);
            read = MIN(length,read);
            ret = original_recv(socket,((uint8_t*)buffer + read),length-read,flags);
            ret = ret == -1 ? read : read + (size_t)ret;
        break;
        case ODB_RECEIVING_HEAD:
        case ODB_RECEIVING_TAIL:
        case ODB_DOWNLOAD_PAYLOAD:
            // if we were getting data from a remote payload, 
            // do not read, download data until all real data have been downloaded
            DEBUG_LOG("ODB read: get remote payload (state ODB_DOWNLOAD_PAYLOAD) !!");
            INIT_ODB_Local_Buffer(&entry->info.payload, buffer, length);
            err = recv_virtual_to_real(socket,&length,flags,&entry->info);
            if(ODB_SUCCESS == err || ODB_INCOMPLETE == err){
                ret = length;
                DEBUG_LOG("ODB read: get remote payload of max size %zu !!",length);
            }
            else{
                DEBUG_LOG("ODB read: get remote payload failed !!");
                entry->info.progress = ODB_NONE;
                ret = -1;
            }
        break;
        case ODB_RECEIVING_FILE:
            err = recv_file(buffer,&length,&entry->info);
            if(ODB_SUCCESS == err || ODB_INCOMPLETE == err){
                ret = length;
                // if we were getting data from a remote file and all data have been downloaded
                // read normally
                if(ret == 0)return recv(socket,buffer,length,flags);
                DEBUG_LOG("ODB read: get remote file of max size %zu !!",length);
            }
            else{
                DEBUG_LOG("ODB read: get remote file failed !!");
                entry->info.progress = ODB_NONE;
                ret = -1;
            }
        break;
        case ODB_HEADER_IN_PROGRESS:
        __attribute__((fallthrough));
            /* fall through */
        case ODB_DESC_IN_PROGRESS:
            size_t rec_bytes = 0; 
            err = recv_ODB_Header_and_Desc(socket,buffer,length,&rec_bytes,flags,&entry->info);
            if(err == ODB_SUCCESS){
                up_entry->info.is_ODB = 1;
                entry->info.is_ODB = 1;
                //DEBUG_LOG("ODB_DESC_IN_PROGRESS : %d socket up & down set to ODB",socket);
            }
            else if(err == ODB_INCOMPLETE){
                ERROR_LOG("Incomplete header/ desc reception");
                errno = EAGAIN;
                ret = -1;
                break;
            }
            else if(err == ODB_PARSE_ERROR){
                rec_bytes = MIN(rec_bytes,length);
                DEBUG_LOG("ODB parsing header/desc failed, restored from cache %zu bytes, try to received : %zu bytes",rec_bytes,length-rec_bytes);
                ret = original_recv(socket,((uint8_t*)buffer + rec_bytes),length-rec_bytes,flags);
                ret = ret < 0 ? rec_bytes : rec_bytes + (size_t)ret;
                if(ret>=0){DEBUG_LOG("Received %zd bytes on socket %d", ret, socket);}
                break;
            }
            // should never happen
            else{
                ret = -1;
                break;
            }
         __attribute__((fallthrough));
            /* fall through */
        case ODB_PAYLOAD_IN_PROGRESS:
            DEBUG_LOG("ODB : Parsing payload ...");
            up_entry->info.is_ODB = 1;
            err = recv_payload(socket,buffer,&length,flags,&entry->info);
            if(err == ODB_SUCCESS || err == ODB_INCOMPLETE) ret += length;
            else ret = -1; 
        break;
        default: 
            ERROR_LOG("ODB read: unknown state %d !!",entry->info.progress);
            ret = -1;
        break;
    }

    ODB_State_log(entry->info.progress);
    DEBUG_LOG("recv(socket=%d, buffer=%p, length=%zu, flags=%d) = %zd bytes",socket,buffer,length,flags,ret);
    #if DEBUG
        if(entry->info.progress == ODB_NONE){
            frame_count++;
        }
        if (ret > 0)
            tot_bytes_recv += (size_t) ret;
    #endif

    return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen){
    (void) src_addr;
    (void) addrlen;
    //ODB_init();
    #if !ODB
        if(is_socket(sockfd) <= 0){
            DEBUG_LOG("recvfrom(socket=%d, buf=%p, len=%zu, flags=%d)",sockfd,buf,len,flags);
        }
        return original_recvfrom(sockfd,buf,len,flags,src_addr,addrlen);
    #endif
    DEBUG_LOG("Recvfrom called");
    return recv(sockfd,buf,len,flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
    ssize_t ret = 0;
    DEBUG_LOG("recvmsg(socket=%d, msg=%p, flags=%d)",sockfd,msg,flags);
    #if !ODB
        ret = original_recvmsg(sockfd,msg,flags);
        
    #else
        if(msg ==NULL){
            ret = original_recvmsg(sockfd,msg,flags);
        }
        else{
            // read all iov until error or end
            ssize_t tot_len = 0;
            for(size_t i = 0; i < msg->msg_iovlen && ret >= 0; i++){
                tot_len += msg->msg_iov[i].iov_len;
                ssize_t local_ret = recv(sockfd,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len,flags);
                // in case of error
                if(local_ret < 0){
                    ERROR_LOG("recv(%d, %p, %zu, %d)",sockfd,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len,flags);
                    if (ret == 0) ret = -1;
                    break;
                }
                ret += local_ret;
                // stop if we didn't fullfil the iov
                if((size_t)local_ret < msg->msg_iov[i].iov_len) break;
            }
            DEBUG_LOG("recvmsg(socket=%d, msg=%p, flags=%d) = %zd / %zu bytes",sockfd,msg,flags,ret,tot_len);
        }
    #endif

    if(ret>0){IOV_log(msg->msg_iov,msg->msg_iovlen);}
    
    return ret;
}

// ************************************
// *                                  *
// *           Read section           *
// *                                  *
// ************************************

ssize_t read(int fd, void *buf, size_t count){
    #if !ODB
        if(is_socket(fd) <= 0){
            DEBUG_LOG("read on file(fd=%d, buf=%p, count=%zu)",fd,buf,count);
        }
        else{
            DEBUG_LOG("read on socket(fd=%d, buf=%p, count=%zu)",fd,buf,count);
        }
        ssize_t ret = original_read(fd,buf,count);
        if(ret > 0){ Buffer_log(buf,ret);}
        return ret;
    #endif
    if(is_socket(fd) <= 0) return original_read(fd,buf,count);
    else return recv(fd,buf,count,0);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt){
    ssize_t ret = 0;
    DEBUG_LOG("readv(fd=%d, iov=%p, iovcnt=%d)",fd,iov,iovcnt);
    #if !ODB
        ret = original_readv(fd,iov,iovcnt);
    #else
        if(is_socket(fd) <= 0) ret = original_readv(fd,iov,iovcnt);
        else{
            // apply read to all iov until error, partial read or end
            for(int i = 0; i < iovcnt && ret >= 0; i++){
                ssize_t local_ret = read(fd,iov[i].iov_base,iov[i].iov_len);
                if(local_ret < 0){
                    ERROR_LOG("read(%d,%p,%zu)",fd,iov[i].iov_base,iov[i].iov_len);
                    if (local_ret == 0) ret = -1;
                    break;
                }
                DEBUG_LOG("read(%d,%p,%zu) = %zd bytes",fd,iov[i].iov_base,iov[i].iov_len,ret);
                Buffer_log(iov[i].iov_base,ret);
                ret += local_ret;
                // stop if we didn't fullfil the iov
                if((size_t) local_ret < iov[i].iov_len) break;
            }
        }
    #endif

    if( ret > 0){IOV_log(iov,iovcnt);}
    DEBUG_LOG("readv(socket=%d, iov=%p, iovcnt=%d) = %zd bytes",fd,iov,iovcnt,ret);
    
    return ret;
}

// ************************************
// *                                  *
// *          Sendfile section        *
// *                                  *
// ************************************

// if connection is an ODB connection, send data as it is, else call recv/writev to send data 

static ODB_ERROR store_sendfile_fd(ConnectionInfo *info, int in_fd){
    if(info == NULL) return ODB_NULL_PTR;
    ODB_ERROR err = create_ODB_Server_if_not_exist(&info->desc.source_addr,&ODB_conf);
    if(ODB_SUCCESS != err){
        remove_ODB_Remote_Buffer(&intern_RAB, in_fd);
        return err;
    }
    DEBUG_LOG("ODB server thread created ! \n");

    // create fd for RAB
    err = create_ODB_Remote_sendfile(&intern_RAB, in_fd, &info->desc.d_desc.fd);
    if(ODB_SUCCESS != err ){
        DEBUG_LOG("create_ODB_Remote_Buffer NOT created ! \n");
        return err;
    }
    DEBUG_LOG("create_ODB_Remote_Buffer created with id : %zu ! \n", info->desc.d_desc.fd);

    return ODB_SUCCESS;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count){
    //ODB_init();
    #if !ODB
        DEBUG_LOG("sendfile(out_fd=%d, in_fd=%d, offset=%p, count=%zu)",out_fd,in_fd,offset,count);
        return original_sendfile(out_fd,in_fd,offset,count);
    #endif

    // Note : if in_fd is a socket, should return -1 with errno = EINVAL
    ConnectionTable *out_entry      = NULL;
    uint8_t         is_out_ODB      = 1;

    DEBUG_LOG("using sendfile out_fd=%d, in_fd=%d, offset=%p, count=%zu",out_fd,in_fd,offset,count);
     
    // Determine if out_fd is an ODB socket
    if ( is_socket(out_fd) <= 0 ){
        is_out_ODB = 0;
        DEBUG_LOG("out_fd is a file");
    }
    else {
        out_entry = get_connection(&up_connections, out_fd);
        #if DEBUG
            if(out_entry == NULL)DEBUG_LOG("out entry is NULL !!");
        #endif
        if (out_entry == NULL || 0 == out_entry->info.is_ODB) is_out_ODB = 0;
    }

    // Determine if in_fd is a socket, if so -> error
    if ( is_socket(in_fd) > 0 ){
        errno = EINVAL;
        return -1;
    }

    // if out_fd is not an ODB Socket
    if( is_out_ODB == 0){
        DEBUG_LOG("out_fd (%d) is not an ODB Socket -> call original sendfile",out_fd);
       return original_sendfile(out_fd, in_fd, offset, count);
    }

    // otherwise, if out_fd is an ODB Socket
    else if( is_out_ODB > 0){
        DEBUG_LOG("out_fd is an ODB Socket -> store in ODB Server");
        if( ODB_SUCCESS != store_sendfile_fd(&out_entry->info, in_fd) ) return -1;
        if(NULL != offset) *offset += count;

        // send virtual header and desc
        ODB_Header  header;
        ODB_Desc    desc;
        struct iovec iov[2];
        iov[0].iov_base = &header;
        iov[0].iov_len  = ODB_HEADER_SIZE;
        iov[1].iov_base = &desc;
        iov[1].iov_len  = ODB_DESC_SIZE;
        INIT_ODB_Header(&header,ODB_MSG_SEND_VIRTUAL,0);
        INIT_ODB_Desc(desc,out_entry->info.desc.d_desc.fd,0,0,0,out_entry->info.desc.source_addr);
        compute_ODB_crc(&header,&desc);
        serialize_odb_desc_inplace(&desc);
        ssize_t ret = original_writev(out_fd,iov,2);
        if(ret < 0){
            errno = EIO;
            return -1;
        }

        return count;
    }

    errno = EIO;
    return -1;
}

/***********************************
*                                  *
*          Splice section          *
*                                  *
***********************************/

ssize_t splice(int fd_in, loff_t *off_in, int fd_out,loff_t *off_out, size_t len, unsigned int flags){
    DEBUG_LOG("splice :  fd_in=%d, off_in=%p, fd_out=%d, off_out=%p, len=%zu, flags=%u",fd_in,off_in,fd_out,off_out,len,flags);
    return original_splice(fd_in,off_in,fd_out,off_out,len,flags);
}
