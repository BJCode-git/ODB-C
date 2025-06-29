#include <ODB/odb.h>
#include <ODB/odb-utils.h>
#include <ODB/odb-config-parser.h>
#include <ODB/odb-remote.h>
#include <dlfcn.h>
#include <sys/select.h>

ssize_t strict_writev(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t total_sent = 0;
    int i = 0;
    size_t offset = 0;

    while (i < iovcnt) {
        // Attente si nécessaire
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        if (select(fd + 1, NULL, &wfds, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        // Création d’un iov temporaire sans copie
        struct iovec tmp[iovcnt - i];
        for (int j = i, k = 0; j < iovcnt; ++j, ++k) {
            tmp[k].iov_base = (j == i) ? (char*)iov[j].iov_base + offset : iov[j].iov_base;
            tmp[k].iov_len = (j == i) ? iov[j].iov_len - offset : iov[j].iov_len;
        }

        ssize_t n = original_writev(fd, tmp, iovcnt - i);
        if (n < 0) {
            //if (errno == EINTR) continue;
            //if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return total_sent == 0 ? (ssize_t) -1 : (ssize_t) total_sent;
        }

        total_sent += n;

        // Mise à jour de l’état
        ssize_t remaining = n;
        while (i < iovcnt && remaining >= (ssize_t)(iov[i].iov_len - offset)) {
            remaining -= (iov[i].iov_len - offset);
            i++;
            offset = 0;
        }
        offset += remaining;
    }

    return total_sent;
}

ssize_t strict_sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t total_sent = 0;
    int i = 0;
    size_t offset = 0;

    while (i < (int)msg->msg_iovlen) {
        // Attente si nécessaire
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        if (select(fd + 1, NULL, &wfds, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        struct msghdr tmp = *msg;
        tmp.msg_iov = (struct iovec *)&msg->msg_iov[i];
        tmp.msg_iovlen = msg->msg_iovlen - i;

        // On ne modifie pas les buffers originaux
        struct iovec first = tmp.msg_iov[0];
        first.iov_base = (char *)first.iov_base + offset;
        first.iov_len -= offset;

        tmp.msg_iov[0] = first;

        ssize_t n = original_sendmsg(fd, &tmp, flags);
        if (n < 0) {
            //if (errno == EINTR) continue;
            //if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return total_sent == 0 ? (ssize_t) -1 : (ssize_t)total_sent;
        }

        total_sent += n;

        // Mise à jour de l’état
        ssize_t remaining = n;
        while (i < (int)msg->msg_iovlen && remaining >= (ssize_t)(msg->msg_iov[i].iov_len - offset)) {
            remaining -= (msg->msg_iov[i].iov_len - offset);
            i++;
            offset = 0;
        }
        offset += remaining;
    }

    return total_sent;
}

ssize_t strict_send(int fd,const void *buf, size_t count, int flags){
    //init_original_functions();
    //ODB_init();
    size_t written = 0;
    while(written < count){
        ssize_t ret = original_send(fd, (const char *)buf + written, count - written,flags);
        if (ret < 0){
            //if( errno == EAGAIN || errno == EWOULDBLOCK ) continue;
            ERROR_LOG("send(%d,%p,%zu,%d)",fd,buf,count,flags);
            if(errno == EINTR ) continue;
            return written == 0 ? (ssize_t) -1 : (ssize_t)written;
        }
        if(ret == 0){
            ERROR_LOG("written less than expected");
            return (ssize_t) written;
        }
        written += (size_t)ret;
    }
    return (ssize_t) written;
}

ssize_t strict_recv(int fd, void *buf, size_t count,int flags){
    //init_original_functions();
    //ODB_init();
    (void) flags;
    ssize_t readed = 0;
    while((size_t) readed < count){
        ssize_t ret = original_recv(fd, (char *)buf + readed, count - readed, flags);
        if (ret < 0 ){
            if( errno == EINTR ) continue;
            ERROR_LOG("recv(%d,%p,%zu,%d)", fd,buf,count,flags);
            return readed == 0 ? -1 : readed;
        }
        //end of stream
        else if(ret == 0){
            ERROR_LOG("original_recv(%d,%p,%zu,%d) -> %zu / %zu bytes readed", fd,buf,count,flags,(size_t)readed,count);
            return readed;
        }
        else readed += ret;
    }
    return readed;
}


// ************************************
// *                                  *
// *   ODB signal handler functions   *
// *                                  *
// ************************************

void sighandler(int signo, siginfo_t *info, void *context){

    //DEBUG_LOG("Received signal %d", signo);

    if( signo != SIGSEGV) return;
    (void) context;

    //printf("Received SIGSEGV signal for address %p\n", info->si_addr);

    uintptr_t addrToUnprotect = (uintptr_t) info->si_addr & ~(PAGE_SIZE - 1);
    DEBUG_LOG("Entering Handler with addr %p",(void*) addrToUnprotect);

    ODB_ProtectedMemoryTable *entry = find_ODB_Protected_Memory(&intern_PMT, (const void*)addrToUnprotect, 1);
    ODB_Query_Desc   query;
    ODB_Desc         virtual_desc;
    ODB_Local_Buffer buffer;

    // Test if this is an ODB Related page fault, remove from PMT
    if(entry != NULL){
        DEBUG_LOG("ODB Related Pagefault");
        void  *fault_addr = entry->addr;
        size_t fault_size = entry->size;

        // remove from ProtectedMemoryTable and remove protection
        remove_ODB_Protected_Memory(&intern_PMT, entry,&virtual_desc);

        INIT_ODB_Local_Buffer((&buffer),fault_addr,fault_size);
        DEBUG_LOG("Local buffer which create interrupt :");
        ODB_Local_Buffer_log(&buffer);

        // if body_size and tail_size are 0 then it is a sendfile desc
        if(virtual_desc.d_desc.body_size == 0 && virtual_desc.d_desc.tail_size == 0){
            ConnectionTable *down_entry = get_connection(&down_connections,virtual_desc.d_desc.head_size);
            if(down_entry == NULL){
                DEBUG_LOG("Failed to get connection in down connections");
            }
            else{
                // set the connection state as receiving a file
                down_entry->info.progress = ODB_RECEIVING_FILE;
                down_entry->info.bytes_read_write = fault_size;
            }
            INIT_ODB_Query(query,ODB_MSG_GET_FILE,virtual_desc.d_desc.fd,0,fault_size,0);
        }
        else{
            //compute how many header data is in the body 
            INIT_ODB_Query(query,ODB_MSG_GET_BODY,virtual_desc.d_desc.fd,virtual_desc.d_desc.head_size,MIN(buffer.body_size,virtual_desc.d_desc.body_size),0);
        }

        DEBUG_LOG("Fault -> get_remote data");
        ODB_get_remote_data(&query,&virtual_desc.source_addr, &buffer,0,NULL);
    }
    else{
        DEBUG_LOG("Not ODB Related Pagefault, error : %s",strerror(errno));
        fprintf(stderr,"Error with addr %p", info->si_addr);
         #if DEBUG
            ucontext_t  *ctx         = (ucontext_t *)context;
            void        *faulting_ip = NULL;

            // L'adresse de l'instruction qui a causé le SIGSEGV
            if(ctx != NULL){
            #if defined(__x86_64__)
                faulting_ip = (void *)ctx->uc_mcontext.gregs[REG_RIP];
            #elif defined(__i386__)
                faulting_ip = (void *)ctx->uc_mcontext.gregs[REG_EIP];
            #elif defined(__aarch64__)
                faulting_ip = (void *)ctx->uc_mcontext.pc;
            #else
                #error Unsupported architecture
            #endif
            }
            if(faulting_ip !=NULL){
                Dl_info dlinfo;
                int found = dladdr(faulting_ip, &dlinfo);
                const char* str_info = found ? dlinfo.dli_sname : "unknown";
                void* addr = found ? dlinfo.dli_saddr : faulting_ip;
                DEBUG_LOG("Faulting function: %s (%p)\n", str_info, addr);
                fprintf(stderr,"Faulting function: %s (%p)\n", str_info, addr);
            }
        #endif
        
        perror("core dump");
        exit(EXIT_FAILURE);
    }

    DEBUG_LOG("Leaving Handler");
}

void install_handler(void){

    struct sigaction sa;
    bzero(&sa, sizeof(sa));
    sa.sa_sigaction = &sighandler;
    sa.sa_flags     = SA_SIGINFO;
    // Bloque SIGSEGV pendant qu'on exécute le handler
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSEGV);
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        DEBUG_LOG("Unable to install hanler for SIGSEGV !");
        exit(EXIT_FAILURE);
    }
    DEBUG_LOG("Handler installed !");
}


// ************************************
// *                                  *
// *    ODB Remote Buffer Services    *
// *                                  *
// ************************************

uint8_t                ODB_server_created    = 0;
static pthread_mutex_t ODB_serv_mutex        = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ODB_serv_creation_mtx = PTHREAD_MUTEX_INITIALIZER;

int is_ODB_server_created(void){
    int ret =0;
    pthread_mutex_lock(&ODB_serv_mutex);
        ret = ODB_server_created > 0 ? 1 : 0;
    pthread_mutex_unlock(&ODB_serv_mutex);
    return ret;
}

void reset_ODB_server(void){
    pthread_mutex_lock(&ODB_serv_mutex);
        ODB_server_created = 0;
    pthread_mutex_unlock(&ODB_serv_mutex);
}

ODB_ERROR receive_request(int fd,ODB_Query_Desc *query) {
    if(query == NULL) return ODB_NULL_PTR;
    DEBUG_LOG("ODB server : receiving request ...");

    if(strict_recv(fd, query, ODB_QUERY_DESC_SIZE,0) < 0 )
        return ODB_SOCKET_READ_ERROR;

    DEBUG_LOG("ODB server : Request received ...");

    deserialize_odb_query_desc_inplace(query);
    return ODB_SUCCESS;
}

ODB_ERROR answer_client(int fd, ODB_Query_Desc *query) {
    if(query == NULL) return ODB_NULL_PTR;

    //printf("BE thread server : Answering client\n");
    DEBUG_LOG("answering client...");
    struct iovec        answer[2]= {{NULL,0},{NULL,0}};
    ODB_Local_Buffer*   odb_buffer    = NULL;
    uint8_t             remove_buffer = 0;

    // get the odb buffer associated to the fd in query
    if(ODB_MSG_GET_FILE == query->type){
        size_t in_fd = 0;
        off_t offset = query->d_desc.head_size;
        if(ODB_SUCCESS != find_ODB_Remote_sendfile(&intern_RAB, query->d_desc.fd, &in_fd)){
            return ODB_UNKNOWN_ERROR;
        }
        // 0x7ffff000 is the max size transferrable by sendfile
        if(ODB_SUCCESS != original_sendfile(fd, in_fd, &offset, 0x7ffff000)){
            return ODB_SOCKET_WRITE_ERROR;
        }
        original_close(in_fd);
        return ODB_SUCCESS;
    }
    //printf("BE thread server : Searching RAB %zu\n", query->d_desc.fd);
    odb_buffer = find_ODB_Remote_Buffer(&intern_RAB, query->d_desc.fd);
    if( odb_buffer == NULL ){
        DEBUG_LOG("BE thread server : RAB %zu not found !", query->d_desc.fd);
        //printf("BE thread server : RAB %zu not found !", query->d_desc.fd);
        return ODB_UNKNOWN_ERROR;
    }
    //printf("BE thread server : Found RAB %p\n", odb_buffer);

    size_t payload_size = odb_buffer->head_size + odb_buffer->body_size + odb_buffer->tail_size;
    uint8_t *original_start = ((uint8_t*)odb_buffer->buffer),
            *original_end   = ((uint8_t*)odb_buffer->buffer) + payload_size;

    //printf("BE thread server : Computing payload to send %zu\n", payload_size);
    switch(query->type){
        case ODB_MSG_GET_PAYLOAD :
            // send real data, will send missing datd
            // * head_size, tail size > 0 will be used as
            // a top/bottom offset to know where to start/end
            // *body size > 0 will be use to know max data to send
            // we'll use head_size OR tail_size to know where to start/end
            DEBUG_LOG("[REMOTE SEND] Payload data from fd %zu", query->d_desc.fd);
            DEBUG_LOG("ODB server local buffer :");
            ODB_Local_Buffer_log(odb_buffer);
            ptrdiff_t diff         = 0;
            uint8_t*  start        = original_start  + (MIN(query->d_desc.head_size,payload_size));
            uint8_t*  end          = original_end    - (MIN(query->d_desc.tail_size,payload_size));

            diff = end >= start ? end - start : 0;
    
            // set the body frame
            answer[0].iov_base = start;
            answer[0].iov_len  = MIN((size_t) diff,query->d_desc.body_size);
            DEBUG_LOG("SEND_REAL_PAYLOAD : %zu bytes from %p to %p", answer[0].iov_len, start, end);

            if( (start + answer[0].iov_len) >= original_end) remove_buffer = 1;
        break;
        
        case ODB_MSG_GET_BODY :
            DEBUG_LOG("[REMOTE SEND] Body data from fd %zu", query->d_desc.fd);
            // set the body frame
            size_t offset = MIN(query->d_desc.head_size,payload_size);
            answer[0].iov_base  =(void*) ((uint8_t*) odb_buffer->buffer + offset);
            answer[0].iov_len   = MIN(payload_size-offset,query->d_desc.body_size);
            DEBUG_LOG("SEND_BODY : len = %zu",answer[0].iov_len);
            DEBUG_LOG("Sending :  %s\n",(char*) answer[0].iov_base);
            remove_buffer = 1;
        break;

        // if request for unaligned data
        case ODB_MSG_GET_UNALIGNED_DATA:
            // query request format : {hi, h(i+1) + b(i+1) ; ti}
            // we assume we have :
            // For each i, P = h(i) + b(i) + t(i) = h(0) + b(0) + t(0), 
            // where P, h(0), b(0), t(0) are the original payload, header,body and tail sizes.
            // Plus, for each i, bi = b(i+1) + (h(i+1) - hi) + (t(i+1) - ti)
            // So for each i, h(i) <= h(i+1), t(i) <= t(i+1), b(i) >= b(i+1)

            // There, we know {hi, h(i+1) + b(i+1) = d ; ti}
            // we can obtain :
            // (1) bi = P-hi-ti
            // (2) t(i+1) = P-h(i+1)-b(i+1) = P - d
            // (3) h(i+1) = (d + hi + (t(i+1) - ti) -bi) / 2
            // receive the last bound :
            size_t hi = query->d_desc.head_size;
            size_t d  = query->d_desc.body_size;
            size_t ti = query->d_desc.tail_size;
            
            size_t bi     = payload_size - hi - ti;
            size_t t_next = payload_size - d;
            size_t h_next = (d - (hi - (t_next - ti)));

             DEBUG_LOG("Computed : \n"
                      "b(i) : %zu \n"
                      "h(i+1) + b(i+1) : %zu \n"
                      "head : [ %zu ; %zu ] , head_len = %zu \n"
                      "tail : [ %zu ; %zu ] , tail_len = %zu",
                      bi,d,
                      hi,h_next,(size_t) (h_next - hi),
                      ti,t_next,(size_t) (t_next - ti));

            //security check
            hi = MIN(hi,payload_size);
            d  = MIN(d,payload_size);
            ti = MIN(ti,payload_size);
            bi = MIN(bi,payload_size);
            t_next = MIN(t_next,payload_size);


            // set head data iovec
            answer[0].iov_base =(void*) ((uint8_t*) odb_buffer->buffer + hi);
            answer[0].iov_len  = h_next > hi ? h_next - hi : 0;
            answer[0].iov_len  = MIN(payload_size - hi,answer[0].iov_len);
            
            // set tail data iovec
            answer[1].iov_base = (void*) ((uint8_t*) odb_buffer->buffer + (payload_size - t_next));
            answer[1].iov_len  = t_next > ti ? t_next - ti : 0;
            answer[1].iov_len  = MIN(payload_size - t_next,answer[1].iov_len);

            DEBUG_LOG("RAB %zu :", query->d_desc.fd);
            ODB_Local_Buffer_log(odb_buffer);

            DEBUG_LOG("[SEND_UNALIGNED_DATA] :\n"
                      "Head : %zu bytes from %p \n"
                      "Tail : %zu bytes from %p ", 
                      answer[0].iov_len, answer[0].iov_base, 
                      answer[1].iov_len, answer[1].iov_base);
        break;

        default:
            return ODB_INVALID_REQUEST;
    }

    DEBUG_LOG("Answering back ODB Data ...");
    ssize_t sent_bytes = original_writev(fd, answer, 2);
    //strict_send(fd, answer.iov_base, answer.iov_len,0);
    if( sent_bytes < 0){
        ERROR_LOG("send answer");
        return ODB_SOCKET_WRITE_ERROR;
    }
    else if((size_t) sent_bytes < answer[0].iov_len + answer[1].iov_len){
        ERROR_LOG("%zb bytes sent instead of %zu", sent_bytes, answer[0].iov_len + answer[1].iov_len);
    }
    DEBUG_LOG("Answer back sent !");
    
    if (remove_buffer > 0){
        DEBUG_LOG("Removing buffer %zu ...",query->d_desc.fd);
        remove_ODB_Remote_Buffer(&intern_RAB, query->d_desc.fd);
    }

    return ODB_SUCCESS;
}

ODB_ERROR handle_client(void* argv) {
    if(argv == NULL){
        DEBUG_LOG("handle_client : NULL_ARGS");
        return ODB_NULL_PTR;
    }

    int fd = *(int*) argv;
    ODB_Query_Desc query;

    // receive request  and answer client if success
    if( ODB_SUCCESS != receive_request(fd, &query) || ODB_SUCCESS != answer_client(fd, &query)){
        DEBUG_LOG("handle_client : receive request error");
        original_close(fd);
        return ODB_UNKNOWN_ERROR;
    }

    original_close(fd);
    return ODB_SUCCESS;
}

void* handle_payload_requests(void* argv) {
    DEBUG_LOG("Initializing Server...\n");

    if(argv == NULL){
        DEBUG_LOG("handle_payload_requests : NULL_ARGS");
        pthread_exit(NULL);
    }

    Thread_args* args = (Thread_args *) argv;

    int server_fd = -1, client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        DEBUG_LOG("Could not create socket");
        pthread_cond_signal(&args->cond);
        pthread_exit(NULL);
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // tries to bind the server 3 times (with different ports)

    uint8_t binded = 0; 
    for (int i = 0; i < 3; i++) {
        if (bind(server_fd, (struct sockaddr *) &args->server_addr, sizeof((args->server_addr))) < 0){
           DEBUG_LOG("Bind fail on %s:%d, cause : %s",inet_ntoa(args->server_addr.sin_addr), htons(args->server_addr.sin_port), strerror(errno));
           args->server_addr.sin_port = htons(get_random_port());
           DEBUG_LOG("Trying to bind on %s:%d...",inet_ntoa(args->server_addr.sin_addr), htons(args->server_addr.sin_port));
        }
        else{
            binded = 1;
            break;
        }
    }

    if(!binded){
        DEBUG_LOG("Bind fail on %s:%d",inet_ntoa(args->server_addr.sin_addr), htons(args->server_addr.sin_port));
        pthread_cond_signal(&args->cond);
        goto clean_handle_payload_requests;
    }

    if (listen(server_fd, 10) < 0) {
        DEBUG_LOG("Listen fail");
        pthread_cond_signal(&args->cond);
        goto clean_handle_payload_requests;
    }

    // if we succeed until here, 
    // we consider the server created and unlock the mutex
    pthread_mutex_lock(&ODB_serv_mutex);
        ODB_server_created = 1;
    pthread_mutex_unlock(&ODB_serv_mutex);

    // tell the main thread that the server is created
    pthread_cond_signal(&args->cond);

    DEBUG_LOG("Payload Server Listening on : %s:%d",inet_ntoa(args->server_addr.sin_addr), htons(args->server_addr.sin_port));
    //printf("Payload Server Listening on : %s:%d\n",inet_ntoa(args->server_addr.sin_addr), htons(args->server_addr.sin_port));
    while (1) {
        //printf("BE thread server : Waiting for client...\n");
        client_fd = original_accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *)&addrlen);
        if (client_fd < 0) {
            DEBUG_LOG("handle_payload_requests : error accept");
            continue;
        }
        //printf("BE thread server : Client accepted !\n");
        DEBUG_LOG("BE thread server : Got client");
        handle_client(&client_fd);
    }

    clean_handle_payload_requests:
        DEBUG_LOG("ending...");
        original_close(server_fd);
        free(args);
        pthread_exit(NULL);
}

ODB_ERROR create_ODB_Server_if_not_exist(struct sockaddr_in *net_addr, ODB_Config *conf){
    pthread_t tID;
    ODB_ERROR err = ODB_SUCCESS;
    
    //implies that only one thread try to create the server at the same time
    pthread_mutex_lock(&ODB_serv_creation_mtx);
        if (is_ODB_server_created()) {
            // copy the adress of the server in the net_addr buff if not null
            //DEBUG_LOG("Copy addr of the server %s:%d",inet_ntoa(server_addr.sin_addr), htons(server_addr.sin_port));
            memcpy(net_addr,&conf->ODB_serv_addr , sizeof(conf->ODB_serv_addr));

            pthread_mutex_unlock(&ODB_serv_creation_mtx);
            return ODB_SUCCESS;
        }

        // if server not created, create it in a new thread
        Thread_args *args = malloc(sizeof(Thread_args));
        if(args == NULL){
            DEBUG_LOG("malloc fail");
            return ODB_MEMORY_ALLOCATION_ERROR;
        }

        //init cond
        pthread_cond_init(&args->cond, NULL);

        pthread_mutex_lock(&ODB_serv_mutex);

            // give the server address
            memcpy(&args->server_addr,&conf->ODB_serv_addr,sizeof(ODB_conf.ODB_serv_addr));
            // create the server thread
            if (pthread_create(&tID, NULL, handle_payload_requests, args) != 0) {
                DEBUG_LOG("Error creating payload request handler thread");
                return ODB_THREAD_CREATE;
            }

            // Wait for cond to be set
            pthread_cond_wait(&args->cond, &ODB_serv_mutex);
            
            if( ODB_server_created == 0){
                err = ODB_THREAD_CREATE;
            }   
            else{
                err = ODB_SUCCESS;
                memcpy(net_addr,&args->server_addr,sizeof(struct sockaddr_in));
                memcpy(&conf->ODB_serv_addr,&args->server_addr,sizeof(struct sockaddr_in));
            }
        
        pthread_mutex_unlock(&ODB_serv_mutex);

        pthread_cond_destroy(&args->cond);

    pthread_mutex_unlock(&ODB_serv_creation_mtx);

    DEBUG_LOG("end");

    return err;
}

// ************************************
// *                                  *
// *          ODB RAB access          *
// *                                  *
// ************************************

ODB_ERROR ODB_get_remote_data(ODB_Query_Desc *query,struct sockaddr_in *server_addr, const ODB_Local_Buffer *buffer, size_t local_buff_offset,size_t *tot_bytes_read){
    if(query == NULL || buffer == NULL || server_addr == NULL) return ODB_NULL_PTR;

    size_t local_bytes_read =0;
    if(tot_bytes_read !=NULL) *tot_bytes_read = 0;
    else                       tot_bytes_read = &local_bytes_read;

    const size_t payload_size = buffer->head_size + buffer->body_size + buffer->tail_size;
    int          sock          = -1;
    ssize_t      bytes_read    = 0;
    size_t       bytes_to_read = 0;
    ODB_MSG_Type msg_type      = query->type;

    // step :
        // 1. connect to server
        // 2. send request
        // 3. receive data (only data)

    // if we want to complete local head / tail 
    if(query->d_desc.head_size == 0 && query->d_desc.body_size == 0 && query->d_desc.tail_size == 0) 
        return ODB_SUCCESS;

    DEBUG_LOG("get remote data : \n");
    /* create connection with the remote server */
    // create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        ERROR_LOG("socket");
        return ODB_SOCKET_CREATE_ERROR;
    }

    DEBUG_LOG("Connecting to remote : %s:%d",inet_ntoa(server_addr->sin_addr),ntohs(server_addr->sin_port));
    // connect socket
    if (connect(sock, (const struct sockaddr *) server_addr, sizeof(*server_addr)) < 0){
        ERROR_LOG("connect to ODB server");
        return ODB_SOCKET_CREATE_ERROR;
    }
    DEBUG_LOG("Sending query :");
    ODB_Query_log(query);

    // serialize query, then send it
    serialize_odb_query_desc_inplace(query);

    // send request
    if(original_write(sock, query, ODB_QUERY_DESC_SIZE) < 0){
        ERROR_LOG("write request");
        original_close(sock);
        return ODB_SOCKET_WRITE_ERROR;
    }
    DEBUG_LOG("Request sent !");
    deserialize_odb_query_desc_inplace(query);

    uint8_t * start = NULL; //, *end = NULL;
    
    switch(msg_type){
        case ODB_MSG_GET_PAYLOAD:
            bytes_to_read = MIN(query->d_desc.body_size,payload_size - local_buff_offset);
            start         = ((uint8_t*) buffer->buffer) + local_buff_offset;

            bytes_read = strict_recv(sock, start,bytes_to_read,MSG_WAITALL);
            if(bytes_read < 0){
                ERROR_LOG("Payload read");
                original_close(sock);
                return ODB_SOCKET_READ_ERROR;
            }
            if ((size_t)bytes_read != bytes_to_read || bytes_read == 0){
                ERROR_LOG("Body read not enough !! got %zu bytes instead of %zu",(size_t) bytes_read,bytes_to_read); 
            }
            *tot_bytes_read += (size_t) bytes_read;
        break;

        case ODB_MSG_GET_BODY:
            size_t offset = MIN(payload_size, query->d_desc.head_size);
            bytes_to_read = MIN(payload_size - offset, query->d_desc.body_size);
            start = ((uint8_t*) buffer->buffer) + offset;

            bytes_read = strict_recv(sock,(void*) start,bytes_to_read,MSG_WAITALL);
            if(bytes_read < 0){
                DEBUG_LOG("[ERROR] Body read error !!");
                original_close(sock);
                return ODB_SOCKET_READ_ERROR;
            }
            if ((size_t)bytes_read != bytes_to_read || bytes_read == 0){
                ERROR_LOG("Body read not enough !! got %zu bytes instead of %zu",(size_t) bytes_read,bytes_to_read); 
            }

            *tot_bytes_read += (size_t) bytes_read;
        break;

        case ODB_MSG_GET_UNALIGNED_DATA:
            // query format :
            //  {hi ; h(i+1) + b(i+1) ; ti}
            // we assume we have :
            //  Local Buffer : {h(i+1); b(i+1) ; t(i+1)}, 
            // And Last Desc received : {h(i) ; b(i) ; t(i) }
            // For each i, P = h(i) + b(i) + t(i) = h(0) + b(0) + t(0), 
            // where P, h(0), b(0), t(0) are the original payload, header,body and tail sizes.
            // So for each i, h(i) <= h(i+1), t(i) <= t(i+1), b(i) >= b(i+1)

            // So locally, we know :
            // Local Buffer : {h(i+1); b(i+1) ; t(i+1)}, 
            // Query Desc : {hi ; h(i+1) + b(i+1) ; ti}

            size_t head_to_recv = buffer->head_size > query->d_desc.head_size ? buffer->head_size - query->d_desc.head_size : 0;
            size_t tail_to_recv   = buffer->tail_size > query->d_desc.tail_size ? buffer->tail_size - query->d_desc.tail_size : 0;
            struct iovec iovecs[2] = {
                {((uint8_t*) buffer->buffer) + buffer->head_size - head_to_recv, head_to_recv},
                {((uint8_t*) buffer->tail), tail_to_recv}
            };
            bytes_to_read     = head_to_recv + tail_to_recv;
            struct msghdr msg = MSGHDR_INITIALIZER(iovecs,2,0);
            
            // receive unaligned data
            bytes_read = original_recvmsg(sock,&msg,MSG_WAITALL);
            if( bytes_read < 0){
                DEBUG_LOG("[ERROR] Unaligned data read error !!");
                original_close(sock);
                return ODB_SOCKET_READ_ERROR;
            }
            if ((size_t)bytes_read != bytes_to_read || bytes_read == 0){
                ERROR_LOG("Body read not enough !! got %zu bytes instead of %zu",(size_t) bytes_read,bytes_to_read); 
            }
            
            DEBUG_LOG("Received %zu / %zu bytes of unaligned data",bytes_read,bytes_to_read);
            DEBUG_LOG("Head:");
            Buffer_log(iovecs[0].iov_base,iovecs[0].iov_len);
            DEBUG_LOG("Tail:");
            Buffer_log(iovecs[1].iov_base,iovecs[1].iov_len);
            *tot_bytes_read += (size_t) bytes_read;
        break;

        case ODB_MSG_GET_FILE:
            start               = ((uint8_t*) buffer->buffer) + local_buff_offset;
            bytes_to_read = MIN(query->d_desc.body_size,payload_size);
            bytes_read    = strict_recv(sock, start,bytes_to_read,0);
            if(bytes_read < 0){
                original_close(sock);
                return ODB_SOCKET_READ_ERROR;
            }
            *tot_bytes_read += (size_t) bytes_read;
            
        break;

        default:
            original_close(sock);
            DEBUG_LOG("Query has unexpected msg type !!");
            return ODB_UNKNOWN_ERROR;
    }

    if(tot_bytes_read == 0){
        DEBUG_LOG("[ERROR] No data received !!");
    }
    DEBUG_LOG("Got %zu bytes",*tot_bytes_read);

    original_close(sock);
    return ODB_SUCCESS;
}

ODB_ERROR handle_remote_error(ODB_Config *conf,ODB_Local_Buffer *buf, size_t *bytes_read){
    if(conf == NULL || buf == NULL || bytes_read == NULL) return ODB_NULL_PTR;
    (void) buf;
    (void) bytes_read;
    switch(conf->r_err_strat){
        case CORRUPT:
            return 0;
        break;
        case BEST_EFFORT:

        break;
        case FAKE_SEND:

        break;
        case ABORT:
        default:
            perror("ODB : Fault error");
            DEBUG_LOG("ODB : Fault error");
            abort();
    }
    return -1;
}

