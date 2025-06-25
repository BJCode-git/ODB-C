#include <ODB/odb-utils.h>



/****************************************
*                                       *
*           CRC computing               *
*                                       *
****************************************/


// CRC code extracted and adapted from https://github.com/lammertb/libcrc/blob/master/src/crc8.c

static const uint8_t sht75_crc_table[] = {
	0,   49,  98,  83,  196, 245, 166, 151, 185, 136, 219, 234, 125, 76,  31,  46,
	67,  114, 33,  16,  135, 182, 229, 212, 250, 203, 152, 169, 62,  15,  92,  109,
	134, 183, 228, 213, 66,  115, 32,  17,  63,  14,  93,  108, 251, 202, 153, 168,
	197, 244, 167, 150, 1,   48,  99,  82,  124, 77,  30,  47,  184, 137, 218, 235,
	61,  12,  95,  110, 249, 200, 155, 170, 132, 181, 230, 215, 64,  113, 34,  19,
	126, 79,  28,  45,  186, 139, 216, 233, 199, 246, 165, 148, 3,   50,  97,  80,
	187, 138, 217, 232, 127, 78,  29,  44,  2,   51,  96,  81,  198, 247, 164, 149,
	248, 201, 154, 171, 60,  13,  94,  111, 65,  112, 35,  18,  133, 180, 231, 214,
	122, 75,  24,  41,  190, 143, 220, 237, 195, 242, 161, 144, 7,   54,  101, 84,
	57,  8,   91,  106, 253, 204, 159, 174, 128, 177, 226, 211, 68,  117, 38,  23,
	252, 205, 158, 175, 56,  9,   90,  107, 69,  116, 39,  22,  129, 176, 227, 210,
	191, 142, 221, 236, 123, 74,  25,  40,  6,   55,  100, 85,  194, 243, 160, 145,
	71,  118, 37,  20,  131, 178, 225, 208, 254, 207, 156, 173, 58,  11,  88,  105,
	4,   53,  102, 87,  192, 241, 162, 147, 189, 140, 223, 238, 121, 72,  27,  42,
	193, 240, 163, 146, 5,   52,  103, 86,  120, 73,  26,  43,  188, 141, 222, 239,
	130, 179, 224, 209, 70,  119, 36,  21,  59,  10,  89,  104, 255, 206, 157, 172
};

uint8_t crc8_ptr(const uint8_t *input_ptr, size_t num_bytes, uint8_t crc){
    size_t a;
    const unsigned char *ptr;

    ptr = input_ptr;

    if ( ptr != NULL ){ 
        for (a=0; a<num_bytes; a++) {
            crc = sht75_crc_table[(*ptr++) ^ crc];
        }
    }
    return crc;
}

/*
 * uint8_t crc_8( const unsigned char *input_str, size_t num_bytes );
 *
 * The function crc_8() calculates the 8 bit wide CRC of an input string of a
 * given length.
 */


/****************************************
*                                       *
*          ODB_Header functions         *
*                                       *
****************************************/
#if ODB_STANDALONE
void compute_ODB_Header_crc(ODB_Header *ptr){
    if (ptr == NULL) return;

    uint8_t crc = CRC_INIT;
    
    crc = crc8_ptr((const uint8_t *) &(ptr->magic_number),sizeof(ptr->magic_number),CRC_INIT);
    crc = crc8_ptr((const uint8_t *) &(ptr->type),sizeof(ptr->type),crc);
    crc = crc8_ptr((const uint8_t *) &(ptr->total_size),sizeof(ptr->total_size),crc);
    ptr->crc = crc;

}
#endif

ODB_ERROR parse_ODB_Header(ODB_Header *header){
    if (header == NULL) return ODB_NULL_PTR;

    #if ODB_STANDALONE
        uint8_t crc = header->crc;
        if(header->magic_number != ODB_MAGIC_NUMBER){
            DEBUG_LOG("Not a valid ODB Header parsed -> magic number not valid !\n");
            return ODB_PARSE_ERROR;
        }
        
        compute_ODB_Header_crc(header);
        if( crc != header->crc){
            header->crc = crc;
            DEBUG_LOG("Invalid ODb Header : crc mismatch %u vs %u",crc,header->crc);
            return ODB_PARSE_ERROR;
        }
    #endif
   
    if( header->type < NONE || ODB_MSG_SEND_VIRTUAL < header->type){
        DEBUG_LOG("Not a valid ODB Header parsed -> type not valid !\n");
        return ODB_PARSE_ERROR;
    }

    ODB_HEADER_log(header);
    
    return ODB_SUCCESS;
}

/****************************************
*                                       *
*           ODB_DESC functions          *
*                                       *
****************************************/

void compute_ODB_Local_Desc_crc(ODB_Local_Desc *ptr){
    if (ptr == NULL) return;
    ptr->magic_number = ODB_MAGIC_NUMBER;
    uint8_t crc = CRC_INIT;
    crc = crc8_ptr((const uint8_t *) &ptr->magic_number, sizeof(ptr->magic_number),CRC_INIT);
    crc = crc8_ptr((const uint8_t *) &ptr->desc.d_desc.fd, sizeof(ptr->desc.d_desc.fd),crc);
    crc = crc8_ptr((const uint8_t *) &ptr->desc.d_desc.head_size, sizeof(ptr->desc.d_desc.head_size),crc);
    crc = crc8_ptr((const uint8_t *) &ptr->desc.d_desc.body_size, sizeof(ptr->desc.d_desc.body_size),crc);
    crc = crc8_ptr((const uint8_t *) &ptr->desc.d_desc.tail_size, sizeof(ptr->desc.d_desc.tail_size),crc);
    crc = crc8_ptr((const uint8_t *) &ptr->desc.source_addr, sizeof(ptr->desc.source_addr),crc);
    ptr->crc = crc;
}

// Sérialisation en place : modifie directement la structure
void serialize_odb_desc_inplace(ODB_Desc *desc) {
    serialize_ODB_Data_Desc(desc->d_desc);
    desc->source_addr.sin_addr.s_addr = htonl(desc->source_addr.sin_addr.s_addr);
    desc->source_addr.sin_port = htons(desc->source_addr.sin_port);
}

// Désérialisation en place : restaure les valeurs originales
void deserialize_odb_desc_inplace(ODB_Desc *desc) {
    deserialize_ODB_Data_Desc(desc->d_desc);
    desc->source_addr.sin_addr.s_addr = ntohl(desc->source_addr.sin_addr.s_addr);
    desc->source_addr.sin_port = ntohs(desc->source_addr.sin_port);
}

/*
static ODB_ERROR parse_ODB_Local_Desc(ODB_Local_Desc *desc) {
    if(desc == NULL) return ODB_NULL_PTR;
    
    if(desc->magic_number == ODB_MAGIC_NUMBER){
        //DEBUG_LOG("Parsing Local Descriptor with Magic Number");
        uint8_t crc = desc->crc;
        compute_ODB_Local_Desc_crc(desc);
        //ODB_DESC_log(&desc->desc);
        if(crc == desc->crc){
            //DEBUG_LOG("Valid Local Descriptor ?");
            if( desc->desc.d_desc.head_size <= (size_t) PAGE_SIZE && 
                desc->desc.d_desc.tail_size <= (size_t) PAGE_SIZE)
            {
                return ODB_SUCCESS;
            }
        }
        //DEBUG_LOG("Invalid ODB_Desc : crc mismatch %d != %d\n",crc,desc->crc);
        desc->crc = crc;
    }

    return ODB_PARSE_ERROR;
}

ODB_ERROR it_parse_Local_Desc(IO_Iterator *start, ODB_Local_Desc **desc){
    if (start == NULL || desc == NULL) return ODB_NULL_PTR;
    if (start->io_count == 0) return ODB_BUFFER_OVERFLOW;

    IO_Iterator it;
    IO_Iterator end;
    IO_Iterator_cpy(&it, start);
    IO_Iterator_cpy(&end, &it);
    IO_Iterator_incr(&end, ODB_LOCAL_DESC_SIZE);

    if(!IO_Iterator_is_end(&end)){
        *desc = (ODB_Local_Desc *) IO_Iterator_get(&it, sizeof(uint8_t));
        if (desc == NULL) return ODB_UNKNOWN_ERROR;
    }
    else return ODB_BUFFER_OVERFLOW;
    
    return parse_ODB_Local_Desc(*desc);
}

ODB_ERROR search_for_a_descv(const struct iovec *buff, const int iocount, const size_t max_it, ODB_Desc *desc) {
    if (buff == NULL || desc == NULL) return ODB_NULL_PTR;

    IO_Iterator it;
    size_t count = 0;
    ODB_ERROR ret = ODB_SUCCESS;
    ODB_Local_Desc *l_desc = NULL;
    //memset(desc, 0, ODB_LOCAL_DESC_SIZE);
    init_IO_Iterator(&it, buff, iocount);

    while (!IO_Iterator_is_end(&it) && count < max_it) {
        ret = it_parse_Local_Desc(&it, &l_desc);
        if (ret == ODB_SUCCESS){
            memcpy(desc,&l_desc->desc,ODB_DESC_SIZE);
            //DEBUG_LOG("found a descriptor :\n");
            //ODB_DESC_log(desc);
            return ODB_SUCCESS;
        } 
        else if (ret == ODB_NULL_PTR || ret == ODB_BUFFER_OVERFLOW) {
            return ret;
        }
        IO_Iterator_incr(&it, 1);
        count++;
    }

    return ODB_PARSE_ERROR;
}

ODB_ERROR search_for_a_descv_offset(const struct iovec *buff, const int iocount,const size_t offset, const size_t max_it, ODB_Desc *desc){
    if (buff == NULL || desc == NULL) return ODB_NULL_PTR;

    IO_Iterator it;
    size_t count = 0;
    ODB_ERROR ret = ODB_SUCCESS;
    ODB_Local_Desc *l_desc = NULL;
    //memset(desc, 0, sizeof(ODB_Desc));
    init_IO_Iterator(&it, buff, iocount);
    IO_Iterator_incr(&it, offset);

    while (!IO_Iterator_is_end(&it) && count < max_it) {
        ret = it_parse_Local_Desc(&it, &l_desc);
        if (ret == ODB_SUCCESS) {
            memcpy(desc,&l_desc->desc,ODB_DESC_SIZE);
            DEBUG_LOG("found a descriptor :\n");
            ODB_DESC_log(desc);
            DEBUG_LOG("Parsed desc :");
            ODB_DESC_log(&l_desc->desc);
            return ODB_SUCCESS;
        } 
        else if (ret == ODB_NULL_PTR || ret == ODB_BUFFER_OVERFLOW) {
            return ret;
        }
        IO_Iterator_incr(&it, 1);
        count++;
    }

    return ODB_PARSE_ERROR;
}

ODB_ERROR search_for_a_desc(const void *buff,size_t max_it, ODB_Desc *desc){
    const struct iovec b ={.iov_base = (void *) buff, .iov_len = max_it};
    return search_for_a_descv(&b,1,max_it,desc);
}

ODB_ERROR search_for_a_desc_offset(const void *buff,const size_t offset,size_t max_it, ODB_Desc *desc){
    const struct iovec b ={.iov_base = (void *) buff, .iov_len = max_it};
    return search_for_a_descv_offset(&b,1,offset,max_it,desc);
}
    */

/****************************************
*                                       *
*       ODB_Query_Desc functions        *
*                                       *
****************************************/

void serialize_odb_query_desc_inplace(ODB_Query_Desc *desc){
    if(desc == NULL) return;
    serialize_ODB_Data_Desc(desc->d_desc);
}

void deserialize_odb_query_desc_inplace(ODB_Query_Desc *desc){
    if(desc == NULL) return;
    deserialize_ODB_Data_Desc(desc->d_desc);
}

/****************************************
*                                       *
*         ODB crc functions        *
*                                       *
****************************************/
#if ODB_STANDALONE
    void compute_ODB_crc(ODB_Header *header,ODB_Desc *desc){
        if (header == NULL) return;
        uint8_t crc = CRC_INIT;
        crc = crc8_ptr((const uint8_t *) &header->magic_number, sizeof(header->magic_number),CRC_INIT);
        crc = crc8_ptr((const uint8_t *) &header->type, sizeof(header->type),crc);
        crc = crc8_ptr((const uint8_t *) &header->total_size, sizeof(header->total_size),crc);

        if(desc != NULL && header->type != ODB_MSG_SEND_REAL){
            crc = crc8_ptr((const uint8_t *) &desc->d_desc.head_size, sizeof(desc->d_desc.head_size),crc);
            crc = crc8_ptr((const uint8_t *) &desc->d_desc.body_size, sizeof(desc->d_desc.body_size),crc);
            crc = crc8_ptr((const uint8_t *) &desc->d_desc.tail_size, sizeof(desc->d_desc.tail_size),crc);
            crc = crc8_ptr((const uint8_t *) &desc->source_addr, sizeof(desc->source_addr),crc);
        }

        header->crc = crc;
    }

    ODB_ERROR parse_ODB_Header_Desc(ODB_Header *header, ODB_Desc *desc){
        if(header == NULL || desc == NULL) return ODB_NULL_PTR;
        uint8_t crc = header->crc;
        compute_ODB_crc(header,desc);

        if(crc != header->crc){
            // restore original value
            DEBUG_LOG("Invalid ODb Header : crc mismatch %hhu vs %hhu",crc,header->crc);
            header->crc = crc;
            return ODB_PARSE_ERROR;
        }
        
        size_t payload_size = desc->d_desc.head_size + desc->d_desc.body_size + desc->d_desc.tail_size;
        if( header->type != ODB_MSG_SEND_REAL && header->total_size != payload_size){
            DEBUG_LOG("Invalid ODb Header : payload size mismatch %zu vs %zu",header->total_size,payload_size);
            return ODB_PARSE_ERROR;
        }

        return ODB_SUCCESS;
    }
#endif
/****************************************
*                                       *
*           ODB log functions           *
*                                       *
*****************************************/

#if DEBUG
    void Buffer_log(const void *buf,size_t buflen){
        if(buf == NULL || buflen == 0) return;
        if(buflen > 500) return;
        for(size_t i =0;i<buflen;i++){
            char *c = (char*) buf;
            if( isprint(c[i]) || c[i]=='\n')
                DEBUG_LOG_CH("%c",c[i]);
            else
                DEBUG_LOG_CH("|0x%02x|", c[i]);
            //if (i >0 && i % 80 == 0) DEBUG_LOG_CH("\n");
        }
        DEBUG_LOG_CH("\n");
    }

    void IOV_log(const struct iovec *iov, size_t iovcnt){
        for(size_t i =0 ; i<iovcnt;i++){
            DEBUG_LOG("IOV[%zu] at %p : %zu bytes\n",i,iov[i].iov_base,iov[i].iov_len);
            if( iov[i].iov_len < 500) 
                Buffer_log(iov[i].iov_base,iov[i].iov_len);
        }
    }

    void ODB_DESC_log(ODB_Desc *desc) {
        if(desc == NULL) return;
        DEBUG_LOG_CH("\tODB_Desc : \n");
        DEBUG_LOG_CH("\t\tFd           : %zu \n",desc->d_desc.fd);
        DEBUG_LOG_CH("\t\tIp_address   : %s:%d \n",inet_ntoa(desc->source_addr.sin_addr),ntohs(desc->source_addr.sin_port));
        DEBUG_LOG_CH("\t\tHead_size    : %zu \n",desc->d_desc.head_size);
        DEBUG_LOG_CH("\t\tBody_size    : %zu \n",desc->d_desc.body_size);
        DEBUG_LOG_CH("\t\tTail_size    : %zu \n",desc->d_desc.tail_size);
        //DEBUG_LOG_CH("\t\tCrc          : %d\n",desc->crc);
    }

    void ODB_HEADER_log(ODB_Header *header) {
        if(header == NULL) return;
        DEBUG_LOG_CH("\tODB_Header : \n");
        #if ODB_STANDALONE
            DEBUG_LOG_CH("\t\tMagic_number : %d \n",header->magic_number);
        #endif
        switch(header->type) {
            case NONE:
            DEBUG_LOG_CH("\t\t NONE \n");
            break;
            case ODB_MSG_GET_PAYLOAD:
            DEBUG_LOG_CH("\t\t ODB_MSG_GET_PAYLOAD \n");
            break;
            case ODB_MSG_GET_UNALIGNED_DATA:
            DEBUG_LOG_CH("\t\t ODB_MSG_GET_UNALIGNED_DATA \n");
            break;
            case ODB_MSG_SEND_UNALIGNED_DATA:
            DEBUG_LOG_CH("\t\t ODB_MSG_SEND_UNALIGNED_DATA \n");
            break;
            case ODB_MSG_SEND_REAL:
            DEBUG_LOG_CH("\t\t ODB_MSG_SEND_REAL \n");
            break;
            case ODB_MSG_SEND_VIRTUAL:
            DEBUG_LOG_CH("\t\t ODB_MSG_SEND_VIRTUAL \n");
            break;
            default:
            return;
        }
        DEBUG_LOG_CH("\t\tTotal_size    : %zu \n",header->total_size);
        #if ODB_STANDALONE
            DEBUG_LOG_CH("\t\tCrc          : %d\n",header->crc);
        #endif
    }

    void ODB_Query_log(ODB_Query_Desc *q){
        if(q == NULL) return;
        DEBUG_LOG_CH("Query :");
        DEBUG_LOG_CH("\t fd : %zu",q->d_desc.fd);
        DEBUG_LOG_CH("\t head_size : %zu",q->d_desc.head_size);
        DEBUG_LOG_CH("\t body_size : %zu",q->d_desc.body_size);
        DEBUG_LOG_CH("\t tail_size : %zu\n",q->d_desc.tail_size);
    }

    void ODB_Local_Buffer_log(ODB_Local_Buffer *buffer) {
        DEBUG_LOG_CH("\tODB_Local_Buffer : \n");
        DEBUG_LOG_CH("\t\tHead : %p \n",buffer->buffer);
        DEBUG_LOG_CH("\t\tHead_size    : %zu \n",buffer->head_size);
        // Buffer_log(buffer->buffer,buffer->head_size);
        DEBUG_LOG_CH("\t\tBody : %p \n",buffer->body);
        DEBUG_LOG_CH("\t\tBody_size    : %zu \n",buffer->body_size);
        // Buffer_log(buffer->body,buffer->body_size);
        DEBUG_LOG_CH("\t\tTail : %p \n",buffer->tail);
        DEBUG_LOG_CH("\t\tTail_size    : %zu \n",buffer->tail_size);
        // Buffer_log(buffer->tail,buffer->tail_size);
    }

    void ODB_Config_log(ODB_Config *config) {
        if(config == NULL) return;
        DEBUG_LOG_CH("\t ODB configuration:\n");
        DEBUG_LOG_CH("\t ODB ports to ignore: ");
        for (int i = 0; i < config->n_ports; i++) {
            DEBUG_LOG_CH("%d ", config->no_odb_ports[i]);
        }
        DEBUG_LOG_CH("\n");
        DEBUG_LOG_CH("\t ODB corrupt value: %d\n", config->corrupt_value);
        DEBUG_LOG_CH("\t ODB countdown: %d\n", config->ms_countdown);
        DEBUG_LOG_CH("\t ODB server address: %s:%d\n", inet_ntoa(config->ODB_serv_addr.sin_addr), ntohs(config->ODB_serv_addr.sin_port));
    }

    static const char ODB_ERROR_MSG[14][50] = {
        "Incomplete",
        "Parse error",
        "Wrong message type",
        "Null pointer",
        "Buffer overflow",
        "Memory allocation error",
        "Mprotect error",
        "Socket create error",
        "Socket write error",
        "Socket read error",
        "Not a socket",
        "Thread create error",
        "Unknown error",
        "Success"
    };

    void ODB_ERROR_log(ODB_ERROR err) {
        uint8_t index = 0;
        if (err >13) err = ODB_UNKNOWN_ERROR;

        index = err == ODB_SUCCESS ? 13 : (uint8_t) -err;
        DEBUG_LOG_CH("\tODB_ERROR : %s\n", ODB_ERROR_MSG[index]);
    }

    static char *state_str[19] = {
        "ODB_NONE",
        "ODB_RESTORE_FROM_HEADER",
        "ODB_RESTORE_FROM_DESC",
        "ODB_RESTORE_FROM_HEADER_AND_DESC",
        "ODB_HEADER_IN_PROGRESS",
        "ODB_DESC_IN_PROGRESS",
        "ODB_PAYLOAD_IN_PROGRESS",
        "ODB_SENDFILE_IN_PROGRESS",
        "ODB_RECEIVING_HEAD",
        "ODB_DOWNLOAD_PAYLOAD",
        "ODB_DOWNLOAD_PAYLOAD_ONLY",
        "ODB_RECEIVING_TAIL",
        "ODB_RECEIVING_FILE",
        "ODB_SEND_REAL",
        "ODB_SEND_VIRTUAL",
        "ODB_SEND_VIRTUAL_TRANSMIT",
        "ODB_SEND_CLIENT_REAL",
        "ODB_SEND_CLIENT_VIRTUAL",
        "ODB_UNKNOWN_STATE"
    };

    void ODB_State_log(ODB_ProgressState state){
        if (state>=19) state = ODB_UNKNOWN_STATE;
        DEBUG_LOG_CH("\tODB_State : %s\n",state_str[state]);
    }

    void MSGHDR_log(const struct msghdr *msg){
        if(msg == NULL) return;
        DEBUG_LOG("msg_name      :");
        Buffer_log(msg->msg_name,msg->msg_namelen);
        DEBUG_LOG("msg_iov      :");
        IOV_log(msg->msg_iov,msg->msg_iovlen);
        DEBUG_LOG("msg_control   :");
        Buffer_log(msg->msg_control,msg->msg_controllen);
        DEBUG_LOG("msg_flags    : %d \n",msg->msg_flags);
    }

#endif

/****************************************
*                                       *
*       Network related functions       *
*                                       *
*****************************************/
/*
int get_peer_info(int fd, struct sockaddr_in *addr) {
    if (addr == NULL) return -1;
    
    struct sockaddr_in  temp_addr;
    memset(&temp_addr, 0, sizeof(temp_addr));
    socklen_t addr_len = sizeof(temp_addr);
    
    if (getpeername(fd, (struct sockaddr *) &temp_addr, &addr_len) == -1) {
        DEBUG_LOG("getpeername error : %s",strerror(errno));
        return -1;
    }
    if (addr != NULL) *addr = temp_addr;

    return 1;
}


char * get_peer_addr(int fd){
    static char buffer[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    if(get_peer_info(fd,&addr) == -1) return NULL;
    if(inet_ntop(AF_INET,&addr.sin_addr,buffer,INET_ADDRSTRLEN) == NULL) return NULL;
    return buffer;
}
*/

/*
int is_socket(const int sockfd){
    
    struct stat statbuf;
    if(fstat(sockfd, &statbuf) == -1){
        perror("is_socket: ERROR fstat");
        return -1;
    }
    // if it's not a socket, return 0
    return S_ISSOCK(statbuf.st_mode);
}
*/


int is_socket(const int sockfd) {
    int sock_type;
    socklen_t optlen = sizeof(sock_type);

    // Get Socket Type
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) < 0) {
        // not a valid socket
        if (errno == ENOTSOCK || errno == EBADF){
            errno = 0;
            DEBUG_LOG("%d is not a valid socket", sockfd);
            return 0;
        }
        // valid socket but opt errors
        perror("getsockopt failed");
        DEBUG_LOG("[ERROR] getsockopt error: %s\n", strerror(errno));
        errno = 0;
        return 1;
    }

    // Vérifier le type de la socket
    if (sock_type == SOCK_STREAM) return 1;
    else return 0;
}

#if !ODB_STANDALONE
int is_ODB_allowed(int sockfd){
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    unsigned int peer_port = 0,local_port = 0;
    
    DEBUG_LOG("test odb socket : %d",sockfd);
    //struct sockaddr_in peer_addr;
    //socklen_t peer_addr_len = sizeof(peer_addr);
    if (getpeername(sockfd, (struct sockaddr *)&addr, &addr_len) < 0) {
        perror("getpeername failed");
        DEBUG_LOG("getpeername error : %s",strerror(errno));
        return 0;
    }
    peer_port = ntohs(addr.sin_port);
    if (getsockname(sockfd, (struct sockaddr*)&addr, &addr_len) == -1) {
        DEBUG_LOG("getsockname error : %s",strerror(errno));
        return 0;
    }
    local_port = ntohs(addr.sin_port);
    DEBUG_LOG("socket %d, local port : %d, peer port : %d",sockfd,local_port,peer_port);

    if(peer_port == 0 || local_port == 0){
        DEBUG_LOG("socket %d, addr : %s:%d is not ODB",sockfd,inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
        return 0;
    }
    
    for (int i = 0; i < MAX_PORTS; i++){
        if( peer_port == ODB_conf.no_odb_ports[i] || local_port == ODB_conf.no_odb_ports[i]){
            DEBUG_LOG("socket %d, addr : %s:%d is ODB",sockfd,inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
            return 1;
        }
    }
    DEBUG_LOG("socket %d, addr : %s:%d is not ODB",sockfd,inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));

    return 0;
}
#endif

int is_address_available(const struct sockaddr_in* addr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0; // socket failed => considered unavailable

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int result = bind(sockfd, (const struct sockaddr*)addr, sizeof(*addr));
    close(sockfd);

    return result == 0 ? 1 : 0;
}

int get_random_port(void) {
    //srand(time( NULL ));
    return (rand() % (65535 - 49152 + 1)) + 49152;
}

void create_peer_addr(struct sockaddr_in *peer_addr) {
    srand( time( NULL ) );
    peer_addr->sin_family       = AF_INET;
    peer_addr->sin_addr.s_addr  = htonl(INADDR_LOOPBACK);
    // dynamic private port range
    peer_addr->sin_port         = htons(get_random_port()); 
    //htons(ODB_SERVER_PORT);

    // get a random ip address among the ones available
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    char selected_ip[INET_ADDRSTRLEN] = ODB_SERVER_ADDR;

    #ifdef LOOK_FOR_SERVER_ADDR
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            // we will not enter for because ifa will be NULL
        }
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                const char *ip = inet_ntoa(addr->sin_addr);
                //if (strncmp(ip, "127.", 4) != 0) { 
                //    // Éviter localhost
                //    strncpy(selected_ip, ip, INET_ADDRSTRLEN);
                //    break;
                //}
                if (strncmp(ip, "0.0.0.0", 7) != 0) { 
                    // Éviter any
                    strncpy(selected_ip, ip, INET_ADDRSTRLEN);
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    #endif

    // associate the ip and port to the structure
    
    peer_addr->sin_addr.s_addr = inet_addr(selected_ip);
}

/**
 * @fn getlocalip
 * @brief Récupère l'adresse IP locale associée à un socket
 * @param socket - Le socket
 * @param addr - L'adresse de retour
 * @return L'adresse IP locale , NULL si la récupération a échoué
 */
int getlocalip(int socket_fd, struct sockaddr_in *addr) {
    if(addr == NULL) return -1;
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(socket_fd, addr, &len) >= 0) {
        return 1;
    } else {
        DEBUG_LOG("getsockname failed");
        return -1;
    }
}

/****************************************
*                                       *
*        Memory related functions       *
*                                       *
*****************************************/

// Th 2 following functions are only used for performance tests (study the impact of non-alignment and initial sending by back-end)

void* Buffer_malloc(size_t hd_size,size_t bd_size,size_t tl_size, void **full_memory_ptr){
	size_t tot_size = hd_size + bd_size + tl_size;
	if(full_memory_ptr == NULL || tot_size == 0) return NULL;
	*full_memory_ptr = NULL;

	if( bd_size% (size_t) PAGE_SIZE!=0) return NULL;
	size_t to_allocate = 0;

	to_allocate += PAGE_SIZE - (hd_size % PAGE_SIZE);
	to_allocate += PAGE_SIZE -bd_size;
	to_allocate += PAGE_SIZE - (tl_size % PAGE_SIZE);

	if(to_allocate %PAGE_SIZE != 0) return NULL;

	*full_memory_ptr = valloc(to_allocate);
	if(*full_memory_ptr == NULL){
			perror("valloc");
			return NULL;
		}
	uint8_t *ptr = (uint8_t*)full_memory_ptr;
	ptr += PAGE_SIZE - (hd_size % PAGE_SIZE);
	return (void*)ptr;
}

void *Buffer_malloc_equitable_split(size_t buflen,char **full_memory_ptr){
	if(full_memory_ptr == NULL || buflen == 0) return NULL;
	*full_memory_ptr = NULL;

	uint8_t *ptr = NULL;
	if(buflen <= (size_t)PAGE_SIZE){
		*full_memory_ptr = (char*) valloc(PAGE_SIZE);
		if(*full_memory_ptr == NULL){
			perror("valloc");
			return NULL;
		}
		return *full_memory_ptr;
	}

	// split a page in two part (hd and tl)
	size_t r = buflen % (size_t)PAGE_SIZE;
	size_t hd_sz= 0, bd_sz = 0, tl_sz = 0;
	if(r == 0){
		bd_sz = buflen - (size_t) PAGE_SIZE;
		hd_sz = ((size_t) PAGE_SIZE)/2;
		tl_sz = ((size_t) PAGE_SIZE)/2;
	}
	else{
		bd_sz = buflen - r;
		hd_sz = r/2;
		tl_sz = buflen - hd_sz - bd_sz;
	}

	*full_memory_ptr = (char*) valloc(PAGE_SIZE + hd_sz + bd_sz + tl_sz);
	if(*full_memory_ptr == NULL){
		perror("valloc");
		return NULL;
	}
	// int ptr to the beginning of the head
	ptr = (uint8_t*) *full_memory_ptr + hd_sz;

	return (void*)ptr;
}

/*
static int is_address_in_virtual(ODB_Local_Buffer *buffer, void *addr) {

    if (NULL == buffer || addr == NULL || buffer->buffer == NULL) return 0;
    uintptr_t pt_addr   = (uintptr_t) addr;
    uintptr_t start     = (uintptr_t) buffer->buffer, 
              end = start + buffer->head_size + buffer->body_size + buffer->tail_size;
    return (start <= pt_addr && pt_addr <= end);
}
*/

// Vérifie si une adresse est alignée sur PAGE_SIZE
static uint8_t is_page_aligned(const void *addr) {
    return ((uintptr_t) addr & (PAGE_SIZE - 1)) == 0;
}

// Aligne vers le haut, sauf si déjà aligné
static void *align_up_to_page(const void *addr) {
    if (addr == NULL) return NULL;
    uintptr_t a = (uintptr_t) addr;
    if (is_page_aligned(addr)) return (void *) a;
    return (void *) ((a + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
}

// Aligne vers le bas (toujours la page courante)
static void *align_down_to_page(const void *addr) {
    if (addr == NULL) return NULL;
    uintptr_t a = (uintptr_t) addr;
    return (void *) (a & ~(PAGE_SIZE - 1));
}

ODB_ERROR get_buffer_parts(ODB_Local_Buffer *buf) {
    if (buf == NULL || buf->buffer == NULL) return ODB_NULL_PTR;

    size_t total_size = buf->head_size + buf->body_size + buf->tail_size;
    uint8_t *start = (uint8_t *) buf->buffer;
    uint8_t *end   = start + total_size;

    // Corps = entre les pages complètes à l'intérieur du buffer
    uint8_t *body_start = (uint8_t *) align_up_to_page(start);
    uint8_t *body_end   = (uint8_t *) align_down_to_page(end);

    if(body_end < body_start){
        buf->head_size  = total_size;
        buf->body       = (void*) end;
        buf->body_size  = 0;
        buf->tail       = (void*) end;
        buf->tail_size  = 0;
        return ODB_SUCCESS;
    }

    buf->body = (void *) body_start;
    buf->tail = (void *) body_end;

    buf->head_size = (size_t)(body_start - start);
    buf->body_size = body_end ==  body_start ? 0 : (size_t)(body_end - body_start);
    buf->tail_size = (size_t)(end - body_end);

    return ODB_SUCCESS;
}


/****************************************
*                                       *
*     Connections Hashmaps functions    *
*                                       *
*****************************************/
static pthread_mutex_t CON_mutex = PTHREAD_MUTEX_INITIALIZER;

static ConnectionTable *add_connection(ConnectionTable **connections, int sockfd) {
    if(connections == NULL) return NULL;

    ConnectionTable *entry = (ConnectionTable *) malloc(sizeof(ConnectionTable));
    if (entry == NULL) return NULL;

    //DEBUG_LOG("add_connection: entry");
    entry->sockfd                   = sockfd;
    //DEBUG_LOG("add_connection: peer addr copied");
    //entry->info.peer_addr           = *addr;
    #if ODB_STANDALONE
        // Connection are ODB by default
        entry->info.is_ODB              = 1;
    #else 
        entry->info.is_ODB              = is_ODB_allowed(sockfd);
    #endif
    entry->info.progress            = ODB_NONE;
    
    entry->info.bytes_read_write    = 0;
    // ODB frame
    //DEBUG_LOG("add_connection: set ODB header");
    memset(&entry->info.odb_header,0,ODB_HEADER_SIZE);
    //DEBUG_LOG("add_connection: set ODB desc");
    memset(&entry->info.desc,0,ODB_DESC_SIZE);
    entry->info.payload.buffer      = NULL;
    entry->info.payload.tail        = NULL;
    entry->info.payload.body        = NULL;
    entry->info.payload.head_size   = 0;
    entry->info.payload.body_size   = 0;
    entry->info.payload.tail_size   = 0;
    #if USE_ODB_HTTP
        ODB_http_init(&entry->http_parser);
    #endif

   
    HASH_ADD_INT(*connections, sockfd, entry);

    return entry;
}
void remove_connection(ConnectionTable **connections, int sockfd) {
    DEBUG_LOG("Removing fd %d ...",sockfd);
    ConnectionTable *entry = NULL;
    if (connections == NULL || *connections == NULL){
        DEBUG_LOG("Connection table is NULL");
        return;
    }

    pthread_mutex_lock(&CON_mutex);
        // find connection if exists
        HASH_FIND_INT(*connections, &sockfd, entry);
        // Delete entry from hash table
        if(entry != NULL){
            #if DEBUG
                if(entry->info.is_ODB)
                    DEBUG_LOG("Delete fd %d (ODB Conn) from connection table",entry->sockfd);
                else
                    DEBUG_LOG("Delete fd %d (not ODB Conn) from connection table",entry->sockfd);
            #endif
            HASH_DEL(*connections, entry);
            free(entry);
            DEBUG_LOG("Connexion supprimée avec succès ! Nombre total: %d", HASH_COUNT(*connections));
        }
        else{
            DEBUG_LOG("Connection %d not found",sockfd);
        }
    pthread_mutex_unlock(&CON_mutex);
}
ConnectionTable *get_connection(ConnectionTable **connections, int sockfd){
    ConnectionTable *entry = NULL;
    if(!is_socket(sockfd)) return NULL;

    DEBUG_LOG("Lookin for connection %d", sockfd);
    pthread_mutex_lock(&CON_mutex);
        HASH_FIND_INT(*connections, &sockfd, entry);
    pthread_mutex_unlock(&CON_mutex);
    if ( entry == NULL){

        //DEBUG_LOG("Connexion non trouvée -> ajout");
        DEBUG_LOG("Adding new connection %d", sockfd);
        pthread_mutex_lock(&CON_mutex);
            entry = add_connection(connections, sockfd);
        pthread_mutex_unlock(&CON_mutex);
        
    }

    return entry;
}

void reset_connections(ConnectionTable **connections) {
    if(connections == NULL) return;
    ConnectionTable *entry = NULL, *tmp = NULL;
    pthread_mutex_lock(&CON_mutex);
    HASH_ITER(hh, *connections, entry, tmp){
        HASH_DEL(*connections, entry);
        free(entry);
    }
    *connections = NULL;
    pthread_mutex_unlock(&CON_mutex);
}   

/****************************************
*                                       *
*    Remote Buffer Hashmaps functions   *
*                                       *
*****************************************/
static pthread_mutex_t RAB_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t          RAB_fd    = 0;

ODB_Local_Buffer* create_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t size, size_t *rab_fd){

    if(RAB==NULL || rab_fd == NULL || size == 0){
        DEBUG_LOG("Bad args");
        return NULL;
    }
    
    unsigned int           n_buffers  = 0;
    ODB_RemoteAccessBuffer *entry     = (ODB_RemoteAccessBuffer*) malloc(sizeof(ODB_RemoteAccessBuffer));
    ODB_Local_Buffer       *lc_buffer = NULL;
    if( entry == NULL ) return NULL;

  
    #if  EQU_ALIGN
        char *full_memory_ptr = NULL;
        entry->buffer.buffer = Buffer_malloc_equitable_split(size, &full_memory_ptr);
        DEBUG_LOG("special malloc : %p begin adress, %p buffer address",full_memory_ptr, entry->buffer.buffer);
    #else
        entry->buffer.buffer = malloc(size);
    #endif
    if( entry->buffer.buffer == NULL) {
        free(entry);
        return NULL;
    }
    entry->accessed = 1;
    lc_buffer = &entry->buffer;

    INIT_ODB_Local_Buffer((&entry->buffer), entry->buffer.buffer, size);
    DEBUG_LOG("Rab Buffer created");
    //ODB_Local_Buffer_log(&entry->buffer);

    pthread_mutex_lock(&RAB_mutex);
        n_buffers = HASH_COUNT(*RAB);
        entry->fd = RAB_fd;

        HASH_ADD_INT(*RAB, fd, entry);
        //*rab_fd = entry->fd;
        *rab_fd = RAB_fd;
        size_t new_count = HASH_COUNT(*RAB);
        if( new_count != n_buffers){
            RAB_fd++;
            start_garbage_collector(&ODB_conf);
        }
    pthread_mutex_unlock(&RAB_mutex);
    
    if(n_buffers == new_count){
        DEBUG_LOG("No more space ! RAB not added !");
        free(entry->buffer.buffer);
        free(entry);
        return NULL;
    }

    return lc_buffer;
}
ODB_ERROR remove_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t fd) {
    if( RAB == NULL) return ODB_NULL_PTR;

    DEBUG_LOG("Trying to remove rab %zu...",fd);

    ODB_RemoteAccessBuffer *entry = NULL;

    pthread_mutex_lock(&RAB_mutex);
        HASH_FIND_INT(*RAB, &fd, entry);
        if(entry != NULL){

            //if(RAB_fd == entry->fd && RAB_fd > 0) RAB_fd--;
            DEBUG_LOG("Remove RAB %zu",entry->fd);

            // if it concerns a Remotely accessible file
            if(entry->buffer.buffer == NULL)
                original_close(entry->buffer.head_size);
            // if its simply a buffer
            else
                free(entry->buffer.buffer);

            DEBUG_LOG("Free %p",entry->buffer.buffer);
            //printf("Free %p\n",entry->buffer.buffer);
            HASH_DEL(*RAB, entry);
            
            free(entry);
            size_t new_count = HASH_COUNT(*RAB);
            if(new_count == 0) stop_garbage_collector();
        }
    pthread_mutex_unlock(&RAB_mutex);
    
    return ODB_SUCCESS;
}

ODB_Local_Buffer *find_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB, size_t fd) {
    ODB_RemoteAccessBuffer *entry   = NULL;
    ODB_Local_Buffer       *ret     = NULL;

    pthread_mutex_lock(&RAB_mutex);
        HASH_FIND_INT(*RAB, &fd, entry);
        if(entry != NULL){
            DEBUG_LOG("Found RAB %zu at %p\n",entry->fd,(void*) entry);

            entry->accessed = 1;            
            ret = &entry->buffer;
        }
        else{
            //printf("[ERROR]Remote Buffer %zu not found !", fd);
            DEBUG_LOG("[ERROR]Remote Buffer %zu not found !", fd);
        }
    pthread_mutex_unlock(&RAB_mutex);

    return ret;
}

ODB_ERROR create_ODB_Remote_sendfile(ODB_RemoteAccessBuffer **RAB, int sendfile_fd, size_t *rab_fd){
    if( RAB == NULL || rab_fd == NULL || sendfile_fd < 0) return ODB_NULL_PTR;

    // search if the the original sendfile fd already exists in the RAB
    if( ODB_SUCCESS == find_ODB_Remote_sendfile(RAB, sendfile_fd, rab_fd)) return ODB_SUCCESS;

    // dup sendfile fd to save a descriptor to the file
    int          new_fd = dup(sendfile_fd);
    unsigned int n_buffers  = 0;
    if(new_fd < 0) return ODB_UNKNOWN_ERROR;

    ODB_RemoteAccessBuffer *entry     = (ODB_RemoteAccessBuffer*) malloc(sizeof(ODB_RemoteAccessBuffer));
    if( entry == NULL ){
        close(new_fd);
        return ODB_MEMORY_ALLOCATION_ERROR;
    }

    entry->accessed         = 1;
    entry->buffer.buffer    = NULL;
    // use head_size as the dup file descriptor record
    entry->buffer.head_size = (size_t) new_fd;
    // use tail_size as the original sendfile fd
    entry->buffer.tail_size = (size_t) sendfile_fd;

    pthread_mutex_lock(&RAB_mutex);
        n_buffers = HASH_COUNT(*RAB);
        entry->fd = RAB_fd;

        HASH_ADD_INT(*RAB, fd, entry);
        *rab_fd = entry->fd;
        size_t new_count = HASH_COUNT(*RAB);
    pthread_mutex_unlock(&RAB_mutex);

    DEBUG_LOG("RAB created with id : %zu",entry->fd);
    
    if(n_buffers == new_count){
        DEBUG_LOG("No more space ! RAB not added !");
        free(entry->buffer.buffer);
        free(entry);
        return ODB_MEMORY_ALLOCATION_ERROR;
    }

    return ODB_SUCCESS;
}

ODB_ERROR find_ODB_Remote_sendfile(ODB_RemoteAccessBuffer **RAB, int sendfile_fd, size_t *rab_fd){
    if( RAB == NULL || rab_fd == NULL)
        return ODB_NULL_PTR;

    ODB_RemoteAccessBuffer *entry, *tmp;
    pthread_mutex_lock(&RAB_mutex);
    HASH_ITER(hh, *RAB, entry, tmp){
        if(entry->buffer.tail_size == (size_t) sendfile_fd){
            *rab_fd = entry->fd;
            entry->accessed = 1;
            return ODB_SUCCESS;
        }
    }
    pthread_mutex_unlock(&RAB_mutex);

    return ODB_NOT_FOUND;
}

void reset_ODB_Remote_Buffer(ODB_RemoteAccessBuffer **RAB) {
    if(RAB == NULL) return;
    ODB_RemoteAccessBuffer *entry, *tmp;
    pthread_mutex_lock(&RAB_mutex);
        HASH_ITER(hh, *RAB, entry, tmp){
            entry->accessed = 0;
        }
    *RAB = NULL;
    pthread_mutex_unlock(&RAB_mutex);
}

/****************************************
*                                       *
*       ODB RAB cleaner functions       *
*                                       *
*****************************************/

void garbage_collect_ODB_RAB(){

    if(intern_RAB == NULL ) return;
    ODB_RemoteAccessBuffer *entry = NULL,*tmp = NULL;

    pthread_mutex_lock(&RAB_mutex);
        HASH_ITER(hh, intern_RAB, entry, tmp){
            // remove buffer which have not been accessed between 
            // two garbage collections
            if(entry->accessed == 0){
                DEBUG_LOG("Garbage collect RAB %zu",entry->fd);
                free(entry->buffer.buffer);
                HASH_DEL(intern_RAB, entry);
                free(entry);
            }
            else entry->accessed = 0;
        }
    pthread_mutex_unlock(&RAB_mutex);

}

static timer_t timer_id = 0;

void start_garbage_collector(ODB_Config *conf){
    if(timer_id != 0) return;

    DEBUG_LOG("Starting garbage collector ...");
    struct sigevent sev = {0};
    struct itimerspec its = {0};

    sev.sigev_notify          = SIGEV_THREAD;
    sev.sigev_notify_function = garbage_collect_ODB_RAB;
    sev.sigev_value.sival_ptr = NULL;

    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1) {
        perror("timer_create");
        return;
    }

    // 1St call in x milliseconds
    long countdown_ms = conf == NULL ? DEFAULT_COUNTDOWN : conf->ms_countdown;
    //(void) conf;
    its.it_value.tv_sec = countdown_ms / 1000;
    its.it_value.tv_nsec = (countdown_ms % 1000) * 1000000;
    DEBUG_LOG("Garbage collection period : %ld s, %ld ns",its.it_value.tv_sec,its.it_value.tv_nsec);

    // Repeat with x period
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    

    if (timer_settime(timer_id, 0, &its, NULL) == -1) {
        perror("timer_settime");
        DEBUG_LOG("Error in timer_settime , errno : %d // args",errno);
        timer_delete(timer_id);
        timer_id = 0;
    }
}

void stop_garbage_collector(){
    if (timer_id != 0) {
        DEBUG_LOG("Stopping garbage collection ...");
        timer_delete(timer_id);
        timer_id = 0;
    }
}

/****************************************
*                                       *
*  Protected Memory Hashmaps functions  *
*                                       *
*****************************************/

ODB_ERROR add_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT, void *addr,size_t size,size_t payload_offset,const ODB_Desc *vdesc) {
    if(PMT==NULL || addr==NULL || size==0) return ODB_NULL_PTR;

    // check if the ODB_Desc  pointed by vdesc,
    // is effectively in the protected memory (i.e. addr <= vdesc + ODB_DESC_SIZE < addr + size)
    if( (ptrdiff_t) vdesc < (ptrdiff_t) addr || ((ptrdiff_t) addr + size) < ((ptrdiff_t) vdesc + ODB_DESC_SIZE) ){
        DEBUG_LOG("[ERROR] Descriptor is not in the protected memory: start %p, end %p, given %p",addr,(void*) ((ptrdiff_t) addr + size),vdesc);
        return ODB_UNKNOWN_ERROR;
    }

    ODB_ProtectedMemoryTable *entry = (ODB_ProtectedMemoryTable*) malloc(sizeof(ODB_ProtectedMemoryTable));
    if( entry == NULL ){
        DEBUG_LOG("[ERROR] Allocation error : %s",strerror( errno ));
        return ODB_MEMORY_ALLOCATION_ERROR;
    }
    entry->addr = addr;
    entry->size = size;
    entry->desc =(ODB_Desc*) vdesc;
    //from where we should download and copy the remote payload
    entry->payload_offset = payload_offset;

    unsigned int n_buffers = 0;
    ODB_Local_Buffer buf;
    INIT_ODB_Local_Buffer(&buf, entry->addr, entry->size);
    n_buffers = HASH_COUNT(*PMT);

    HASH_ADD_PTR(*PMT, addr, entry);
    if(n_buffers == HASH_COUNT(*PMT)){
        DEBUG_LOG("[ERROR] No more space");
        return ODB_MEMORY_ALLOCATION_ERROR;
    }

    if ( mprotect( buf.body,buf.body_size, PROT_NONE)  == -1) {
        #if DEBUG
            DEBUG_LOG("mprotect error: %s",strerror( errno ));
            if (errno == EINVAL) {
                DEBUG_LOG("[ERROR] Invalid protection flags or address is not aligned.\n");
            } else if (errno == EACCES) {
                DEBUG_LOG("[ERROR] Insufficient privileges.\n");
            } else if (errno == ENOMEM) {
                DEBUG_LOG("[ERROR] Address range is invalid or address space is insufficient.\n");
            }
        #endif
        // delete entry from hash table
        HASH_DEL(*PMT, entry);
        free(entry);
        return ODB_MPROTECT_ERROR;
    }
    else{
        DEBUG_LOG("Add mprotection at %p, body size %zu, total size %zu",buf.body,buf.body_size,size);
    }

    return ODB_SUCCESS;
}

ODB_ERROR remove_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT, ODB_ProtectedMemoryTable *entry,ODB_Desc *vdesc) {
    if( PMT == NULL || entry == NULL) return ODB_NULL_PTR;

    DEBUG_LOG("removing mprotection...");
    ODB_Local_Buffer buf;
    INIT_ODB_Local_Buffer(&buf, entry->addr, entry->size);
    
    if ( mprotect( buf.body, buf.body_size, PROT_READ | PROT_WRITE)  == -1) {
        DEBUG_LOG("mprotect error %d: %s",errno,strerror( errno ));
        return ODB_MPROTECT_ERROR;
    }
    else{
        if(vdesc != NULL && entry->desc != vdesc){
            memcpy((void*)vdesc,(void*) entry->desc,ODB_DESC_SIZE);
        }
    }
    DEBUG_LOG("mprotection removed  at %p of size %zu", buf.body, buf.body_size);
    HASH_DEL(*PMT, entry);
    free(entry);

    return ODB_SUCCESS;
}

void reset_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT) {
    if(PMT == NULL) return;

    ODB_ProtectedMemoryTable *entry = NULL, *tmp = NULL;
    HASH_ITER(hh, *PMT, entry, tmp){
        ODB_Local_Buffer buf;
        INIT_ODB_Local_Buffer(&buf, entry->addr, entry->size);
        // remove protection on entry if it exists
        if(-1 == mprotect( buf.body, buf.body_size, !PROT_NONE)){
            ERROR_LOG("remove protection on %p, %zu",buf.body, buf.body_size);
        }
        HASH_DEL(*PMT, entry);
        free(entry);
    }
    *PMT = NULL;
}

ODB_ProtectedMemoryTable* find_ODB_Protected_Memory(ODB_ProtectedMemoryTable **PMT,const void *addr, size_t size) {
    // find an entry if the region beginning at addr and of size size contains a protected region

    if( PMT == NULL || addr == NULL || size == 0) return NULL;
    
    ODB_ProtectedMemoryTable *entry = NULL;
    uintptr_t begin_region = (uintptr_t) addr,
              end_region = begin_region + size -1;
    uintptr_t start, end;
    uintptr_t max_begin, min_end;


    for(entry = *PMT; entry !=NULL; entry = entry->hh.next){
        start   = (uintptr_t) entry->addr;
        end     = entry->size > 0 ? start + entry->size - 1 : start;

        max_begin   = MAX(start, begin_region);
        min_end     = MIN(end, end_region);

        if( max_begin <= min_end ){
            DEBUG_LOG("Protected memory found : %p of size %zu !",entry->addr,entry->size);
            return entry;
        }
    }

    DEBUG_LOG("No protected memory not found");

    return NULL;
}