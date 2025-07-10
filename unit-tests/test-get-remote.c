#include <newutils.h>

#define REMOTE_IP "127.0.0.1"
#define REMOTE_PORT  10001

#define LOCAL_IP "127.0.0.1"
#define LOCAL_PORT  10000

#define RAB_SIZE sysconf(_SC_PAGESIZE) * 3

int rab_fd;

int init(size_t size){
	char *c = NULL;
	rab_fd = create_ODB_Remote_Buffer(&intern_RAB, size);

	if(rab_fd < 0){
		fprintf(stderr,"create_ODB_Remote_Buffer error\n");
		exit(EXIT_FAILURE);
	}

	ODB_Local_Buffer *buf = NULL;

	buf = find_ODB_Remote_Buffer(&intern_RAB, rab_fd);

	if( NULL == buf || NULL == buf->buffer){
		fprintf(stderr,"find_ODB_Remote_Buffer error\n");
		exit(EXIT_FAILURE);
	}

	c = (char*) buf->buffer;
	for(size_t i = 0; i < buf->head_size; i++){
		c[i] = 'H';
	}
	c = (char*) buf->body;
	for(size_t i = 0; i < buf->body_size; i++){
		c[i] = 'B';
	}

	c = (char*) buf->tail;
	for(size_t i = 0; i < buf->tail_size; i++){
		c[i] = 'T';
	}

	return 0;
}


int compare(ODB_Local_Buffer *src, ODB_Local_Buffer *dst){

	if(src == NULL || dst == NULL) return -1;

	size_t s1 = src->head_size + src->body_size + src->tail_size;
	size_t s2 = dst->head_size + dst->body_size + dst->tail_size;


	return memcmp(src->buffer, dst->buffer, MIN(s1,s2));	
}

void* remote_server(void *arg) {
	
	(void) arg;
	struct sockaddr_in server_addr;
	int    server_fd = -1;
	memset(&server_addr, 0, sizeof(server_addr));

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Fake Remote Server : Socket error\n");
		exit(EXIT_FAILURE);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	server_addr.sin_port 		= htons(REMOTE_PORT);

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Fake Remote Server : Bind error\n");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 1) < 0) {
		perror("Fake Remote Server : Listen error\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		DEBUG_LOG("Fake Remote Server : Accepting a client ...\n");
		int client = accept(server_fd, NULL, NULL);

		if (client < 0) {
			perror("Fake Remote Server :  Accept error\n");
		}

		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, handle_client, &client) != 0) {
			perror("Fake Remote Server : pthread_create error\n");
			exit(EXIT_FAILURE);
		}

		DEBUG_LOG("Fake Remote Server : client handled !");

	}

	DEBUG_LOG("Fake Remote Server : remote server exit \n");

	pthread_exit(NULL);
}

int test_real_get_remote(size_t size) {
	ODB_Header 					query_header;
	ODB_Desc 					query_desc;
	ODB_Local_Buffer 			local_buffer, *original_buffer;
	size_t 						bytes_read = 0;
	size_t 						offset = 0;
	struct sockaddr_in 			remote_addr;
	remote_addr.sin_family 		= AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	remote_addr.sin_port 		= htons(REMOTE_PORT);

	INIT_ODB_Header((&query_header),ODB_MSG_GET_PAYLOAD,ODB_DESC_SIZE + ODB_HEADER_SIZE);
	INIT_ODB_Local_Buffer((&local_buffer), malloc(size), NULL, NULL, 0, size, 0);
	if( NULL == local_buffer.buffer ){
		fprintf(stderr, "test_real_get_remote : malloc error\n");
		return -1;
	}

	get_buffer_parts(&local_buffer);

	size_t buf_len = local_buffer.head_size + local_buffer.body_size + local_buffer.tail_size;

	// get remote head
	DEBUG_LOG("get remote head");
	INIT_ODB_Desc(query_desc,ODB_DESC_REAL,rab_fd,0,local_buffer.head_size,0,remote_addr);
	printf("Get %zu bytes of RAB with offset %zu\n", query_desc.body_size ,query_desc.head_size);
	if( ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,offset, &bytes_read) ){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	//Buffer_log(local_buffer.buffer, size);
	offset += bytes_read;

	// get remote body
	DEBUG_LOG("get remote body");
	INIT_ODB_Desc(query_desc,ODB_DESC_REAL,rab_fd,offset, local_buffer.head_size + local_buffer.body_size - offset,0,remote_addr);
	printf("Get %zu bytes of RAB with offset %zu\n", query_desc.body_size ,query_desc.head_size);
	if( ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,offset, &bytes_read)){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	//Buffer_log(local_buffer.buffer, size);
	offset += bytes_read;

	// get remote tail
	DEBUG_LOG("get remote tail");
	INIT_ODB_Desc(query_desc,ODB_DESC_REAL,rab_fd,offset,buf_len - offset,0,remote_addr);
	printf("Get %zu bytes of RAB with offset %zu\n", query_desc.body_size ,query_desc.head_size);
	if(ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,offset, &bytes_read)){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	DEBUG_LOG("Final Local Buffer :");
	//Buffer_log(local_buffer.buffer, size);
	offset += bytes_read;

	original_buffer = find_ODB_Remote_Buffer(&intern_RAB,rab_fd);
	if( original_buffer == NULL){
		fprintf(stderr,"test_real_get_remote : compare error\n");
		free(local_buffer.buffer);
		return -1;
	}

	int cmp = compare(original_buffer,&local_buffer);
	if( cmp != 0){
		DEBUG_LOG("test_real_get_remote : compare error %d-th byte different\n",cmp);
		free(local_buffer.buffer);
		return -1;
	}
	else{
		DEBUG_LOG("test_real_get_remote : compare ok\n");
		free(local_buffer.buffer);
	}

	return 0;
}

int test_unaligned_header_get_remote(size_t size) {
	ODB_Header 					query_header;
	ODB_Desc 					query_desc;
	ODB_Local_Buffer 			local_buffer,*original_buffer = NULL;
	size_t 						bytes_read = 0;
	struct sockaddr_in 			remote_addr;
	remote_addr.sin_family 		= AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	remote_addr.sin_port 		= htons(REMOTE_PORT);

	INIT_ODB_Header((&query_header),ODB_MSG_GET_PAYLOAD,ODB_DESC_SIZE + ODB_HEADER_SIZE);
	INIT_ODB_Local_Buffer((&local_buffer), malloc(size), NULL, NULL, 0, size, 0);
	if( NULL == local_buffer.buffer ){
		fprintf(stderr, "test_real_get_remote : malloc error\n");
		free(local_buffer.buffer);
		return -1;
	}
	get_buffer_parts(&local_buffer);
	memset(local_buffer.buffer, 0, size);

	// get remote head
	DEBUG_LOG("get remote head");
	INIT_ODB_Desc(query_desc,ODB_DESC_VIRTUAL,rab_fd,local_buffer.head_size,0,0,remote_addr);
	printf("Get %zu bytes of header RAB\n", query_desc.head_size);
	if( ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,0, &bytes_read) ){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	Buffer_log(local_buffer.buffer, local_buffer.head_size);
	
	original_buffer = find_ODB_Remote_Buffer(&intern_RAB,rab_fd);
	if( original_buffer == NULL){
		fprintf(stderr,"test_real_get_remote : compare error\n");
		free(local_buffer.buffer);
		return -1;
	}

	int cmp = memcmp(local_buffer.buffer, original_buffer->buffer, MIN(local_buffer.head_size,original_buffer->head_size));
	if( cmp != 0){
		fprintf(stderr,"test_real_get_remote : header compare error\n");
		DEBUG_LOG("test_real_get_remote : header compare error %d-th byte different\n",cmp);
		free(local_buffer.buffer);
		return -1;
	}
	else{
		printf("test_real_get_remote : header compare ok\n");
		DEBUG_LOG("test_real_get_remote : headercompare ok\n");
		free(local_buffer.buffer);
	}

	return 0;
}

int test_unaligned_tail_get_remote(size_t size) {

	ODB_Header 					query_header;
	ODB_Desc 					query_desc;
	ODB_Local_Buffer 			local_buffer,*original_buffer = NULL;
	size_t 						bytes_read = 0;
	struct sockaddr_in 			remote_addr;
	remote_addr.sin_family 		= AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	remote_addr.sin_port 		= htons(REMOTE_PORT);

	INIT_ODB_Header((&query_header),ODB_MSG_GET_PAYLOAD,ODB_DESC_SIZE + ODB_HEADER_SIZE);
	INIT_ODB_Local_Buffer((&local_buffer), malloc(size), NULL, NULL, 0, size, 0);
	if( NULL == local_buffer.buffer ){
		fprintf(stderr, "test_real_get_remote : malloc error\n");
		return -1;
	}
	get_buffer_parts(&local_buffer);
	memset(local_buffer.buffer, 0, size);

	// get remote tail
	DEBUG_LOG("get remote tail");
	INIT_ODB_Desc(query_desc,ODB_DESC_VIRTUAL,rab_fd,0,0,local_buffer.tail_size,remote_addr);
	printf("Get %zu bytes of tail RAB\n", query_desc.tail_size);
	if(ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,0, &bytes_read)){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	Buffer_log(local_buffer.tail, local_buffer.tail_size);

	original_buffer = find_ODB_Remote_Buffer(&intern_RAB,rab_fd);
	if( original_buffer == NULL){
		free(local_buffer.buffer);
		fprintf(stderr,"test_real_get_remote : compare error\n");
		return -1;
	}

	int cmp = memcmp(local_buffer.tail, original_buffer->tail - local_buffer.tail_size + original_buffer->tail_size, MIN(local_buffer.tail_size,original_buffer->tail_size));
	free(local_buffer.buffer);
	if( cmp != 0){
		fprintf(stderr,"test_real_get_remote : tail compare error\n");
		DEBUG_LOG("test_real_get_remote : tail compare error %d-th byte different\n",cmp);
		return -1;
	}
	else{
		printf("test_real_get_remote : tail compare ok\n");
		DEBUG_LOG("test_real_get_remote : tail compare ok\n");
	}

	return 0;
}

int test_unaligned_both_get_remote(size_t size) {

	ODB_Header 					query_header;
	ODB_Desc 					query_desc;
	ODB_Local_Buffer 			local_buffer, *original_buffer = NULL;
	size_t 						bytes_read = 0;
	struct sockaddr_in 			remote_addr;
	remote_addr.sin_family 		= AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	remote_addr.sin_port 		= htons(REMOTE_PORT);	

	INIT_ODB_Header((&query_header),ODB_MSG_GET_PAYLOAD,ODB_DESC_SIZE + ODB_HEADER_SIZE);
	INIT_ODB_Local_Buffer((&local_buffer), malloc(size), NULL, NULL, 0, size, 0);
	if( NULL == local_buffer.buffer ){
		fprintf(stderr, "test_real_get_remote : malloc error\n");
		free(local_buffer.buffer);
		return -1;
	}
	get_buffer_parts(&local_buffer);
	memset(local_buffer.buffer, 0, size);

	// get remote both
	DEBUG_LOG("get remote both");
	INIT_ODB_Desc(query_desc,ODB_DESC_VIRTUAL,rab_fd,local_buffer.head_size,0,local_buffer.tail_size,remote_addr);
	printf("Get %zu bytes of head, %zu bytes of tail of RAB \n", query_desc.head_size ,query_desc.tail_size);
	if(ODB_SUCCESS != ODB_get_remote_data(&query_desc, &local_buffer,0, &bytes_read)){
		free(local_buffer.buffer);
		return -1;
	}
	printf("Read %zu bytes\n", bytes_read);
	//Buffer_log(local_buffer.buffer, size);
	
	original_buffer = find_ODB_Remote_Buffer(&intern_RAB,rab_fd);
	if( original_buffer == NULL){
		fprintf(stderr,"test_real_get_remote : compare error\n");
		free(local_buffer.buffer);
		return -1;
	}

	int cmp = memcmp(local_buffer.buffer, original_buffer->buffer, MIN(local_buffer.head_size,original_buffer->head_size));
	if( cmp != 0){
		fprintf(stderr,"test_real_get_remote : header compare error\n");
		DEBUG_LOG("test_real_get_remote : header compare error %d-th byte different\n",cmp);
		free(local_buffer.buffer);
		return -1;
	}
	else{
		printf("test_real_get_remote : header compare ok\n");
		DEBUG_LOG("test_real_get_remote : headercompare ok\n");
	}

	cmp = memcmp(local_buffer.tail, original_buffer->tail- local_buffer.tail_size + original_buffer->tail_size, MIN(local_buffer.tail_size,original_buffer->tail_size));
	free(local_buffer.buffer);
	if( cmp != 0){
		fprintf(stderr,"test_real_get_remote : tail compare error\n");
		DEBUG_LOG("test_real_get_remote : tail compare error %d-th byte different\n",cmp);
		return -1;
	}
	else{
		printf("test_real_get_remote : tail compare ok\n");
		DEBUG_LOG("test_real_get_remote : tail compare ok\n");
	}

	return 0;
}

int test_unaligned_get_remote(size_t size) {
	
	int cmp = 0;

	cmp = test_unaligned_header_get_remote(size);
	cmp = MIN(cmp,test_unaligned_tail_get_remote(size));
	cmp = MIN(cmp,test_unaligned_both_get_remote(size));

	cmp = MIN(cmp,test_unaligned_tail_get_remote(1));

	return cmp;
}
int main(void) {
	init(RAB_SIZE);

	// create remote server thread
	pthread_t server_thread;
	if( -1 == pthread_create(&server_thread, NULL, remote_server, NULL)){
		perror("main : pthread_create");
		return -1;
	}

	if( test_real_get_remote(RAB_SIZE) < 0){
		DEBUG_LOG("test_real_get_remote error !");
		fprintf(stderr,"test_real_get_remote error !\n");
		pthread_cancel(server_thread);
		return -1;
	}
	else
		printf("test_real_get_remote ok !\n");

	if( test_unaligned_get_remote(RAB_SIZE) < 0){
		DEBUG_LOG("test_unaligned_get_remote error !");
		fprintf(stderr,"test_unaligned_get_remote error !\n");
		pthread_cancel(server_thread);
		return -1;
	}
	else
		printf("test_unaligned_get_remote ok !\n");

	pthread_cancel(server_thread);

	return 0;
}
