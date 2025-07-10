#include <newutils.h>

#define REMOTE_IP "127.0.0.1"
#define REMOTE_PORT  10001

#define LOCAL_IP "127.0.0.1"
#define LOCAL_PORT  10000

#define RAB_SIZE sysconf(_SC_PAGESIZE) * 4

int rab_fd;

int init(size_t size){
	char *c = NULL;
	rab_fd = create_ODB_Local_Buffer(&intern_RAB, size);

	if(rab_fd < 0){
		fprintf(stderr,"create_ODB_Local_Buffer error\n");
		exit(EXIT_FAILURE);
	}

	ODB_Local_Buffer *buf = NULL;

	buf = find_ODB_Local_Buffer(&intern_RAB, rab_fd);

	if( NULL == buf || NULL == buf->buffer){
		fprintf(stderr,"find_ODB_Local_Buffer error\n");
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

int test_get_on_fault(size_t size){
	ODB_Local_Buffer buffer, *original_buffer;
	ODB_Desc desc;
	struct sockaddr_in 			remote_addr;
	//size_t 						buf_len=0;
	remote_addr.sin_family 		= AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
	remote_addr.sin_port 		= htons(REMOTE_PORT);


	INIT_ODB_Local_Buffer((&buffer),malloc(size),NULL,NULL,0,size,0);
	if( NULL == buffer.buffer ){
		fprintf(stderr,"test_get_on_fault : malloc error\n");
		return -1;
	}
	get_buffer_parts(&buffer);
	//buf_len = buffer.head_size + buffer.body_size + buffer.tail_size;


	original_buffer = find_ODB_Local_Buffer(&intern_RAB, rab_fd);

	if( NULL == original_buffer || NULL == original_buffer->buffer){
		fprintf(stderr,"test_get_on_fault : find_ODB_Local_Buffer error\n");
		return -1;
	}

	INIT_ODB_Desc(	desc, ODB_DESC_VIRTUAL, rab_fd,
					original_buffer->head_size, original_buffer->body_size, original_buffer->tail_size, 
					remote_addr);

	// copy desc to buffer body
	memcpy(buffer.body,&desc,sizeof(desc));
	
	// protect buffer
	if(ODB_SUCCESS != add_ODB_Protected_Memory(&intern_PMT, buffer.body, buffer.body_size)){
		fprintf(stderr,"test_get_on_fault: add_ODB_Protected_Memory error\n");
		return -1;
	}
	DEBUG_LOG("test_get_on_fault : protected buffer !");


	//  trigger a fault
	char *c = ((char*)buffer.body);
	char temp = c[0];
	c[5] 		= 0;
	c[5] 		= temp;
	// data should have been downloaded after the fault

	// compare data
	int ret = memcmp(original_buffer->body,buffer.body,MIN(original_buffer->body_size,buffer.body_size));
	if( ret != 0){
		fprintf(stderr,"test_get_on_fault : data mismatch ! %d-th byte different\n", ret);
		DEBUG_LOG("Data mismatch ! %d-th byte different\n" ,ret);
		DEBUG_LOG("original_buffer : ");
		ODB_Local_Buffer_log(original_buffer);
		Buffer_log(original_buffer->buffer, original_buffer->body_size + original_buffer->head_size + original_buffer->tail_size);
		DEBUG_LOG("buffer : ");
		ODB_Local_Buffer_log(&buffer);
		Buffer_log(buffer.buffer, buffer.body_size + buffer.head_size + buffer.tail_size);
		return -1;
	}
	else{
		printf("test_get_on_fault : test ok with data_size %zu\n",size);
	}

	free(buffer.buffer);

	return 0;
}

int main(void) {

	//create RAB
	init(RAB_SIZE);

	//install signal handler
	install_handler();

	//create remote server thread
	pthread_t server_thread;
	if( -1 == pthread_create(&server_thread, NULL, remote_server, NULL)){
		perror("main : pthread_create server thread failed");
		return -1;
	}

	// trigger fault programmatically
	//kill(getpid(), SIGSEGV);

	//wait for remote server to exit

	printf("test_get_on_fault with size %zu\n", RAB_SIZE);
	DEBUG_LOG("test_get_on_fault with size %zu\n", RAB_SIZE);
	test_get_on_fault(RAB_SIZE);

	printf("test_get_on_fault with size %zu\n", 3*PAGE_SIZE);
	DEBUG_LOG("test_get_on_fault with size %zu\n", 3*PAGE_SIZE);
	test_get_on_fault(3*PAGE_SIZE);

	return 0;
}