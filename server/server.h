
#ifndef SERVER_H
#define SERVER_H

#include <ODB/odb-utils.h>

#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <opt.h> 
#include <getopt.h>
#include <time.h>


#define TXT_FILENAME	"rsc/lorem.html"
#define IMG_FILENAME	"rsc/img.jpg"
#define VID_FILENAME	"rsc/vid.mp4"
#define DATA_FILENAME	"results/original_data.save"
#define INTER_SAVENAME	"results/inter.save"
#define ANSWER_FILENAME "results/answer.save"

const char answer_filename[] = ANSWER_FILENAME;
const char inter_filename[] = INTER_SAVENAME;

#ifndef BUFSIZE
//#define BUFSIZE sysconf(_SC_PAGESIZE)
	#define BUFSIZE 1024
#endif

#ifndef NB_IT
	#define NB_IT 1
#endif

#ifndef ONE_SHOT
	#define ONE_SHOT 0
#endif

#ifndef EQU_ALIGN
	#define EQU_ALIGN 0
#endif

#ifndef MIN
	#define MIN(a,b) a < b ? a : b
#endif

#ifndef MAX
	#define MAX(a,b) a > b ? a : b
#endif

#ifndef USE_SENDFILE
	#define USE_SENDFILE 0
#endif

#ifndef FALSE
	#define FALSE 0
#endif
#ifndef TRUE
	#define TRUE 1
#endif

typedef enum {
	txt = 0,
	num,
	img,
	vid
}  DataType;


typedef struct {
	struct sockaddr_in 	server_addr;
	struct sockaddr_in 	next_server;
	DataType 			payload_type;
	size_t				payload_bytes;
	char*				save_path;
} ServerConf;

typedef uint8_t Bool;


struct timespec  start_process_time;
    
void start_measure(){
	start_process_time.tv_nsec = 0;
	start_process_time.tv_sec = 0;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_process_time);
}

void stop_and_save_measure(ServerConf *conf){
	struct timespec end_process_time;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_process_time);

	end_process_time.tv_nsec -= start_process_time.tv_nsec;
	end_process_time.tv_sec -= start_process_time.tv_sec;
	
	// save diff time in nanoseconds in a csv file (

	FILE *f = fopen(conf->save_path,"w");
	fprintf(f,"%ld\n",end_process_time.tv_nsec);
	fclose(f);
}



void print_local_buff_alignment(void *buff, size_t len){
	if(buff == NULL) return;
	ODB_Local_Buffer lc_buf;
	INIT_ODB_Local_Buffer((&lc_buf),buff,len);
	get_buffer_parts(&lc_buf);
	printf( "Buffer alignment:\n"
			"\thead_size: %zu\n"
			"\tbody_size: %zu\n"
			"\ttail_size: %zu\n",
			lc_buf.head_size,
			lc_buf.body_size,
			lc_buf.tail_size);
}

int parse_opt(int argc, char **argv, ServerConf *conf){
    if (conf == NULL) return -1;

    char local_ip[INET_ADDRSTRLEN] = "127.0.0.1";
    char dist_ip[INET_ADDRSTRLEN]  = "127.0.0.1";
	char 				   type[4] = "txt";

	conf->payload_type  = txt;
	conf->payload_bytes = 2048;

    const char *short_opts = "i:l:d:p:t:b:s:";
    const struct option long_opts[] = {
        {"ip-address",       required_argument, 0, 'i'},
        {"listen",           required_argument, 0, 'l'},
        {"dest-ip-address",  required_argument, 0, 'd'},
        {"port",             required_argument, 0, 'p'},
        {"type",             required_argument, 0, 't'},
        {"bytes",            required_argument, 0, 'b'},
		{"save-path",        optional_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(local_ip, optarg, INET_ADDRSTRLEN);
                break;
            case 'l':
				conf->server_addr.sin_port  = atoi(optarg);
                break;
            case 'd':
                strncpy(dist_ip, optarg, INET_ADDRSTRLEN);
                break;
            case 'p':
				conf->next_server.sin_port = atoi(optarg);
                break;
            case 't':
				strncpy(type, optarg, 4);
				if(strncmp(type,"txt",4)==0) conf->payload_type = txt;
				else if(strncmp(type,"num",4)==0) conf->payload_type = num;
				else if(strncmp(type,"img",4)==0) conf->payload_type = img;
				else if(strncmp(type,"vid",4)==0) conf->payload_type = vid;
				else{
					fprintf(stderr, "Usage: %s [--ip-address IP] [--listen PORT] [--dest-ip-address IP] [--port PORT] [--type N] [--bytes N]\n", argv[0]);
					return -1;
				}
                break;
			case 's':
				conf->save_path = optarg;
				break;
            case 'b':
				conf->payload_bytes = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [--ip-address IP] [--listen PORT] [--dest-ip-address IP] [--port PORT] [--type N] [--bytes N]\n", argv[0]);
                return -1;
        }
    }


    // Configurer les adresses
    conf->server_addr.sin_family = AF_INET;
    conf->server_addr.sin_port = htons(conf->server_addr.sin_port);
    inet_aton(local_ip, &(conf->server_addr.sin_addr));

    conf->next_server.sin_family = AF_INET;
    conf->next_server.sin_port = htons(conf->next_server.sin_port);
    inet_aton(dist_ip, &(conf->next_server.sin_addr));

	printf("Listening on %s:%d\n", local_ip, ntohs(conf->server_addr.sin_port));
    printf("Sending to %s:%d\n", dist_ip, ntohs(conf->next_server.sin_port));


    return 0;
}


int compare_data(){
	int ans_fd = open(ANSWER_FILENAME,O_RDONLY), data_fd = open(DATA_FILENAME,O_RDONLY);
	if(ans_fd<0 || data_fd<0){
		perror("Open error");
		close(ans_fd);
		close(data_fd);
		return -1;
	}

	printf("Comparing files...\n");
	flock(data_fd,LOCK_EX);

	char ans_buffer[BUFSIZE];
	char data_buffer[BUFSIZE];
	
	int    diff_byte = 0;
	size_t total_compared = 0;

	ssize_t ans_read_bytes 	= 0;
	ssize_t data_read_bytes = 0;

	do{
		// set buffer to zero
		memset(ans_buffer,0,BUFSIZE);
		memset(data_buffer,0,BUFSIZE);
		
		// read from answer file
		ans_read_bytes = read(ans_fd,ans_buffer,BUFSIZE);
		if(ans_read_bytes<0){
			perror("Answer file Read error");
			flock(data_fd,LOCK_UN);
			close(ans_fd);
			close(data_fd);
			return -1;
		}

		// read from data file until reading same number of bytes
		data_read_bytes =read(data_fd,data_buffer,ans_read_bytes);
		while(data_read_bytes < ans_read_bytes ){
			if(data_read_bytes<=0){
				if(data_read_bytes<0)
					perror("Original data file read error");
				printf("Data sizes mismatch, equal bytes so far: %zu\n", total_compared);
				flock(data_fd,LOCK_UN);
				close(ans_fd);
				close(data_fd);
				return -1;
			}
			//printf("Read %zu / %zu bytes from data file\n",data_read_bytes,ans_read_bytes);
			//printf("Need to read %zu more bytes\n",ans_read_bytes-data_read_bytes);
			ssize_t bytes_read = read(data_fd,data_buffer+data_read_bytes,(size_t) ans_read_bytes-data_read_bytes);
			data_read_bytes = bytes_read <= 0 ? bytes_read : data_read_bytes + bytes_read;
		}


		// compare
		diff_byte = memcmp(ans_buffer,data_buffer,ans_read_bytes);


		if(ans_read_bytes > 0 && diff_byte != 0){
			printf("Data mismatch, diff byte : %zd, read bytes : %zu\n", total_compared + ans_read_bytes -diff_byte,  total_compared );
			printf("\n ******** ans_fd ********\n%s,\n******** data_fd ********\n%s\n", ans_buffer,data_buffer);
			flock(data_fd,LOCK_UN);
			close(ans_fd);
			close(data_fd);
			return 0;
		}

		total_compared += (size_t) ans_read_bytes;
	}while(ans_read_bytes > 0);

	flock(data_fd,LOCK_UN);

	close(ans_fd);
	close(data_fd);

	printf("\tData match !!\n");

	return 1;
}

int save_answer(const char *filename,char * buffer, size_t size, Bool truncate){
	int flags = O_WRONLY;
	flags = truncate == TRUE ? flags |O_CREAT | O_TRUNC : flags | O_APPEND;

	int fd = open(filename,flags,0644);
	if(fd<0){
		perror("File Open error\n");
		return -1;
	}

	if(write(fd,buffer,size)<0){
		perror("Write answer to file error\n");
		close(fd);
		return -1;
	}

	close(fd);
	return 1;
}


int serve_client(int client_fd,ServerConf *conf,Bool is_front_end){
	if(conf==NULL) {
		printf("Conf null\n");
		return -1;
	}

	char *to_free = NULL;
	printf("Allocating buffer of size %zu\n",(size_t) BUFSIZE);
	#if EQU_ALIGN
		char *buffer  = (char*) Buffer_malloc_equitable_split((size_t) BUFSIZE,&to_free);
	#else
		char *buffer = (char*) malloc(BUFSIZE);
		to_free = buffer;
	#endif

	if(to_free == NULL){
		perror("Buffer malloc error\n");
		return -1;
	}

	print_local_buff_alignment(buffer,BUFSIZE);

	memset(buffer,1,BUFSIZE);
	int remote_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	uint64_t total_bytes_read = 0;
	uint64_t total_bytes_sent = 0;

	
	if(remote_socket<0){
		perror("Remote server Socket error\n");
		return -1;
	}

	if(connect(remote_socket,(struct sockaddr*)&conf->next_server,sizeof(conf->next_server))<0){
		perror("Remote server Connect error\n");
		close(remote_socket);
		return -1;
	}

	// write to remote server if front end
	if(is_front_end){
		snprintf(buffer,BUFSIZE,"SEND %d;%zu BYTES",conf->payload_type,conf->payload_bytes);
		write(remote_socket,buffer,strlen(buffer));
	}
	// read from client and write to remote server
	else{
		ssize_t bytes_read = read(client_fd,buffer,BUFSIZE);
		if(bytes_read<0){
			perror("Client socket Read error\n");
			close(remote_socket);
			return -1;
		}
		printf("\tRead %zd bytes from client.\n",bytes_read);
		bytes_read = write(remote_socket,buffer,bytes_read);
	}
	
	printf("\tWrote to dist server ...\n");

	// read from remote server
	Bool truncate = FALSE;
	const char *filename = is_front_end ? answer_filename : inter_filename;
	save_answer(filename,NULL,0,TRUE);
	size_t iter = 0;
	size_t diff_at = 0;
	while(1){
		//if( is_front_end && total_bytes_read >=(uint64_t) NB_IT*conf->payload_bytes &&  (conf->payload_type==txt || conf->payload_type==num) ){
		//	break;
		//}
		
		if(diff_at == 0){
			printf("[Frame %zu]:\n",iter++);
		}
		else
			printf("[Frame %zu] (diff at %zu) :\n",iter++,diff_at);
		printf("\tReading from dist server...\n");

		size_t bytes_read = 0;
		while( (size_t) bytes_read < (size_t) BUFSIZE){
			printf("\tReading from dist server %zu bytes...\n",(size_t) (BUFSIZE - bytes_read));
			ssize_t recv_ret = recv(remote_socket,buffer + (size_t) bytes_read,(size_t) (BUFSIZE - bytes_read),0);
			if(recv_ret<0){
				perror("Remote socket Read error\n");
				//close(remote_socket);
				//return -1;
				continue;
			}
			if(recv_ret==0) break;
			
			bytes_read += recv_ret;
			diff_at = bytes_read;
		}
		if(bytes_read==0){
			printf("0 bytes read -> stop reading from dist server.\n");
			break;
		}

		// if internal server,makes a fault (i.e access data)
		if(!is_front_end){
			printf("\tFaulting...\n");
			char c = buffer[bytes_read/2];
			(void) c;
		}

		total_bytes_read += (uint64_t) bytes_read;
		printf("\tRead %zu bytes | total : %lu\n",(size_t) bytes_read,total_bytes_read);

		// write it back to client
		//printf("\tWritting to client %zu-th frame...\n",iter++);
		size_t nb_bytes_to_write = MIN((size_t)bytes_read,BUFSIZE);
		//printf("\n\n\tCalling write with buffer %p, max size : %zd ...\n", buffer,nb_bytes_to_write);
		size_t bytes_written = 0;
		while( (size_t) bytes_written < nb_bytes_to_write){
			ssize_t ret_send = send(client_fd,buffer + bytes_written,nb_bytes_to_write - bytes_written,0);
			if(ret_send<0){
				perror("Remote socket Write error\n");
				//close(remote_socket);
				//return -1;
				continue;
			}
			bytes_written += ret_send;
		}
		//printf("\tCalled write with buffer %p, size %zu -> wrote %zu bytes.\n",buffer,nb_bytes_to_write,(size_t) bytes_read);
		total_bytes_sent += (uint64_t) bytes_written;
		
		if(diff_at == 0)
			diff_at = total_bytes_read != total_bytes_sent ? iter-1 : 0;

		printf("\tWrote %zd bytes | total : %lu.\n",bytes_read,total_bytes_sent);


		printf("\tSaving answer to file %s...\n\n",filename);
		if( -1 == save_answer(filename,buffer,bytes_read,truncate)){
			perror("Error saving data");
			close(remote_socket);
			free(to_free);
			return -1;
		}
		truncate = FALSE;
		

	}

	printf("\tAnswer fully received from remote server !\n");
	close(remote_socket);
	printf("\tRemote server socket closed.\n");

	free(to_free);
	

	//if(is_front_end) compare_data();

	return 0;
}

int serve(ServerConf *conf,Bool is_front_end){
	if(conf==NULL) return -1;

	int soc = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	setsockopt(soc,SOL_SOCKET,SO_REUSEADDR,&(int){1},sizeof(int));
	if(soc<0){
		perror("Listening Socket error\n");
		return -1;
	}

	if(bind(soc,(struct sockaddr*)&conf->server_addr,sizeof(conf->server_addr))<0){
		perror("Bind error\n");
		close(soc);
		return -1;
	}

	if(listen(soc,100)<0){
		perror("Listen error\n");
		close(soc);
		return -1;
	}

	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	while(1){
		printf("Waiting for client...\n");

		int client = accept(soc,(struct sockaddr *)&client_addr,&client_addr_len);
		printf("\tAccept new client at %s:%d\n",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
		if(client<0){
			perror("Accept error\n");
			close(soc);
			return -1;
		}

		int ret = serve_client(client,conf,is_front_end);

		printf("\tClosing client socket...\n");
		close(client);
		printf("\tClient socket closed.\n");

		if(ret<0){
			perror("Error handling client\n");
			//close(soc);
			return -1;
		}
		#if ONE_SHOT
		break;
		#endif
	}

	close(soc);
	return 0;
}


#endif // SERVER_H
