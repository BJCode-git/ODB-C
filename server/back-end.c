

#ifndef BUFSIZE
#define BUFSIZE 1024
#endif


#include <time.h>
#include "server.h"

#define SLEEP_TIME 600

int parse_query(char *buffer,ServerConf *conf){
	// parse client query
	
	if(2 < sscanf(buffer,"SEND %d;%zu BYTES",(int*) &conf->payload_type,(size_t*)&conf->payload_bytes)) 
		return -1;
	
	return 1;
}

int save_data(char *buffer, size_t size, Bool truncate){
	int flags = O_WRONLY;
	flags = truncate == TRUE ? flags |O_CREAT | O_TRUNC : flags | O_APPEND;
	int fd = open(DATA_FILENAME,flags,0644);
	if(fd<0){
		perror("Data file Open error\n");
		return -1;
	}
	flock(fd,LOCK_EX);

	if(write(fd,buffer,size)<0){
		printf("Data file Write error\n");
		flock(fd,LOCK_UN);
		close(fd);
		return -1;
	}

	flock(fd,LOCK_UN);
	close(fd);
	return 1;
}

ssize_t read_cyclic_fd(int fd, char *buffer, size_t size) {
    if (fd < 0 || buffer == NULL || size == 0) {
        errno = EINVAL;
        return -1;
    }

    static off_t position = 0;  // Position de lecture persistante entre les appels
    ssize_t total_read = 0;

    while (total_read < (ssize_t)size) {
        if (lseek(fd, position, SEEK_SET) == (off_t)-1) {
            return -1;
        }

        ssize_t bytes_read = read(fd, buffer + total_read, size - total_read);
        if (bytes_read < 0) {
            return -1; // Erreur de lecture
        } else if (bytes_read == 0) {
            // Fin de fichier atteinte → recommencer depuis le début
            position = 0;
            continue;
        }

        total_read += bytes_read;
        position += bytes_read;
    }

    return total_read;
}

int answer_with_sendfile(int client_fd,ServerConf *conf){
	char  buffer[BUFSIZE];
	int bytes_read = recv(client_fd,buffer,BUFSIZE,0);
	ssize_t ret = -1;

	printf("\tAccepting new client, reading query ...\n");
	if(bytes_read<0){
		perror("Client socket read error\n");
		return -1;
	}

	if(bytes_read==0) return 0;

	printf("\tParsing query ...\n");
	if(parse_query(buffer,conf)<0){
		printf("Parse query error\n");
		//return -1;
	}

	printf("\tGenerating answer ...\n");
	int fd = -1;
	int save_fd = open(DATA_FILENAME,O_WRONLY |O_CREAT | O_TRUNC,0644);

	
	if(conf->payload_type==txt || conf->payload_type==num)
		fd = open(TXT_FILENAME,O_RDONLY);
	if(conf->payload_type==img)
		fd = open(IMG_FILENAME,O_RDONLY);
	else if(conf->payload_type==vid)
		fd = open(VID_FILENAME,O_RDONLY);
	if(fd<0 || save_fd<0){
		fprintf(stderr,"File Open error \"%s\" : %s\n",conf->payload_type==img ? IMG_FILENAME : conf->payload_type==vid ? VID_FILENAME : TXT_FILENAME,strerror(errno));
		return -1;
	}

	Bool chunks_sent = FALSE;
	uint64_t sent_bytes = 0;
	size_t saved_bytes = 0;
	off_t offset = 0, save_offset = 0;
	while(chunks_sent == FALSE){
		
		ret = sendfile(client_fd,fd,&offset,conf->payload_bytes);
		if(ret<0){
			perror("Write to client socket error");
			ret = -1;
			chunks_sent = TRUE;
			continue;
		}
		chunks_sent = ret == 0 ?  TRUE : FALSE;
		sent_bytes += (size_t) ret;
		printf("\tTransferred : %zu (bytes) | Total: %lu (bytes)\n",(size_t) ret,sent_bytes);

		//printf("\tSaving data to file ...\n");
		saved_bytes = 0;
		while(saved_bytes < (size_t) ret){
			ssize_t s = sendfile(save_fd,fd,&save_offset,((size_t) ret)-saved_bytes);
			if( s < 0){
				ret = -1;
				chunks_sent = TRUE;
				continue;
			}
			saved_bytes += (size_t) s;
		}

	}
	printf("\tTotal bytes sent : %zu bytes\n",sent_bytes);


	return ret;
}

int answer_to_client(int client_fd,ServerConf *conf){
	char  buffer[BUFSIZE];
	char *to_free = NULL;
	int bytes_read = recv(client_fd,buffer,BUFSIZE,0);
	ssize_t ret = 1;

	printf("\tAccepting new client, reading query ...\n");
	if(bytes_read<0){
		perror("Client socket read error\n");
		return -1;
	}

	printf("\tReceived :\n%s\n",buffer);

	if(bytes_read==0) return 0;

	printf("\tParsing query ...\n");
	if(parse_query(buffer,conf)<0){
		printf("Parse error\n");
		//use default ServerConf values to know what to send
		//return -1;
	}

	printf("\tAllocating buffer of %zu bytes\n",conf->payload_bytes);
	
	#if EQU_ALIGN
		char *data = (char*) Buffer_malloc_equitable_split(conf->payload_bytes,&to_free);
	#else
		char *data = (char*) malloc(conf->payload_bytes);
		to_free    = data;
	#endif

	if(to_free==NULL){
		perror("Malloc error\n");
		return -1;
	}

	print_local_buff_alignment(buffer,conf->payload_bytes);

	printf("\tGenerating answer ...\n");
	int fd = -1;

	if(conf->payload_type!=num){
		if(conf->payload_type==txt)
			fd = open(TXT_FILENAME,O_RDONLY);
		if(conf->payload_type==img)
			fd = open(IMG_FILENAME,O_RDONLY);
		else if(conf->payload_type==vid)
			fd = open(VID_FILENAME,O_RDONLY);
		if(fd<0){
			fprintf(stderr,"File Open error \"%s\" : %s\n",conf->payload_type==img ? IMG_FILENAME : conf->payload_type==vid ? VID_FILENAME : TXT_FILENAME,strerror(errno));
			free(to_free);
			return -1;
		}
		ret = -1;
	}

	Bool chunks_sent = FALSE, truncate = TRUE;
	uint64_t sent_bytes = 0;
	//size_t it = 0;
	size_t to_send = conf->payload_bytes;
	while(chunks_sent == FALSE){
		
		// if not img/vid or file error occurred
		if(fd == -1){
			// fill with rand() data between 'a' and 'z'
			for(size_t i=0;i<conf->payload_bytes;i++){
				if(i>0 && i % 80 == 0) 
					data[i] = '\n';
				else
					data[i] = conf->payload_type==txt ?  'a' + rand()%26 : rand()%256;
			}
			chunks_sent = TRUE;
		}
		//else if(conf->payload_type==txt){
		//	read_cyclic_fd(fd,data,conf->payload_bytes);
		//	chunks_sent = ++it >= NB_IT ? TRUE : FALSE;
		//}
		else{
			// read from file 
			ssize_t r = read(fd,data,conf->payload_bytes);
			if(r<=0){
				//if error print it
				if( r < 0){
					perror("File Read error\n");
					r = -1;
				}
				// if error or file entirely read
				close(fd);
				chunks_sent = TRUE;
				continue;
			}
			to_send = r;
		}

		//printf("\tSaving data to file ...\n");
		if(save_data(data,to_send,truncate)<0){
			perror("Save data error\n");
			ret = -1;
		}
		else{
			truncate = FALSE;
		}

		printf("\tRead: %zu | Write: %zu | Total: %lu (bytes)\n",to_send,to_send,sent_bytes);
		do{
			ret = send(client_fd,data,to_send,0);
			if(ret<0){
				perror("Write to client socket error");
				ret = -1;
				//chunks_sent = TRUE;
				//continue;
			}
		}while(ret<0);
		sent_bytes += (size_t) ret;
	}
	printf("\tTotal bytes sent : %zu bytes\n",sent_bytes);

	free(to_free);
	return ret;
}

int web_serv(ServerConf *conf){
	if(conf==NULL) return -1;

	int soc = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if(soc<0){
		perror("Socket error\n");
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

	while(1){
		printf("Ready to accept client ...\n");
		int client = accept(soc,NULL,NULL);
		if(client<0){
			perror("Accept error\n");
			close(soc);
			return -1;
		}

		#if USE_SENDFILE
			if(answer_with_sendfile(client,conf) == -1){
				printf("\nError handling client\n");
			}
		#else
			if(answer_to_client(client,conf) == -1){
				printf("\nError handling client\n");
			}
		#endif

		close(client);
		printf("Client handled !");

		#if ONE_SHOT
			break;
		#endif
	}

	close(soc);

	return 0;
}

int main(int argc, char **argv) {

	ServerConf conf;

	// init random seed
	srand( time( NULL ) );

	if(parse_opt(argc,argv,&conf)<0){
		printf("Parse error\n");
		return -1;
	}

	if(web_serv(&conf)<0){
		printf("Serve error\n");
		sleep(SLEEP_TIME);
		return EXIT_FAILURE;
	}
	sleep(SLEEP_TIME);

	return 0;
}