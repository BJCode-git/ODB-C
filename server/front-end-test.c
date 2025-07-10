#include <stdio.h>
#include "server.h"


void clear_stdin_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void get_args(ServerConf *conf) {
    char type[10];
    char bytes[100];
    Bool correct_input = FALSE;

    while (!correct_input) {
        printf("Enter data type among txt/img/vid/num : \n");

        if (fgets(type, sizeof(type), stdin) == NULL) {
            printf("Input error!\n");
            continue;
        }

        // Retirer le \n si présent
        type[strcspn(type, "\n")] = '\0';

        if (strcmp(type, "txt") == 0) conf->payload_type = txt;
        else if (strcmp(type, "num") == 0) conf->payload_type = num;
        else if (strcmp(type, "img") == 0) conf->payload_type = img;
        else if (strcmp(type, "vid") == 0) conf->payload_type = vid;
        else {
            printf("Wrong type entered!\n");
            continue;
        }

        printf("Enter amount of bytes per payload: \n");

        if (fgets(bytes, sizeof(bytes), stdin) == NULL) {
            printf("Input error!\n");
            continue;
        }

        bytes[strcspn(bytes, "\n")] = '\0';  // Retirer le \n

        char *endptr;
        unsigned long long temp = strtoull(bytes, &endptr, 10);

        // Vérifie que toute la chaîne a été convertie
        if (endptr == bytes || *endptr != '\0' || temp == 0) {
            printf("Not a valid number!\n");
            continue;
        }

        conf->payload_bytes = (size_t) temp;
        correct_input = TRUE;
    }
}

void print_config(ServerConf *conf){
	if(conf ==NULL) return;

	printf("\n Running Front-End Test server with config :\n");
	char type[4];
	char addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &conf->server_addr.sin_addr, addr, INET_ADDRSTRLEN);

	switch(conf->payload_type){
		case txt:
			strncpy(type,"txt",4);
		break;
		case num:
			strncpy(type,"num",4);
		break;
		case img:
			strncpy(type,"img",4);
		break;
		case vid:
			strncpy(type,"vid",4);
		break;
		default:
			strncpy(type,"unk",4);
	}

	printf(	"\t IP Adress  : %s:%u \n"
			"\t Query %zu bytes of %s \n",
			addr,
			ntohs(conf->server_addr.sin_port),
			conf->payload_bytes,
			type
			);


}

int test_serve(ServerConf *conf,Bool is_front_end){
	if(conf==NULL) return -1;

	int soc = socket(AF_INET,SOCK_STREAM,0);
	if(soc<0){
		perror("Listening Socket error\n");
		return -1;
	}

	if(bind(soc,(struct sockaddr*)&conf->server_addr,sizeof(conf->server_addr))<0){
		perror("Bind error\n");
		close(soc);
		return -1;
	}

	if(listen(soc,5)<0){
		perror("Listen error\n");
		close(soc);
		return -1;
	}

	
	printf("Waiting for client...\n");

	int client = accept(soc,NULL,NULL);
	if(client<0){
		perror("Accept error\n");
		close(soc);
		return -1;
	}

	handle_client(client,conf,is_front_end);
	close(client);
	close(soc);
	

	return 0;
}

int main(int argc, char **argv) {

	ServerConf conf;

	if(parse_opt(argc,argv,&conf)<0){
		printf("Parse error\n");
		return -1;
	}

	while(1){

		get_args(&conf);
		print_config(&conf);
		if(test_serve(&conf,TRUE)<0){
			printf("Serve error\n");
			return EXIT_FAILURE;
		}
	}


	return 0;
}