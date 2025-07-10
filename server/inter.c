#include <stdio.h>
#include "server.h"


int main(int argc, char **argv) {

	ServerConf conf;

	if(parse_opt(argc,argv,&conf)<0){
		printf("Parse error\n");
		return -1;
	}

	if(serve(&conf,FALSE)<0){
		printf("Serve error\n");
		exit(EXIT_FAILURE);
	}

	sleep(180);

	return 0;
}