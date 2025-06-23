#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
	pid_t pid = fork();
	if (pid == 0) {
		printf("pid is %d, child %d\n", pid,getpid());
	} else {
		printf("pid is %d, parent %d\n", pid,getpid());
	}
	return 0;
}