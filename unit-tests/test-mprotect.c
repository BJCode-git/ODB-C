#include <newutils.h>
#include <stdio.h>
#include <unistd.h>

volatile int flag = 0;

void test_sighandler (int signo, siginfo_t *info, void *context){
	flag = 1;
	if(signo != SIGSEGV){
		printf("No SIGSEGV received !");
	}
	(void) context;

    uintptr_t addrToUnprotect = (uintptr_t) info->si_addr & ~(PAGE_SIZE - 1);
    ODB_ProtectedMemoryTable *entry = find_ODB_Protected_Memory(&intern_PMT, (void*)addrToUnprotect,1);

    printf("Entering Handler with addr %p \n",(void*) addrToUnprotect);

    // Test if this is an ODB Related page fault, remove from PMT

    if(entry != NULL){

        printf("ODB Related Pagefault \n");
		// get the start address of protected zone
		uint8_t *data = (uint8_t *) entry->addr;

        // Remove memory protection
		printf("Remove protection on %p \n",entry->addr);
        if ( ODB_SUCCESS == remove_ODB_Protected_Memory(&intern_PMT, entry)){
           printf("Successful Unprotect ! \n");
        }
        else {
            perror("Unprotect failed !");
        }

        //update 1st value of the unprotected zone
		data[0] = 0xFF;
		(void) data;
		flag += 1;

    }
	else{
		printf("Entry == NULL !! \n");
		exit(EXIT_FAILURE);
	}

    printf("Leaving Handler \n");
}

void fill_local_buffer(ODB_Local_Buffer *buffer){

	for(size_t i = 0; i < buffer->head_size; i++){
		((uint8_t*) buffer->buffer)[i] = 1;
	}

	for(size_t i = 0; i < buffer->body_size; i++){
		((uint8_t*) buffer->body)[i] = 2;
	}

	for(size_t i=0; i<buffer->tail_size;i++){
		((uint8_t*) buffer->tail)[i] = 3;
	}
}

void print_local_buffer_info(void * raw_buffer, ODB_Local_Buffer *buf){
	printf("Adresse buffer : %p\n", raw_buffer);
	printf("Head address   : %p\n", buf->buffer);
	printf("Head size      : %zu bytes\n", buf->head_size);
	printf("Body address   : %p\n", buf->body);
	printf("Body size      : %zu bytes\n", buf->body_size);
	printf("Tail address   : %p\n", buf->tail);
	printf("Tail size      : %zu bytes\n", buf->tail_size);
	printf("--------------------------------------------\n");
}

void print_error(ODB_ERROR err){
	switch(err){
		case ODB_NULL_PTR:
			fprintf(stderr, "NULL POINTER\n");
			break;
		case ODB_MPROTECT_ERROR:
			fprintf(stderr,"MPROTECT ERROR\n");
			break;
		case ODB_MEMORY_ALLOCATION_ERROR:
			fprintf(stderr, "MEMORY ALLOCATION ERROR\n");
		break;
		default:
			fprintf(stderr, "UNKNOWN ERROR\n");
	}
}

int main(void) {

	uint8_t tab1[2*PAGE_SIZE];
	uint8_t tab2[3*PAGE_SIZE];
	uint8_t tab3[6*PAGE_SIZE];
	ODB_Local_Buffer buf1, buf2, buf3;

	INIT_ODB_Local_Buffer((&buf1),tab1,NULL,NULL,0,2*PAGE_SIZE,0);
	INIT_ODB_Local_Buffer((&buf2),tab2,NULL,NULL,0,3*PAGE_SIZE,0);
	INIT_ODB_Local_Buffer((&buf3),tab3,NULL,NULL,0,6*PAGE_SIZE,0);

	get_buffer_parts(&buf1);
	get_buffer_parts(&buf2);
	get_buffer_parts(&buf3);

	// init parts
	fill_local_buffer(&buf1);
	fill_local_buffer(&buf2);
	fill_local_buffer(&buf3);

	print_local_buffer_info(tab1,&buf1);
	print_local_buffer_info(tab2,&buf2);
	print_local_buffer_info(tab3,&buf3);


	struct sigaction sa;
    memset(&sa, 0, sizeof(sa));              	// Mise à zéro
    sa.sa_sigaction = test_sighandler;        // Fonction à appeler
    sa.sa_flags = SA_SIGINFO;                // Pour pouvoir utiliser siginfo_t

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

	ODB_ERROR ret = add_ODB_Protected_Memory(&intern_PMT, buf1.body, buf1.body_size);
	if(ODB_SUCCESS != ret){
		perror("Unable to add memory to protect (tab1)");
		print_error(ret);
	}
	ret = add_ODB_Protected_Memory(&intern_PMT, buf2.body, buf2.body_size);
	if(ODB_SUCCESS != ret){
		perror("Unable to add memory to protect (tab2)");
		print_error(ret);
	}
	ret = add_ODB_Protected_Memory(&intern_PMT, buf3.body, buf3.body_size);
	if(ODB_SUCCESS != ret){
		perror("Unable to add memory to protect (tab3)");
		print_error(ret);
	}

	if( -1 == mprotect(buf1.body, buf1.body_size , PROT_NONE)){
		printf("Failed to mprotect : %p \n", (void*) tab1);
	}
	if( -1 == mprotect(buf2.body, buf2.body_size, PROT_NONE)){
		printf("Failed to mprotect : %p \n", (void*) tab2);
	}
	if( -1 == mprotect(buf3.body, buf3.body_size, PROT_NONE)){
		printf("Failed to mprotect : %p \n", (void*) tab3);
	}

	// try to access some data
	tab1[buf1.head_size +1] = 0xEE;
	// try to access some data
	tab2[buf2.head_size + PAGE_SIZE - 2] = 0xEE;
	// try to access some data
	tab3[buf3.head_size + 2*PAGE_SIZE +1 ] = 0xEE;

	printf( "tab1[%zu] = %d \n"
			"tab2[%zu] = %d \n"
			"tab3[%zu] = %d \n",
			buf1.head_size + 1,
			tab1[buf1.head_size + 1],
			buf2.head_size + PAGE_SIZE - 2,
			tab2[buf2.head_size + PAGE_SIZE - 2],
			buf3.head_size + 2*PAGE_SIZE +1,
			tab3[buf3.head_size + 2*PAGE_SIZE +1]
	);

	if( flag == 3){
		printf("Memory Handler works \n");
	}
	else{
		printf("Memory handler flag only set for %d/3 protected buffers  !! \n",flag);
	}

	// check if protection is really unset
	tab1[buf1.head_size +1] = 0xAA;
	tab2[buf2.head_size +1] = 0xAA;
	tab3[buf3.head_size +1] = 0xAA;
	printf( "tab1.body[0] = %d \n"
			"tab2.body[0] = %d \n"
			"tab2.body[0] = %d \n",
			tab1[buf1.head_size + 1],
			tab2[buf2.head_size + 1],
			tab3[buf3.head_size + 1]
	);

	
	

	return 0;
}