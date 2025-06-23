#include <iterator.h>

DECL_FN_TEST_SEQUENCE(int, "\tdata = %d \n\n");


int IO_equals(IO_Iterator *it1, IO_Iterator *it2){
	if(it1 == NULL || it2 == NULL) return 0;

	uint8_t *data1 = NULL, *data2 = NULL;

	while(!IO_Iterator_is_end(it1) && !IO_Iterator_is_end(it2)){
		data1 = (uint8_t*) IO_Iterator_get(it1,sizeof(int));
		data2 = (uint8_t*) IO_Iterator_get(it2,sizeof(int));

		if(NULL == data1 || NULL == data2) return 0;
		if(*data1 != *data2) return 0;
	}

	return 1;
}

void IO_print_int(IO_Iterator *it){

	uint8_t break_count = 0;
	while(!IO_Iterator_is_end(it)){
		int *data = (int*) IO_Iterator_get(it,sizeof(int));
		if(NULL != data){
			printf("%d ", *data);
			if(break_count == 15){
				break_count = 0;
				putchar('\n');
			}
		}
		IO_Iterator_incr(it,1);
	}
	putchar('\n');
}

void test_op(){
	size_t res = 0;
	int t1[] = {1,2,3,4,5,6},
		t2[] = {7,8,9,10},
		t3[] = {11,12,13,14};

	int z1[] = {},
		z2[] = {},
		z3[] = {};
	
	int pz1[] = {101,102},
		pz2[] = {},
		pz3[] = {},
		pz4[] = {103,104};

		
	struct iovec tab[]    = { {t1, 6},  {t2, 4},   {t3, 4} };
	struct iovec ztab[]   = { {z1, 0},  {z2, 0},   {z3, 0} };
	struct iovec pztab1[] = { {pz1, 2}, {pz2, 0},  {pz3, 0}, { pz4, 2} };
	struct iovec pztab2[] = { {pz2, 0}, {pz3, 0},  {pz1, 2}, { pz4, 2} };
	struct iovec pztab3[] = { {pz1, 2}, {pz4, 2},  {pz2, 0}, { pz3, 0} };

	IO_Iterator it,zit,pzit1,pzit2,pzit3;
	init_IO_Iterator(&it,    tab,       3);
	init_IO_Iterator(&zit,   ztab,      3);
	init_IO_Iterator(&pzit1, pztab1,    4);
	init_IO_Iterator(&pzit2, pztab2,    4);
	init_IO_Iterator(&pzit3, pztab3,    4);

	// 2 evaluations for each 0 (incr 0 and decr 0)
	ssize_t seq1[] = {3,4,0, 3, 3, 0,-2,-4,-3,-21};
	int 	exp1[] = {4,8,8,11,14,14,12, 8, 5,  1};
	
	ssize_t seq2[] = {-1,-2};
	int 	exp2[] = {0,0};

	ssize_t seq3[] = {	1,	0,	1,	1, -2, -3, 10};
	int 	exp3[] = {102,102,103,104,102,101, 104};

	ssize_t seq4[] = {  1,  0,  2, -3};
	int 	exp4[] = {102,102,104,101};

	ssize_t seq5[] = {-2};
	int 	exp5[] = {103};


	printf("Test iterator operator ...\n");

	printf("/********** Normal Tab iterator **********/\n");
	res = test_sequence_int(&it,seq1,exp1,10);
	if( res == 12)
		printf("\ttest1 passed\n");
	else
		printf("\ttest1 failed, %zu numbers equal\n",res);

	printf("/********** Zero Tab iterator **********/\n");
	res = test_sequence_int(&zit,seq2,exp2,3);
	if( res == 0)
		printf("\ttest2 passed\n");
	else
		printf("\ttest2 failed, %zu numbers equal\n",res);

	printf("/********** Partial zero tab iterator 1 **********/\n\n");
	printf("/**********       Void middle tab       **********/\n");
	res = test_sequence_int(&pzit1,seq3,exp3,7);
	if( res == 7)
		printf("\ttest3 passed\n");
	else
		printf("\ttest3 failed, %zu numbers equal\n",res);

	printf("\n/********** Partial zero tab iterator 2 **********/\n");
	printf("/**********       Void begin  tab       **********/\n");
	res = test_sequence_int(&pzit2,seq4,exp4,4);
	if( res == 5)
		printf("\ttest4 passed\n");
	else
		printf("\ttest4 failed, %zu numbers equal\n",res);

	printf("\n/********** Partial zero tab iterator 3 **********/\n");
	printf("/**********        Void end tab         **********/\n");
	pzit3.current_vec = 3;
	pzit3.current_index = 0;
	res = test_sequence_int(&pzit3,seq5,exp5,1);
	if( res == 1)
		printf("\ttest5 passed\n");
	else
		printf("\ttest5 failed, %zu numbers equal\n",res);

}

void test_cpy(){
	printf("Testing copy ...\n");
	int t1[] = {1,1,1,1,1,1},
		t2[] = {2,2,2,2},
		t3[] = {3,3,3,3};

	int tt1[] = {101,101,101,101,101,101},
		tt2[] = {102,102,102,102},
		tt3[] = {103,103,103,103};

	struct iovec io1[]    = { {t1, 6},  {t2, 4},   {t3, 4} };
	struct iovec io2[]    = { {tt1, 6}, {tt2, 4},  {tt3, 4} };

	IO_Iterator it1, it2;
	init_IO_Iterator(&it1, io1, 3);
	init_IO_Iterator(&it2, io2, 3);

	printf("It1 before copy : \n");
	IO_print_int(&it1);
	printf("It2 before copy : \n");
	IO_print_int(&it2);

	IO_Iterator_start(&it1);
	IO_Iterator_start(&it1);

	IO_Iterator_cpy(&it2,&it1);

	IO_Iterator_start(&it1);
	IO_Iterator_start(&it2);

	printf("It1 after copy : \n");
	IO_print_int(&it1);
	printf("It2 after copy : \n");
	IO_print_int(&it2);

	if(IO_equals(&it1,&it2)) printf("\nTest passed!\n");
	else printf("\nTest failed!\n");

}

int main(void){

	test_cpy();
	test_op();

	return 0;
	
}