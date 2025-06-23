#include <newutils.h>
#include <iterator.h>

int main(void) {
	
	ODB_Desc desc;
	ODB_Desc found_desc;
	char buf1[1024];
	char buf2[512];
	char buf3[ODB_DESC_SIZE];
	struct iovec iov[3] = { {buf1,1024}, {buf2,512}, {buf3,ODB_DESC_SIZE} };

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(80);
	desc.source_addr = addr;

	INIT_ODB_Desc(desc,ODB_DESC_REAL,1,128,256,512,addr);

	memset(&found_desc,0,ODB_DESC_SIZE);
	memset(buf1,0,1024);
	memset(buf2,0,512);
	memcpy(buf3,&desc,sizeof(desc));

	DEBUG_LOG("Looking for a descv : \n");
	search_for_a_descv(iov,3,1024+512+ODB_DESC_SIZE,&found_desc);

	DEBUG_LOG("searched desc :\n");
	ODB_DESC_log(&found_desc);

	DEBUG_LOG("Original desc :\n");
	ODB_DESC_log(&desc);

	if(memcmp(&desc,&found_desc,sizeof(desc)) != 0) {
		printf("Error in search_for_a_descv\n");
		return -1;
	}
	else{
		printf(" Descv found !\n");
	}

	return 0;
}