#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <llhttp.h>

#define THRESHOLD 10

#include <sys/stat.h>
#include <sys/file.h>

static int count = 0;
#define DEBUG_ODB_MESSAGE(ODB_parser) 																		\
do { 																										\
	printf("Simulate Sending Message %d...\n",count);														\
	char *filename = "debug/test-http.log"; 																\
	FILE *file = fopen(filename, "a"); 																		\
	if (file) { 																							\
		int fd = fileno(file); 																				\
		flock(fd, LOCK_EX);																					\
		if(ODB_parser == NULL){																				\
			fprintf(file,"************************\n"														\
					 "|    HPE_Ok Message %d    |\n"														\
					 "************************\n",count);													\
		}																									\
		else{																								\
			fprintf(file,"************************\n"														\
					 "|    HTTP Message %d    |\n"															\
					 "************************\n",count);													\
			if(PARSE_HEADER == ODB_parser->http_state ) {													\
				fprintf(file,"Header Data:\n------------------------\n%.*s------------------------\n",		\
							(int) ODB_parser->http_data_size,(char*) ODB_parser->http_data);				\
			}																								\
			if(SEND_HTTP_REAL == ODB_parser->http_state ) {													\
				fprintf(file,"Real Data:\n------------------------\n%.*s------------------------\n",		\
							(int) ODB_parser->http_data_size,(char*) ODB_parser->http_data);				\
			}																								\
			else if(SEND_HTTP_VIRTUAL == ODB_parser->http_state) { 											\
				fprintf(file,"Virtual Data:\n------------------------\n%.*s\n------------------------\n",	\
							(int) ODB_parser->http_data_size,(char*) ODB_parser->http_data);				\
			}																								\
		}																									\
		flock(fd, LOCK_UN);																					\
		fclose(file); 																						\
	} else { 																								\
		fprintf(stderr, "Could not open debug file: %s\n", filename); 										\
	} 																										\
} while (0)


typedef enum ODB_Http_State{
	PARSE_HEADER,
	SEND_HTTP_REAL,
	SEND_HTTP_VIRTUAL
} ODB_Http_State;

typedef struct ODB_Http{
	llhttp_t		http_parser;
	ODB_Http_State	http_state;
	void 			*http_data;
	size_t 			http_data_size;
	size_t 			content_length;
}ODB_Http;

static llhttp_settings_t ODB_http_settings	= {};

void print_state(ODB_Http_State state) {

	switch(state) {
		case SEND_HTTP_REAL:
			printf("Message State : SEND_HTTP_REAL\n");
		break;
		case SEND_HTTP_VIRTUAL:
			printf("Message State : SEND_HTTP_VIRTUAL\n");
		break;
		default:
			printf("Unknown state\n");
		break;
	}
}

static void reset_ODB_Http(ODB_Http* parser) {
	if(parser == NULL) return;

	parser->http_state 	= PARSE_HEADER;
	parser->http_data 	= NULL;
	parser->http_parser.data = parser;
	parser->http_data_size 	 = 0;
	parser->content_length 	 = 0;
}



static int on_headers_complete(llhttp_t* parser) {
	if(NULL == parser || NULL == parser->data) return 0;
	
	ODB_Http* ctx = (ODB_Http*)parser->data;
	ctx->content_length = parser->content_length;
	//ctx->http_state = parser->content_length >= (size_t) THRESHOLD ? SEND_HTTP_VIRTUAL : SEND_HTTP_REAL; 
	//if(parser->content_length >= (size_t) THRESHOLD)
	//	ctx->http_state 	= SEND_HTTP_VIRTUAL;
	//else
	//	ctx->http_state 	= SEND_HTTP_REAL;

	printf("Headers complete! Content size : %ld\n", parser->content_length);
	//print_parser(parser);

	return HPE_PAUSED;
}

static int on_message_begin(llhttp_t* parser) {
	(void) parser;
	printf("\nMessage %d begin\n\n", ++count);
	return 0;
}



// to slice buffer for each message
static int on_message_complete(llhttp_t* parser) {
	(void) parser;
	//ODB_Http* ctx = (ODB_Http*)parser->data;
	//if(ctx->http_state == PARSE_CHUNK || ctx->http_state == SEND_HTTP_REAL)
	//	ctx->http_state = HTTP_FINISH_REAL;
	//else if (ctx->http_state == SEND_HTTP_VIRTUAL)
	//	ctx->http_state = HTTP_FINISH_VIRTUAL;
	printf("\nMessage %d complete!\n\n", count);
	parser->finish = HTTP_FINISH_SAFE_WITH_CB;
	return HPE_PAUSED;
}



static void init_settings(){
	static uint8_t initiated = 0;
	if(initiated==1) return;
	llhttp_settings_init(&ODB_http_settings);
	ODB_http_settings.on_message_begin		= on_message_begin;
	ODB_http_settings.on_message_complete	= on_message_complete;
	ODB_http_settings.on_headers_complete	= on_headers_complete;
	//ODB_http_settings.on_body 			= on_body;
	//ODB_http_settings.on_chunk_header		= on_chunk_header;
	//ODB_http_settings.on_chunk_complete	= on_chunk_complete;

	initiated = 1;
}


void init_parser(ODB_Http* parser) {
	init_settings();
	llhttp_init(&parser->http_parser, HTTP_BOTH, &ODB_http_settings);  // ou HTTP_BOTH selon les cas
	llhttp_set_lenient_keep_alive(&parser->http_parser, 1);
	reset_ODB_Http(parser);
}


// will always treats all bytes
void parse_and_send_buffer(ODB_Http *parser,const char* buf, size_t len){
	if( parser == NULL || buf == NULL || len == 0) return;

	parser->http_data			= (void*) buf;
	parser->http_data_size		= 0;

	enum llhttp_errno err 	= HPE_PAUSED;
	size_t tot_parsed 		= 0;
	//uint8_t sent = 0;
	uint8_t to_sent = 1;
	while(err != HPE_OK){
		to_sent = 1;
		const char *start 	 = buf + tot_parsed;
		size_t 		to_parse = len > tot_parsed ? len - tot_parsed : 0;
		size_t parsed 		 = 0;

		printf("parsing %p (%zu bytes)\n", start, to_parse);
		
		err = llhttp_execute(&parser->http_parser, start, to_parse);
	
		// handle parsing error
		switch(err){
			case HPE_OK:
				printf("OK at message %d\n", count);
				ODB_Http *null_ptr = NULL;
				DEBUG_ODB_MESSAGE(null_ptr);
				//printf("Reset parser");
				//llhttp_reset(&parser->http_parser);
			break;
			case HPE_PAUSED:
				const char* last_pos = (const char*) llhttp_get_error_pos(&parser->http_parser);
				if(last_pos == NULL) last_pos = start + to_parse;
				if(*last_pos =='\n') printf("Paused at character '\\n'\n");
				else if(*last_pos =='\r') printf("Paused at character '\\r'\n");
				else if(*last_pos =='\0') printf("Paused at character '\\0'\n");
				else printf("Paused at %c\n", *last_pos);
				ptrdiff_t diff = (const ptrdiff_t) last_pos - (const ptrdiff_t) parser->http_data;
				parsed = (size_t) diff;
				parser->http_data_size += (size_t) diff;
				printf("Paused with %zu bytes parsed\n",parsed);
				if(parser->http_state == PARSE_HEADER){
					if( parser->http_parser.content_length >= (size_t) THRESHOLD){
						// send real header
						printf("Header size is %zu\n", parser->http_data_size);
						DEBUG_ODB_MESSAGE(parser);
						parser->http_data 		= (void*) last_pos;
						parser->http_data_size  = 0;
						parser->http_state		= SEND_HTTP_VIRTUAL;
						to_sent = 0;
					}
					else{
						parser->http_state = SEND_HTTP_REAL;
					}
					
				}
				else if(parser->http_state == SEND_HTTP_VIRTUAL){
					// send virtual header
					DEBUG_ODB_MESSAGE(parser);
					parser->http_data		= (void*) last_pos;
					parser->http_data_size	= 0;
					parser->http_state		= PARSE_HEADER;
					to_sent = 0;
				}

				if(parser->http_state == SEND_HTTP_REAL){
					to_sent = 1;
				}
				llhttp_resume(&parser->http_parser);
			break; 
			default:
				if(parser->http_data_size != 0){
					DEBUG_ODB_MESSAGE(parser);
				}
				printf("[ERROR] Parsing error\n");
				const char *e_name = llhttp_errno_name(err), 
						   *e_reas = llhttp_get_error_reason(&parser->http_parser);
			
				if(e_name != NULL && e_reas != NULL) 
					fprintf(stderr, "Parse error: %s %s\n", e_name, e_reas);
				// it's a non-standard error so we must call init to init the llhttp_parser
				else{
					init_parser(parser);
				}
				
				parser->http_state 		= SEND_HTTP_REAL;
				parser->http_data		= (void*) start;
				parser->http_data_size	= to_parse;
				DEBUG_ODB_MESSAGE(parser);
				printf("[RESET] Parsing error\n");
				
				reset_ODB_Http(parser);
				printf("[RESET] Parser RESET\n");
				llhttp_reset(&parser->http_parser);
				
				return;
			break;
		}
		printf("Parsed %zu bytes\n",parsed);
		tot_parsed += parsed;

	}

	if(to_sent){
		/// compute size
		ptrdiff_t diff 			= (const ptrdiff_t) buf + len - (const ptrdiff_t) parser->http_data;
		parser->http_data_size += (size_t) diff;
		printf("[TO_SENT] Sent %zu bytes\n", parser->http_data_size);
		// send data
		DEBUG_ODB_MESSAGE(parser);
	}

	//parse_end:
	//reset_ODB_Http(parser);
	if ( parser->http_parser.flags & F_CONNECTION_CLOSE || parser->http_parser.finish == HTTP_FINISH_SAFE_WITH_CB) {
		printf("[RESET] Parsing finish normally\n");
		llhttp_reset(&parser->http_parser);
		reset_ODB_Http(parser);
	}
	else{
		// dont reset parser state, in case data is not complete
		parser->http_data		= NULL;
		parser->http_data_size	= 0;
	}
}

int main() {
	
	ODB_Http odb_parser, odb_parser2;
	init_parser(&odb_parser);
	init_parser(&odb_parser2);

	const char* chunk1 =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 12\r\n"
		"Content-Type: text/html\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"<h1>One</h1>"
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 13\r\n"
		"Content-Type: text/html\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"<h1>Two!</h1>"
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 13\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"Hello, ";

	const char* chunk2 = 
		"world!";

	const char * part_header1 = 
		"HTTP/1.1 200 OK\r\n"
		"Cont";

	const char * part_header2 = 
		"ent-Length: 14\r\n"
		"Content-Type: text/html\r\n"
		"\r\n";
	const char* part_header3=
	"abcdefghijklmn";

	const char* error_chunk = "CAUSE ERROR, BUT PLZ WORKS !";
	
	const char* chunk3 =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 5\r\n"
		"Content-Type: text/html\r\n"
		"\r\n"
		"abcde";

	
	const char* chunk4 =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"7\r\n"
		"Mozilla\r\n"
		"9\r\n"
		"Developer\r\n"
		"7\r\n"
		"Network\r\n"
		"0\r\n"
		"\r\n"
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"5\r\n"
		"Hello\r\n"
		"8\r\n"
		" World !\r\n"
		"0\r\n"
		"\r\n";
	
	const char* real_chunks =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 4\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"abcd"
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 4\r\n"
		"Content-Type: text/html\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"efgh"
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 4\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"ijkl";

	const char* request_chunk = 
		"GET / HTTP/1.1\r\n"
		"Host: a\r\n"
		"Connection: close\r\n"
		"\r\n";
	
	printf("======== Multiple MSG ========\n");
	parse_and_send_buffer(&odb_parser, chunk1, strlen(chunk1));

	printf("\n======== Last MSG Part========\n");
	parse_and_send_buffer(&odb_parser, chunk2, strlen(chunk2));

	printf("\n======== Part Header 1 ========\n");
	parse_and_send_buffer(&odb_parser, part_header1, strlen(part_header1));

	printf("\n======== Part Header 2 ========\n");
	parse_and_send_buffer(&odb_parser, part_header2, strlen(part_header2));
	
	printf("\n======== Part Header 3 ========\n");
	parse_and_send_buffer(&odb_parser, part_header3, strlen(part_header3));

	printf("\n======== Error Chunk ========\n");
	parse_and_send_buffer(&odb_parser, error_chunk, strlen(error_chunk));

	printf("\n======== Simple Message ========\n");
	parse_and_send_buffer(&odb_parser, chunk3, strlen(chunk3));

	printf("\n======== Encoding Chunk ========\n");
	parse_and_send_buffer(&odb_parser, chunk4, strlen(chunk4));

	printf("\n======== Real Chunks ========\n");
	parse_and_send_buffer(&odb_parser, real_chunks, strlen(real_chunks));

	printf("\n======== Request Chunk ========\n");
	parse_and_send_buffer(&odb_parser2, request_chunk, strlen(request_chunk));

	return 0;
}


/*
static size_t update_ODB_Http(ODB_Http* parser, const void * buffer) {
	if(parser == NULL || buffer == NULL ) return 0;

	ptrdiff_t diff = (const ptrdiff_t) llhttp_get_error_pos(&parser->http_parser) - (const ptrdiff_t) buffer;
	
	switch(parser->http_state){
		case HTTP_NONE:
		break;
		case PARSE_HEADER:
			if(parser->http_header == NULL){
				parser->http_header = (void*) buffer;
				parser->http_header_size = (size_t) diff;
				printf("\t Setting Header : %.*s\n", (int) diff, (char*) parser->http_header);
			}
			else{
				parser->http_header_size += (size_t) diff;
				printf("\t Updating Header : %.*s\n", (int) diff, (char*) parser->http_header);
				if (parser->http_parser.flags & F_CHUNKED) {
					parser->http_state = PARSE_CHUNK;
				}
				else if(parser->content_length >= (size_t) THRESHOLD)
					parser->http_state 	= SEND_HTTP_VIRTUAL;
				else
					parser->http_state 	= SEND_HTTP_REAL;
			}
			
		break;
		case PARSE_CHUNK:
			if(parser->http_data == NULL){
				parser->http_data = (void*) buffer;
				parser->http_data_size = (size_t) diff;
				printf("\t Setting Chunk : \n%.*s\n", (int) diff, (char*) parser->http_data);
			}
			else{
				parser->http_data_size += (size_t) diff;
				printf("Updating Chunk : \n%.*s\n", (int) diff, (char*) parser->http_data);
			}
			
		break;
		default:
		break;
	}
	return (size_t)diff;
}


static int on_body(llhttp_t* parser,const char* at, long unsigned int length) {
	printf("Analysing Body ...(%p, %ld)\n", at, length);
	ODB_Http* ctx = (ODB_Http*)parser->data;
	if(ctx == NULL || ctx->http_state == PARSE_CHUNK) return 0;

	if(ctx->http_data == NULL){
		ctx->http_data = (void*) at;
		ctx->http_data_size = length;
	}
	else{
		ctx->http_data_size += length;
	}
	printf("\tTotal Parsed Body is : %.*s\n", (int) ctx->http_data_size, (char*) ctx->http_data);
	printf("\tTotal Body length : %ld\n", ctx->http_data_size);
	//print_parser(parser);
	return 0;
}

// to fusion each chunk as body
static int chunk_count = 1;
static int on_chunk_header(llhttp_t* parser) {
	(void) parser;
	ODB_Http* ctx = (ODB_Http*)parser->data;
	ctx->http_state = PARSE_CHUNK;
	printf("Chunk %d begin\n",chunk_count);
	return HPE_PAUSED;
}

// to fusion each chunk as body
static int on_chunk_complete(llhttp_t* parser) {
	(void) parser;
	printf("Chunk %d complete\n",chunk_count++);
	return HPE_PAUSED;
}

*/