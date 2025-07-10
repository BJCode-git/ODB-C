#include <ODB/odb.h>
#include <ODB/odb-utils.h>
#include <ODB/odb-http.h>



static ODB_Http 		 *current_ODB_http_parser = NULL;
static llhttp_settings_t ODB_http_settings		 = {};
static pthread_mutex_t	 ODB_http_parser_mutex	 = PTHREAD_MUTEX_INITIALIZER;


#define lock_ODB_http_mutex() pthread_mutex_lock(&ODB_http_parser_mutex)

#define unlock_ODB_http_mutex() pthread_mutex_unlock(&ODB_http_parser_mutex)


static int handle_on_header_complete(llhttp_t* parser){
	(void)parser;

	if(current_ODB_http_parser == NULL) return 0;
	
	// save the pointer to first byte of the body (following the header)
	current_ODB_http_parser->http_data		= (void*) llhttp_get_error_pos(parser) + 1;
	current_ODB_http_parser->content_length = parser->content_length;
	current_ODB_http_parser->http_state 	= current_ODB_http_parser->content_length >= (size_t) VIRTUAL_THRESHOLD ? SEND_HTTP_VIRTUAL : SEND_HTTP_REAL;
	return 0;
}

static int handle_on_message_complete(llhttp_t* parser) {
	DEBUG_LOG("Message complete");
	(void) parser;
	if(current_ODB_http_parser == NULL) return 0;
	// update ODB parser state
	current_ODB_http_parser->http_state = HTTP_NONE;
	return 0;
}

static void init_http_setting(){
	static uint8_t is_iniated = 0;

	if(is_iniated == 0){
		llhttp_settings_init(&ODB_http_settings);
		/*Set ODB callbacks */
		ODB_http_settings.on_message_complete = handle_on_message_complete;
		ODB_http_settings.on_headers_complete = handle_on_header_complete;
		is_iniated = 1;
	}
}

void ODB_http_init(ODB_Http *parser){

	if(parser == NULL) return;

	if(parser->http_state != HTTP_NONE){
		llhttp_reset(&parser->http_parser);
		return;
	}

	/*Initialize settings */
	init_http_setting();


	/*Initialize the parser in HTTP_BOTH mode, meaning that it will select between
	*HTTP_REQUEST and HTTP_RESPONSE parsing automatically while reading the first
	*input.
	*/
	llhttp_init(&parser->http_parser, HTTP_BOTH, &ODB_http_settings);
}


size_t ODB_http_parse(ODB_Http *parser, const void* buffer, size_t buf_len){

	if(parser == NULL || buffer == NULL || buf_len == 0) return 0;
	parser->http_data = NULL;

	lock_ODB_http_mutex();
		current_ODB_http_parser = parser;
		parser->http_data = (void*) buffer;

		llhttp_errno_t err = llhttp_execute(&parser->http_parser, buffer,buf_len);
		switch(err){
			case HPE_OK:
				parser->http_state = HTTP_NONE;
			break;
			case HPE_PAUSED:
				llhttp_resume(&parser->http_parser);
			break;
			case HPE_PAUSED_UPGRADE:
				llhttp_resume_after_upgrade(&parser->http_parser);
			break;
			default:
				parser->http_state = HTTP_NONE;
				DEBUG_LOG("error : %s , %s",llhttp_errno_name(err),llhttp_get_error_reason(&parser->http_parser));
			break;
		}

		// compute body len part in the buffer for the current header (in case buffer contain header + part of the body)
		// note : We could consider that the buffer contains several headers/bodies
		parser->local_data_size = buf_len - (size_t) ( (const ptrdiff_t) (void*) llhttp_get_error_pos(&parser->http_parser) - (const ptrdiff_t) buffer);
		current_ODB_http_parser = NULL;
	unlock_ODB_http_mutex();
	
	return 0;
}

 
/*
size_t ODB_http_parsed_bytes(ODB_Http *parser,const char *original_buffer){
	if(parser == NULL || original_buffer == NULL) return 0;
	const char *last_bytes_parsed = llhttp_get_error_pos(&parser->http_parser);
	const ptrdiff_t bytes_parsed = (const ptrdiff_t) last_bytes_parsed - (const ptrdiff_t) original_buffer;
	if(bytes_parsed < 0) return 0;
	return (size_t) bytes_parsed;
}

*/