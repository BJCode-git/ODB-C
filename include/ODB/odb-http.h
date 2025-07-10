#ifndef ODB_HTTP_H
#define ODB_HTTP_H

#include <llhttp.h>
#include <pthread.h>


typedef enum ODB_Http_State{
	HTTP_NONE,
	SEND_HTTP_REAL,
	SEND_HTTP_VIRTUAL
} ODB_Http_State;

typedef struct ODB_Http{
	llhttp_t		http_parser;
	ODB_Http_State	http_state;
	void 			*http_data;
	size_t 			local_data_size;
	size_t 			content_length;
}ODB_Http;

//extern ODB_Http 			*current_ODB_http_parser;
//extern pthread_mutex_t		ODB_http_parser_mutex;
//extern llhttp_settings_t	ODB_http_settings;



void ODB_http_init();

// return the number of bytes parsed
size_t ODB_http_parse(ODB_Http *parser, const void* buffer, size_t buf_len);

#endif // ODB_HTTP_H