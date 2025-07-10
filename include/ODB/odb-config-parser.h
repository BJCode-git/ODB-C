#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <ODB/odb.h>

#ifndef ODB_CONF_PATH
	#define ODB_CONF_PATH "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/config/ODB.conf"
#endif

// get env 
// getenv( "ODB_CONF_PATH" );

void load_ODB_config(ODB_Config *config);
const char* strategy_to_string(ODB_Remote_Error_Policy strategy);

#endif // CONFIG_PARSER_H