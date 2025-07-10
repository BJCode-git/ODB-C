#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
// include networking
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef ODB_CONF_PATH
	#define ODB_CONF_PATH "/home/julien/Cours/Cours3A/Stage3A/Dev/ODBc-Project/NEWODB/config/ODB.conf"
	//#define ODB_CONF_PATH "/etc/ODB/odb.conf"
#endif

#ifndef DEFAULT_COUNTDOWN
    #define DEFAULT_COUNTDOWN 1000
#endif
#ifndef MAX_PORTS
    #define MAX_PORTS 16
#endif
#ifndef MAX_LINE_LENGTH
    #define MAX_LINE_LENGTH 256
#endif

typedef enum {
    ABORT=0,
    CORRUPT,
    BEST_EFFORT,
    FAKE_SEND
} ODB_Remote_Error_Policy;

typedef enum {
    PASS_THROUGH=0,
    VIRTUAL
} ODB_Sendfile_From_Sock_Policy;

typedef struct {
    uint16_t                        no_odb_ports[MAX_PORTS];
    uint8_t                         n_ports;
    int8_t                          corrupt_value;
    ODB_Remote_Error_Policy         r_err_strat;
    ODB_Sendfile_From_Sock_Policy   sf_so_strat;
    uint16_t                        ms_countdown;
    struct sockaddr_in              ODB_serv_addr;
} ODB_Config;


const char* strategy_to_string(ODB_Remote_Error_Policy s) {
    switch (s) {
        case ABORT: return "on_sigsev_abort";
        case CORRUPT: return "on_sigsev_corrupt_data";
        case BEST_EFFORT: return "best_effort";
        case FAKE_SEND: return "fake_sending";
        default: return "unknown";
    }
}

// Parseurs
static ODB_Remote_Error_Policy parse_remote_strategy(const char *value) {
    if (strcmp(value, "on_sigsev_abort") == 0) return ABORT;
    if (strcmp(value, "on_sigsev_corrupt_data") == 0) return CORRUPT;
    if (strcmp(value, "best_effort") == 0) return BEST_EFFORT;
    if (strcmp(value, "fake_sending") == 0) return FAKE_SEND;
    return BEST_EFFORT;  // Valeur par défaut raisonnable
}

static ODB_Sendfile_From_Sock_Policy parse_sendfile_strategy(const char *value) {
    if (strcmp(value, "pass_through") == 0) return PASS_THROUGH;
    if (strcmp(value, "virtual") == 0) return VIRTUAL;
    return PASS_THROUGH;
}

// Fonction de chargement
static void printf_config(ODB_Config *config) {
    printf("ODB ports to ignore: ");
    for (int i = 0; i < config->n_ports; i++) {
        printf("%d ", config->no_odb_ports[i]);
    }
    printf("\n");
    printf("ODB remote error strategy: %s\n", strategy_to_string(config->r_err_strat));
    printf("ODB corrupt value: %d\n", config->corrupt_value);
    printf("ODB countdown: %d\n", config->ms_countdown);
    printf("ODB server address: %s:%d\n", inet_ntoa(config->ODB_serv_addr.sin_addr), ntohs(config->ODB_serv_addr.sin_port));
}
void load_ODB_config(ODB_Config *config) {
    if (!config) return;

    // Valeurs par défaut
    //*config = ODB_Config_INITIALIZER;

    //DEBUG_LOG("Loading ODB config...");

    const char *filename = getenv("ODB_CONF_PATH");
    FILE *fp = NULL;

    if (filename) fp = fopen(filename, "r");
    else{
		printf("ODB_CONF_PATH env not found.\n");
		fp = fopen(ODB_CONF_PATH, "r");
	}

    if (!fp){
        printf("ODB config file not found. Using default values.\n");
        return;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), fp)) {

        // Ignore comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = strtok(line, " \t\n");
        char *value = strtok(eq + 1, "\n");

        if (!key || !value) continue;

        while (isspace((unsigned char)*value)) value++;

        if (strcmp(key, "ports") == 0) {
            config->n_ports = 0;
            char *token = strtok(value, " \t");
            while (token && config->n_ports < MAX_PORTS) {
                config->no_odb_ports[config->n_ports++] = (uint16_t)atoi(token);
                token = strtok(NULL, " \t");
            }
        } else if (strcmp(key, "remote-error-strategy") == 0) {
            config->r_err_strat = parse_remote_strategy(value);
        } else if (strcmp(key, "sendfile-from-socket") == 0) {
            config->sf_so_strat = parse_sendfile_strategy(value);
        } else if (strcmp(key, "corrupt-value") == 0) {
            config->corrupt_value = (int8_t)atoi(value);
        } else if (strcmp(key, "countdown") == 0) {
            config->ms_countdown = (uint16_t)atoi(value);
        } else if (strcmp(key, "server-ip") == 0) {
            memset(&config->ODB_serv_addr, 0, sizeof(config->ODB_serv_addr));
            config->ODB_serv_addr.sin_family = AF_INET;
            // define a random port between 49152 and 65535
            config->ODB_serv_addr.sin_port = htons((rand() % (65535 - 49152 + 1)) + 49152);
            inet_pton(AF_INET, value, &config->ODB_serv_addr.sin_addr);
        } else if (strcmp(key, "server-port") == 0) {
            config->ODB_serv_addr.sin_port = htons((uint16_t)atoi(value));
        }
    }

    //DEBUG_LOG("ODB config loaded !");
    //printf_config(config);

    fclose(fp);
}

int main() {
	ODB_Config config = {.no_odb_ports={80},.n_ports=1,.corrupt_value=-1,.r_err_strat=0,.sf_so_strat=1,.ms_countdown=DEFAULT_COUNTDOWN,.ODB_serv_addr={0}};
	load_ODB_config(&config);
	printf_config(&config);
	return 0;
}