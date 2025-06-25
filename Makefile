CC=gcc
CFLAGS=-Wall -Wextra -Werror -pthread #-pedantic
LDFLAGS=-pthread
VALGRIND=valgrind --tool=memcheck --track-origins=yes --show-leak-kinds=all --errors-for-leak-kinds=all --read-var-info=yes --leak-check=full --verbose  
BIN_DIR=bin
LIB_DIR=lib
INCLUDE_DIR=include
SRC_DIR=src
ODB_SRC= $(wildcard $(SRC_DIR)/ODB/*.c)
DEBUG_DIR=debug
TEST_DIR=unit-tests
RESULTS_DIR=results
SERV_DIR=server

#LIBNAMES
HTTP_LIB=$(LIB_DIR)/libhttp.a
IT_LIB=$(LIB_DIR)/libiterator.a
ODB_LIB=$(LIB_DIR)/libnewodb.so
FE_LIB=$(LIB_DIR)/libFE_odb.so
IS_LIB=$(LIB_DIR)/libIS_odb.so
BE_LIB=$(LIB_DIR)/libBE_odb.so

USE_ODB?=1
USE_STANDALONE?=1
USE_EQU_ALIGN?=0
USE_SENDFILE?=0
##define for using ASAN
USE_ASAN?= 0


##define for static test server configuration
#define if we want to stop after one query and answer
ONE_SHOT?=1
NB_IT?=1
# define if buffer should be equally aligned or not
EQU_ALIGN?=0
RAB_ALIGN?=1
# define buffer size for FE and IS
BUFF_SIZE?=16384
#32768

##define for libnewodb.so
DEBUG?=1

##define for test server dynamic execution
#define how many bytes to receive
QUERY_BYTES?=$(BUFF_SIZE)
#define what type of data to receive
TYPE?="txt"
FE_PORT?=10000
BE_PORT?=10001
IS_BEGIN_PORT?=10002
OUT_PORT?=$(BE_PORT)


#SERV_DEF=-DONE_SHOT=$(ONE_SHOT)  -DEQU_ALIGN=$(EQU_ALIGN) -DRAB_ALIGN=$(RAB_ALIGN)

ifeq ($(DEBUG),1)
	CFLAGS+= -g
endif


ifeq ($(USE_ASAN), 1)
	CFLAGS+=-fsanitize=address -fno-omit-frame-pointer -g
	ASAN_OPTIONS="ASAN_OPTIONS=detect_leaks=1:fast_unwind_on_malloc=0:strict_string_checks=true:verbosity=1:detect_stack_use_after_return=1:track_origins=1:print_stats=1:atexit=1:debug=1:abort_on_error=0"
	ASAN_LIB := $(shell $(CC) -print-file-name=libasan.so):
else
	ASAN_FLAGS=
	ASAN_OPTIONS=
	ASAN_LIB=
endif

all: $(ODB_LIB)

# Crée le dossier bin si nécessaire
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

#Crée le dossier lib si nécessaire
$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(RESULTS_DIR):
	mkdir -p $(RESULTS_DIR)

#Crée le dossier debug si nécessaire
$(DEBUG_DIR):
	mkdir -p $(DEBUG_DIR)


################## Compilation des librairies  ##################

$(IT_LIB):  $(LIB_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -fPIC -c $(SRC_DIR)/iterator.c -o $(LIB_DIR)/iterator.o
	ar rcs $@ $(LIB_DIR)/iterator.o
	rm -f $(LIB_DIR)/iterator.o

$(HTTP_LIB):  $(LIB_DIR)
	cp external/llhttp/build/libllhttp.a $(LIB_DIR)/libllhttp.a
	cp external/llhttp/build/libllhttp.so $(LIB_DIR)/libllhttp.so


################## Compilation des librairies ODB ##################

$(ODB_LIB): clean-lib $(LIB_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -shared -fPIC -ldl -rdynamic $(ODB_SRC)  -DEQU_ALIGN=$(USE_EQU_ALIGN) -DODB=$(USE_ODB) -DDEBUG=$(DEBUG) -DODB_STANDALONE=$(USE_STANDALONE) -o $(ODB_LIB)
$(FE_LIB): clean-lib $(LIB_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -shared -fPIC -ldl -rdynamic $(ODB_SRC)  -DEQU_ALIGN=$(USE_EQU_ALIGN) -DODB=$(USE_ODB) -DDEBUG=$(DEBUG) -DODB_STANDALONE=$(USE_STANDALONE) -DLOG_STATUS=\"FRONT_END\" -o $(FE_LIB)
$(IS_LIB): clean-lib $(LIB_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -shared -fPIC -ldl -rdynamic $(ODB_SRC)  -DEQU_ALIGN=$(USE_EQU_ALIGN) -DODB=$(USE_ODB) -DDEBUG=$(DEBUG) -DODB_STANDALONE=$(USE_STANDALONE) -DLOG_STATUS=\"INTERMEDIATE_SERVER\" -o $(IS_LIB)
$(BE_LIB): clean-lib $(LIB_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -shared -fPIC -ldl -rdynamic $(ODB_SRC)  -DEQU_ALIGN=$(USE_EQU_ALIGN) -DODB=$(USE_ODB) -DDEBUG=$(DEBUG) -DODB_STANDALONE=$(USE_STANDALONE) -DLOG_STATUS=\"BACK_END\" -o $(BE_LIB)

################## Compilation des Tests ##################

test-iterator: $(BIN_DIR) $(IT_LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-iterator $(TEST_DIR)/test-iterator.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-iterator

test-serialisation: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-serialize $(TEST_DIR)/test-serialize.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-serialize

test-buffer-parts: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-buffer-parts $(TEST_DIR)/test-buffer-parts.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-buffer-parts

test-mprotect: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-mprotect $(TEST_DIR)/test-mprotect.c $(SRC_DIR)/newodb.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-mprotect

test-search-desc: $(BIN_DIR) $(IT_LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-search-desc $(TEST_DIR)/test-search-desc.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-search-desc

test-get-remote: clean-debug $(BIN_DIR) $(DEBUG_DIR) 
	ls $(LIB_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-get-remote $(TEST_DIR)/test-get-remote.c $(SRC_DIR)/newodb.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-get-remote

test-get-on-fault: clean-debug $(BIN_DIR) $(DEBUG_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-get-on-fault $(TEST_DIR)/test-get-on-fault.c $(SRC_DIR)/newodb.c $(SRC_DIR)/newutils.c -L$(LIB_DIR) -literator
	chmod +x $(BIN_DIR)/test-get-on-fault

test-http: $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-http $(TEST_DIR)/test-http.c -L$(LIB_DIR) -lllhttp -Wl,-rpath,$(LIB_DIR)
	chmod +x $(BIN_DIR)/test-http

test-fork: $(BIN_DIR) $(ODB_LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-fork $(TEST_DIR)/test-fork.c
	chmod +x $(BIN_DIR)/test-fork

test-conf:
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(BIN_DIR)/test-conf $(TEST_DIR)/test-conf.c
	chmod +x $(BIN_DIR)/test-conf

################## Execution des Tests ##################

run-test-iterator: test-iterator
	./$(BIN_DIR)/test-iterator

run-test-serialisation:test-serialisation
	./$(BIN_DIR)/test-serialize

run-test-buffer-parts:test-buffer-parts
	./$(BIN_DIR)/test-buffer-parts

run-test-mprotect: test-mprotect
	./$(BIN_DIR)/test-mprotect

run-test-search-desc: test-search-desc
	./$(BIN_DIR)/test-search-desc

run-test-get-remote: test-get-remote
	./$(BIN_DIR)/test-get-remote

run-test-get-on-fault: test-get-on-fault
	./$(BIN_DIR)/test-get-on-fault

run-test-http: test-http
	./$(BIN_DIR)/test-http

run-test-fork: test-fork
	LD_PRELOAD=$(ODB_LIB) ./$(BIN_DIR)/test-fork

run-test-conf: test-conf
#export ODB_CONF_PATH=$(pwd)/config/ODB.conf
	./$(BIN_DIR)/test-conf

run-all-tests: run-test-iterator run-test-serialisation run-test-buffer-parts run-test-mprotect run-test-search-desc run-test-get-remote test-get-on-fault

################## Server Tests ##################

## Compilation

back-end: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -pedantic -o $(BIN_DIR)/back-end $(SERV_DIR)/back-end.c $(SRC_DIR)/ODB/odb-utils.c $(SRC_DIR)/ODB/odb.c -DUSE_SENDFILE=$(USE_SENDFILE) -DONE_SHOT=$(ONE_SHOT) -DEQU_ALIGN=$(EQU_ALIGN) $(LDFLAGS) -L$(LIB_DIR)
	chmod +x $(BIN_DIR)/back-end

inter: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -pedantic -o $(BIN_DIR)/inter $(SERV_DIR)/inter.c $(SRC_DIR)/ODB/odb-utils.c $(SRC_DIR)/ODB/odb.c -DUSE_SENDFILE=$(USE_SENDFILE) -DONE_SHOT=$(ONE_SHOT) -DEQU_ALIGN=$(EQU_ALIGN)  -DBUFSIZE=$(BUFF_SIZE) $(LDFLAGS) -L$(LIB_DIR)
	chmod +x $(BIN_DIR)/inter

front-end: $(BIN_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -pedantic -o $(BIN_DIR)/front-end $(SERV_DIR)/front-end.c $(SRC_DIR)/ODB/odb-utils.c $(SRC_DIR)/ODB/odb.c -DUSE_SENDFILE=$(USE_SENDFILE) -DONE_SHOT=$(ONE_SHOT) -DEQU_ALIGN=$(EQU_ALIGN) -DBUFSIZE=$(BUFF_SIZE) $(LDFLAGS) -L$(LIB_DIR) 
	chmod +x $(BIN_DIR)/front-end

front-end-test: $(BIN_DIR) $(SERV_DIR)/front-end-test.c $(SERV_DIR)/server.h 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -pedantic -o $(BIN_DIR)/front-end-test $(SERV_DIR)/front-end-test.c $(LDFLAGS)
	chmod +x $(BIN_DIR)/front-end-test

java-server:
	javac $(SERV_DIR)/Java/*.java 


# Execution des Serveurs

run-front-end: clean-debug $(DEBUG_DIR) $(RESULTS_DIR) $(FE_LIB) front-end
	LD_PRELOAD=$(ASAN_LIB)./$(FE_LIB) $(ASAN_OPTIONS) \
	./$(BIN_DIR)/front-end -i 127.0.0.1 -l $(FE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -t $(TYPE) -b $(QUERY_BYTES) \
	cmp $(RESULTS_DIR)/answer.save $(RESULTS_DIR)/original_data.save

run-inter: clean-debug $(DEBUG_DIR) $(RESULTS_DIR) $(IS_LIB) inter
	LD_PRELOAD=$(ASAN_LIB)./$(IS_LIB) $(ASAN_OPTIONS) \
	./$(BIN_DIR)/inter -i 127.0.0.1 -l $(IS_BEGIN_PORT) -d 127.0.0.1 -p $(BE_PORT) -b $(QUERY_BYTES)

# Règle pattern : run-interX (où X est un nombre)
run-inter%: $(DEBUG_DIR) $(RESULTS_DIR) $(IS_LIB) inter
	@echo "Launching intermediate server $*..."
	$(eval IS_PORT_IN=$(shell echo $(IS_BEGIN_PORT) + $* - 1 | bc))
	$(eval IS_PORT_OUT=$(shell echo $(IS_BEGIN_PORT) + $* -1 + 1 | bc))
	LD_PRELOAD=$(ASAN_LIB)./$(IS_LIB) $(ASAN_OPTIONS) \
	./$(BIN_DIR)/inter	-i "127.0.0.1" -l $(IS_PORT_IN) -d "127.0.0.1" -p $(IS_PORT_OUT) -b $(BUFF_SIZE)

run-back-end: clean-debug $(DEBUG_DIR) $(RESULTS_DIR) $(BE_LIB) back-end
	LD_PRELOAD=$(ASAN_LIB)./$(BE_LIB) $(ASAN_OPTIONS) \
	./$(BIN_DIR)/back-end -i 127.0.0.1 -l $(BE_PORT) -d 127.0.0.1 -t $(TYPE) -p $(IS_BEGIN_PORT) -b $(BUFF_SIZE)

#run-front-end-test: front-end-test $(FE_LIB) clean-debug $(DEBUG_DIR)
#	LD_PRELOAD=./$(FE_LIB) ./$(BIN_DIR)/front-end-test -i 127.0.0.1 -l $(FE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -t $(TYPE) -b $(BUFF_SIZE)

run-java-server: clean-debug $(DEBUG_DIR) clean-results $(RESULTS_DIR)
	java server.Java.MultiTierLauncher img 1

## Execution des Serveurs sans odb
run-no-odb-fe: front-end $(FE_LIB) clean-debug $(DEBUG_DIR)
	./$(BIN_DIR)/front-end -i 127.0.0.1 -l $(FE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -t $(TYPE) -b $(QUERY_BYTES)

run-no-odb-inter: inter $(IS_LIB) clean-debug $(DEBUG_DIR)
	./$(BIN_DIR)/inter -i 127.0.0.1 -l $(IS_BEGIN_PORT) -d "127.0.0.1" -p $(BE_PORT) -b $(BUFF_SIZE)

# Règle pattern : run-interX (où X est un nombre)
run-no-odb-inter%: $(DEBUG_DIR) $(RESULTS_DIR) $(IS_LIB) inter
	@echo "Launching intermediate server $*..."
	$(eval IS_PORT_IN=$(shell echo $(IS_BEGIN_PORT) + $* | bc))
	$(eval IS_PORT_OUT=$(shell echo $(IS_BEGIN_PORT) + $* + 1 | bc))
	./$(BIN_DIR)/inter	-i "127.0.0.1" -l $(IS_PORT_IN) -d "127.0.0.1" -p $(IS_PORT_OUT) -b $(BUFF_SIZE)

run-no-odb-be: back-end $(BE_LIB) clean-debug $(DEBUG_DIR)
	./$(BIN_DIR)/back-end -i 127.0.0.1 -l $(BE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -b $(BUFF_SIZE)


## Execution avec mesure de temps cpu

cpu-run-back-end: back-end $(BE_LIB) clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	export LD_PRELOAD=./$(BE_LIB); \
	/usr/bin/time -f "user %U\nsys %S" -o results/back-end.time \
	./$(BIN_DIR)/back-end -i 127.0.0.1 -l $(BE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -b $(BUFF_SIZE) > "log/back-end.log" 2>&1 

cpu-run-inter: inter $(IS_LIB) clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	export LD_PRELOAD=$(IS_LIB); \
	/usr/bin/time -f "user %U\nsys %S" -o results/inter.time \
	./$(BIN_DIR)/inter -i 127.0.0.1 -l $(IS_BEGIN_PORT) -d 127.0.0.1 -p $(BE_PORT) -b $(QUERY_BYTES) > "log/inter.log" 2>&1

cpu-run-inter%: inter $(IS_LIB) clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	@echo "Running cpu-run-inter$*..."
	$(eval IS_PORT_IN=$(shell echo $(IS_BEGIN_PORT) + $* - 1| bc))
	$(eval IS_PORT_OUT=$(shell echo $(IS_BEGIN_PORT) + $* | bc))
	export LD_PRELOAD=$(IS_LIB); \
	/usr/bin/time -f "user %U\nsys %S" -o results/inter$*.time \
	./$(BIN_DIR)/inter	-i "127.0.0.1" -l $(IS_PORT_IN) -d "127.0.0.1" -p $(IS_PORT_OUT)  -b $(QUERY_BYTES) > "log/inter$*.log" 2>&1

cpu-run-front-end: clean-debug $(DEBUG_DIR) $(RESULTS_DIR) front-end $(FE_LIB)
	export LD_PRELOAD=$(FE_LIB);
	/usr/bin/time -f "user %U\nsys %S" -o results/front-end.time \
	./$(BIN_DIR)/front-end -i 127.0.0.1 -l $(FE_PORT) -d 127.0.0.1 -p $(IS_BEGIN_PORT) -t $(TYPE) -b $(BUFF_SIZE) > "log/front-end.log" 2>&1

## Execution sans ODB avec mesure de temps cpu 

cpu-run-no-odb-be: back-end clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	/usr/bin/time -f "user %U\nsys %S" -o results/no-odb-be.time \
	./$(BIN_DIR)/back-end -i 127.0.0.1 -l 20003 -d 127.0.0.1 -p 20002 -b $(BUFF_SIZE)

cpu-run-no-odb-inter: inter clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	/usr/bin/time -f "user %U\nsys %S" -o results/no-odb-inter.time \
	./$(BIN_DIR)/inter -i 127.0.0.1 -l 20002 -d 127.0.0.1 -p 20003 -b $(BUFF_SIZE)

cpu-run-no-odb-inter%: inter $(IS_LIB) clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	@echo "Running cpu-no-odb-run-inter$*..."
	$(eval IS_PORT_IN=$(shell echo $(IS_BEGIN_PORT) + $* - 1 | bc))
	$(eval IS_PORT_OUT=$(shell echo $(IS_BEGIN_PORT) + $* | bc))
	/usr/bin/time -f "user %U\nsys %S" -o results/inter$*.time \
	./$(BIN_DIR)/inter	-i "127.0.0.1" -l $(IS_PORT_IN) -d "127.0.0.1" -p $(IS_PORT_OUT)  -b $(QUERY_BYTES)

cpu-run-no-odb-fe: front-end clean-debug $(DEBUG_DIR) $(RESULTS_DIR)
	/usr/bin/time -f "user %U\nsys %S" -o results/no-odb-fe.time \
	./$(BIN_DIR)/front-end -i 127.0.0.1 -l 20001 -d 127.0.0.1 -p 20002 -t $(TYPE) -b $(BUFF_SIZE)

clean-debug:
	rm -rf $(DEBUG_DIR)/*

clean-results:
	rm -rf $(RESULTS_DIR)/*

clean-lib:
	rm -rf $(LIB_DIR)/*

clean-bin:
	rm -rf $(BIN_DIR)/*

# Nettoyage des fichiers générés
clean: clean-debug clean-results clean-bin clean-lib

.PHONY: run clean
