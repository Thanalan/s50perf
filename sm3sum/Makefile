# Makefile of sm3sum

CC ?= gcc
# CFLAGS += -Wall -Wextra -Werror -g -O2 # -DDEBUG
CFLAGS += -Wall -g -O2 # -DDEBUG
# CFLAGS += -Wall -Werror -g -DDEBUG
LIBS += -lcrypto_soft -pthread
HEADERS = sm3.h unit_test.h
OBJECTS = sm3sum.o sm3.o file_handler.o

default: sm3sum

%.o: %.c $(HEADERS)
	${CC} -c $< ${CFLAGS} $(LIBS) -o $@

sm3sum: $(OBJECTS)
	${CC} ${OBJECTS} ${CFLAGS}  $(LIBS) -o $@

clean:
	rm *.o
	rm sm3sum
