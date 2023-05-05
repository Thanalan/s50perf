


# CFLAGS += $(shell pkg-config --cflags libcrypto-soft)
# LIBS += $(shell pkg-config --libs libcrypto-soft)

#also


INCLUDE_DIR?=../include
TARGET_LIB_DIR?=../lib
CFLAGS += -I$(INCLUDE_DIR)  -O2 -g -Wno-int-conversion  -Wno-pointer-sign 
CFLAGS += $(shell pkg-config --cflags libpce)

LIBS += -L$(TARGET_LIB_DIR) -lpthread 
LIBS += $(shell pkg-config --libs libpce)
TARGET_BIN_DIR?=.
SRC=$(wildcard *.c  )
OBJS=$(patsubst %.c, %.o, $(SRC))

$(TARGET_BIN_DIR)/perf: $(OBJS)
	$(CC)  $(OBJS) -o $@ $(CFLAGS) $(LIBS) 

%.o: %.c
	$(CC)  -c  $< -o  $@   $(CFLAGS)  

clean:
	@rm -fr $(OBJS) $(TARGET_BIN_DIR)/perf
