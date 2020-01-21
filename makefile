all: libhttp2

INCLIDE_DIR=../../../include
INCLUDE_CCFLAG=-I$(INCLIDE_DIR)

HUFFMAN_DIR=./huffman
HUFFMAN_CCFLAG=-I$(HUFFMAN_DIR)

######################################################################
# LINUX-X86_64
PF_CC=gcc
PF_CCFLAG=-DOS_LINUX -DM_GENERIC_INT32 -m64 -fPIC -Og -Wall -gdwarf-2 
######################################################################

PROJ_CC=$(PF_CC)
PROJ_CCFLAG=$(PF_CCFLAG) $(INCLUDE_CCFLAG) $(HUFFMAN_CCFLAG) -I.

OBJECTS = http2_common.o http2_send.o http2_recv.o $(HUFFMAN_DIR)/huffman.o

clean:
	rm -f *.o *.a $(OBJECTS)

.c.o:
	$(PROJ_CC) $(PROJ_CCFLAG) -c $< -o $@

libhttp2: clean $(OBJECTS)
	ar -r libhttp2.a $(OBJECTS)

test: libhttp2 tcpclient_http2.o
	$(PROJ_CC) -m64 -pthread -o test tcpclient_http2.o libhttp2.a
