TARGET_LIB=libmesploit.a
OBJS = imports.o mesploit.o

INCDIR =
CFLAGS = -std=c99 -O2 -G0 -Wall -Wno-strict-aliasing
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS	= $(CFLAGS)

LIBDIR =
LIBS = 
LDFLAGS	=

PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak