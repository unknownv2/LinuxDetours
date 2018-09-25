UNAME := $(shell uname)
UNAME_M := $(shell uname -m)

CXX = clang++
CXX_FLAGS =  -Wall -Wno-null-conversion -std=c++11 -g -O0 -fno-omit-frame-pointer -fPIC -shared
CXX_DEFINES = -lpthread -ldl -lglog 

SOURCES = barrier.cpp detours.cpp disasm.cpp plthook_elf.cpp

TRAMPOLINE_ARM = trampoline_arm.cpp
TRAMPOLINE_X86 = trampoline_x86.cpp

LIB_NAME = libcorehook

.PHONY: linux_arm64 linux_arm64 linux_x64 macos_x64

all:
ifeq ($(UNAME),Darwin)
	$(MAKE) macos_x64
else
    ifeq ($(UNAME_M),x86_64)
		$(MAKE) linux_x64
    else ifneq (,$(findstring arm,$(UNAME_M)))
		$(MAKE) linux_arm
    else
		$(MAKE) linux_arm64
    endif
endif

linux_x64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) $(SOURCES) $(TRAMPOLINE_X86) -D_ADM64_ -D_UNIX64 -o $(LIB_NAME)64.so	
linux_arm:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) $(SOURCES) $(TRAMPOLINE_ARM) -mcpu=cortex-a5 -D_ARM_ -D_ARM32_ -o $(LIB_NAME)32.so
linux_arm64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) $(SOURCES) $(TRAMPOLINE_ARM) -D _ARM64_ -D _UNIX64 -o $(LIB_NAME)64.so
macos_x64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) $(SOURCES) $(TRAMPOLINE_X86) -D_ADM64_ -D_UNIX64 -o $(LIB_NAME)64.dylib

clean:
ifeq ($(UNAME),Darwin)
	rm -f $(LIB_NAME)64.dylib
else
    ifneq (,$(findstring arm,$(UNAME_M)))
			rm -f $(LIB_NAME)32.so			
    else 
			rm -f $(LIB_NAME)64.so
    endif	
endif

