#include <cstdio>
#include "detours.h"

int main()
{
    printf("hello from LinuxDetours!\n");
	LhInstallHook(NULL, NULL, NULL, NULL);
    return 0;
}