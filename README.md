# Linux Detours

The [Microsoft Detours](https://github.com/Microsoft/Detours) library combined with the [EasyHook](https://github.com/EasyHook/EasyHook) C module thread barrier implementation and modified to work on Linux with support for X64, ARM (supports both ARM32 and Thumb instructions), and ARM64 architectures.


## Dependencies

### [Google Logging Module - glog](https://github.com/google/glog)

You can install it by running:

```
sudo apt-get install libgoogle-glog-dev
```

## Build

### LinuxDetours - Application
You can use Visual Studio to build the `LinuxDetours` application after configuring the project to connect to your Linux system.

### libdetours - Shared Library (*.so, *.dylib)

You can use the [`makefile`](LinuxDetours/Makefile) to build the shared library. The makefile outputs `libdetours32` for ARM and `libdetours64` for X64 and ARM64 in the `LinuxDetours` source directory.

```
git clone https://github.com/unknownv2/LinuxDetours.git
cd LinuxDetours
make -C LinuxDetours
```