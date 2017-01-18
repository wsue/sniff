#toolchains/x86-4.9/prebuilt/linux-x86_64/bin/i686-linux-android-gcc
export NDK=/opt/android/android-ndk-r13/
export NDK_TOOLCHAIN=${NDK}/toolchains/x86-4.9/prebuilt/linux-x86/bin/i686-linux-android-
export NDK_SYSROOT=${NDK}/platforms/android-23/arch-x86

make -f Makefile_gcc clean
make -j16 -f Makefile_gcc 
