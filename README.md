# TOTP Authenticator

## What
Sample TOTP Authenticator using CryptoPP and SFML

![screenshot](https://github.com/tntxtnt/totp-auth/blob/master/img/screenshot.png)

## Why
I want to build my own Google Authenticator, because last I heard Google no longer maintains it.

## How
This project comes with 4 CMake presets: `vs2022`, `ninja-msvc64-rel`, `ninja-msys2-rel`, and `ninja-multiconfig-manjaro-vcpkg`

### Using MSVC
Configure (in project directory):
```
cmake --preset=vs2022
```
Then open `totp-auth.sln`, build and run from VS 2022

If you run directy from `totp-auto.exe`, use `ninja-msvc64-rel` preset:
```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake --preset=ninja-msvc64-rel
cmake --build --preset=ninja-msvc64-rel
```

### Using MSYS2
If you don't have MSVC, use `ninja-msys2-rel` is easy. First install SFML and Crypto++ from MSYS2 shell (I use 64-bit MinGW):
```
pacman -S mingw-w64-x86_64-sfml mingw-w64-x86_64-crypto++
```
It's better to install and use the compatible CMake `mingw-w64-x86_64-cmake` so CMake config can find correct compiler:
```
pacman -S mingw-w64-x86_64-cmake
```
Close MSYS2 shell, open MSYS2 MINGW 64-bit shell. Navigate to project folder. Configure, build, and run:
```
cmake --preset ninja-msys2-rel
cmake --build --preset ninja-msys2-rel
./build/ninja-msys2-rel/totp-auth
```

### Linux builds
```
cmake --preset ninja-multiconfig-manjaro-vcpkg
cmake --build --preset ninja-multiconfig-manjaro-vcpkg --config Release
./build/ninja-multiconfig-manjaro-vcpkg/Release/totp-auth
```
Tested on VirtualBox running Manjaro.

Bug: when the application is closed it throws segmentation fault. I don't know what is it.

## Limitations
No scrolling up/down feature. Currently you can only see top 4 TOTP.
