# TOTP Authenticator

## What
Sample TOTP Authenticator using CryptoPP and SFML using vcpkg

## Why
I want to build my own Google Authenticator, because last I heard Google no longer maintains it.

## How
This project comes with 2 CMake presets: `vs2022` and `ninja-msvc64-rel`

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
