cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

project(totp-auth CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(SFML COMPONENTS system window graphics CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)

add_executable(${PROJECT_NAME} WIN32
  src/main.cpp
  src/totp.h
)
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    sfml-system sfml-graphics sfml-window sfml-main
    cryptopp-static
)

# Copy static resources
file(COPY "res/fonts/RobotoMono-Regular.ttf" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/res/fonts")

set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})