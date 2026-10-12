cmake_minimum_required(VERSION 3.20)
project(cpp-hashlib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(hashlib src/md5/compress.cpp)
target_include_directories(hashlib PUBLIC include)

add_subdirectory(tests)
add_subdirectory(experiments/architecture-study)