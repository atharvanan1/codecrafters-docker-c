cmake_minimum_required(VERSION 3.22)
project(codecrafters_docker_c C)

set(CMAKE_CONFIGURATION_TYPES Debug Release)
set(CMAKE_C_STANDARD 11)

include_directories(app)

add_executable(codecrafters_docker_c
        app/cJSON.c
        app/cJSON.h
        app/main.c
        app/registry_ops.c
        app/registry_ops.h
        app/logger.c
        app/logger.h
        app/file_ops.c
        app/file_ops.h)

target_compile_definitions(codecrafters_docker_c PUBLIC
        _GNU_SOURCE)

target_link_libraries(codecrafters_docker_c
        curl)
