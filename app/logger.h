//
// Created by azzentys on 5/21/22.
//

#ifndef CODECRAFTERS_DOCKER_C_LOGGER_H
#define CODECRAFTERS_DOCKER_C_LOGGER_H

typedef enum LogLevel {
    INFO = 0,
    DBG,
    WARN,
    ERR,
} LogLevel;

void log_msg(LogLevel level, const char *msg, ... );

#endif //CODECRAFTERS_DOCKER_C_LOGGER_H
