//
// Created by azzentys on 5/21/22.
//
#include <stdarg.h>
#include <stdio.h>
#include "logger.h"

// Character codes for colors
// Leveraged Code - https://stackoverflow.com/questions/3585846/color-text-in-terminal-applications-in-unix
const char* red = "\x1B[31m";
const char* yellow = "\x1B[1;33m";
const char* blue = "\x1B[34m";
const char* end = "\x1B[0m";

void log_msg(LogLevel level, const char *msg, ... )
{
    // To process variable argument list
    va_list args;
    va_start(args, msg);

    // Activate color based on message type
    switch(level)
    {
        case INFO:
            printf("INFO: ");
            break;
#ifdef DEBUG
        case DBG:
            printf("%s", blue);
            printf("DBG:  ");
            break;
#endif
        case WARN:
            printf("%s", yellow);
            printf("WARN: ");
            break;
        case ERR:
            printf("%s", red);
            printf("ERR:  ");
            break;
        default:
            return;
    }

    // Message print with color termination code
    vprintf(msg, args);
    printf("%s\n", end);
}
