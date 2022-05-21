//
// Created by azzentys on 5/21/22.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include "file_ops.h"

///
/// \param path File for which path to be made
/// \example mkpath("/tmp/a/b/c") -> creates /tmp/a/b
/// \return 0 on success
int mkpath (const char *path)
{
    char working_path[PATH_MAX] = {0};
    for (int i = 0; i < strnlen(path, PATH_MAX); i++) {
        if (path[i] == '/') {
            strncpy(working_path, path, i + 1);
            struct stat test;
            if (stat(working_path, &test) == -1 && errno == ENOENT) {
                mkdir(working_path, 0777);
            }
        } else {
            continue;
        }
    }
    return 0;
}

///
/// \param src The file to copy
/// \param dest The path at which file to be copied, this should be a defined path
/// \return 0 on success, -1 on error with printed error message on stdout
int copy_file(char *src, char *dest)
{
    int src_fd = open(src, O_RDONLY);
    int dest_fd = creat(dest, 0777);
    char read_buf = 0;
    while(read(src_fd, &read_buf, 1) == 1) {
        if (write(dest_fd, &read_buf, 1) != 1) {
            perror("ERR: write");
            return -1;
        }
    }
    close(src_fd);
    close(dest_fd);
    return 0;
}