#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sched.h>
#include "file_ops.h"
#include "registry_ops.h"
#include "logger.h"

#define DOCKER_TEMPDIR "/tmp/codecrafters-docker/docker.XXXXXX"

///
/// \brief Runs the command after forking from main process with separate PID namespace and chroot
///        as the rootfs_path
/// \param rootfs_path Path to running rootfs directory
/// \param command Command to execute
/// \param cmd_argv Rest of the command
/// \return Return code for running command
int run_docker(char *rootfs_path, char *command, char **cmd_argv)
{
    int dockerpipefd[2];
    int proc_retcode = 0;
    pipe(dockerpipefd);
    int unshare_status = unshare(CLONE_NEWPID | CLONE_NEWNS);
    if (unshare_status == -1) {
        log_msg(ERR, "unshare: %s", strerror(errno));
        return 1;
    }

    int child_pid = fork();
    if (child_pid == -1) {
        log_msg(ERR, "fork: %s", strerror(errno));
        return 1;
    }

    if (child_pid == 0) {
        close(dockerpipefd[0]); // Close the read end
        dup2(1, dockerpipefd[1]);  // Pipe stdout to pipefd write end
        dup2(2, dockerpipefd[1]);  // Pipe stderr to pipefd read end
        chdir(rootfs_path);
        chroot(rootfs_path);
        execvp(command, cmd_argv);  // Replace current program with calling program
        log_msg(ERR, "execvp: %s", strerror(errno));
        return -1;
    } else {
        // We're in parent
        close(dockerpipefd[1]);  // Close the write end
        // Read from the file
        char read_buf[1];
        while (read(dockerpipefd[0], read_buf, 1) > 0) {
            write(1, read_buf, 1);
        }
        close(dockerpipefd[0]);
        // Wait for child to close
        int child_retcode = 0;
        int proc_id = wait(&child_retcode);
        proc_retcode = WEXITSTATUS(child_retcode);
        // Delete temporary run directory
        rmdir(rootfs_path);
    }

    return proc_retcode;
}

// Usage: your_docker.sh run <image> <command> <arg1> <arg2> ...
int
main(int argc, char *argv[])
{
    // Disable output buffering
    setbuf(stdout, NULL);

    // Set directories
    mkpath(DOCKER_PERSIST);
    mkdir(DOCKER_PERSIST, 0777);
    char template[] = DOCKER_PERSIST \
                      "/docker.XXXXXX";
    char *rootfs_path = mkdtemp(template);
    chmod(rootfs_path, 0644);
    log_msg(DBG, "Rootfs Path: %s", rootfs_path);

    // Grab key arguments
    char *image = argv[2];
    char *command = argv[3];

    int pull_res = pull_image(image, rootfs_path);
    if (pull_res < 0) {
        log_msg(ERR, "Failed to pull image");
        return -1;
    }

    return run_docker(rootfs_path, command, &argv[3]);
}
