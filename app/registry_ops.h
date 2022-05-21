//
// Created by azzentys on 5/21/22.
//

#ifndef CODECRAFTERS_DOCKER_C_REGISTRY_OPS_H
#define CODECRAFTERS_DOCKER_C_REGISTRY_OPS_H

#define DOCKER_PERSIST "/tmp/codecrafters-docker"

int pull_image(char *image, char *dirname);

#endif //CODECRAFTERS_DOCKER_C_REGISTRY_OPS_H
