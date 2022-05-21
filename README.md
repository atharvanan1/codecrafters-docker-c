This is a starting point for C solutions to the
["Build Your Own Docker" Challenge](https://codecrafters.io/challenges/docker).

In this challenge, you'll build a program that can pull an image from
[Docker Hub](https://hub.docker.com/) and execute commands in it. Along the way,
we'll learn about [chroot](https://en.wikipedia.org/wiki/Chroot),
[kernel namespaces](https://en.wikipedia.org/wiki/Linux_namespaces), the
[docker registry API](https://docs.docker.com/registry/spec/api/) and much more.

**Note**: If you're viewing this repo on GitHub, head over to
[codecrafters.io](https://codecrafters.io) to signup for early access.

# Building

```bash
cmake -S . -B build
cmake --build build
```

# Running

```bash
$ ./build/codecrafters-docker-c run <image>:<digest> <command> 
```