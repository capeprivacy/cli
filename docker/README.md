# EIF Builder

This can be used by the CLI to build EIFs and then compare the outputted PCRs.

## Use

### Build docker image

```
docker build -t capeprivacy/eif-builder -f docker/Dockerfile.eif_builder .
```

### Build docker image

```
docker run -v ~/.docker:/root/.docker -v /var/run/docker.sock:/var/run/docker.sock capeprivacy/eif-builder build-enclave --docker-uri docker.io/capeprivacy/runtime:release-ffc4e1c --output-file runtime.eif
```

The use should be able to be similified for ease of use in the future:

- `-v ~/.docker:/root/.docker` is required for auth. Once the image runtime images are public we can remove this requirement.
- `-v /var/run/docker.sock:/var/run/docker.sock` is required because there is not a docker daemon running in the container. We could probably
    find another solution here so that even the user doesn't need to be running a docker daemon.
