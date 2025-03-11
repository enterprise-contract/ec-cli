# Offliner

A tool to offline, i.e. place all data for an container image in a remote
registry to a local data directory. This local data directory can be mounted to
docker.io/registry container registry so running against it eliminates remote
network access.

Use: `offliner <pinned image reference> <data directory>`
