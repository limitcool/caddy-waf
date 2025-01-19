# 🐳 Docker

Docker provides a powerful and efficient way to package and run the WAF as a containerized application. This approach offers numerous advantages, including portability, consistency, simplified deployment, and scalability. This section provides comprehensive information on building and running the WAF within Docker containers, following industry best practices.

## Building the Docker Image

The Docker image is built using the `docker build` command, executed from the project's root directory (where the `Dockerfile` is located):

```bash
docker build -t caddy-waf .
```

*   **`docker build`**: This is the Docker command to build an image from a `Dockerfile`.
*   **`-t caddy-waf`**: The `-t` flag tags the built image with the name `caddy-waf`. This tag is used later to reference the image when running containers. You can replace `caddy-waf` with your preferred image name and tag. It is recommended to prefix the image name with the registry, if you are deploying to registries other than Docker Hub, for example: `myregistry/caddy-waf`.
*   **.**: The trailing dot (`.`) specifies that the build context is the current directory, where the `Dockerfile` and other necessary files are found.

**Dockerfile Deep Dive:**

The `Dockerfile` is responsible for defining how the Docker image is built. It should:

*   Start with a suitable base image. We use a multi-stage build, using `golang:1.22.3-alpine` as the builder image and `alpine:latest` as the final image.
*   Install necessary tools for building: `git` (for cloning the repository) and `wget` (for downloading files), as well as `xcaddy` which is used to compile a custom version of `caddy`.
*   Clone the WAF's Git repository.
*   Fetch and install Go dependencies, including the required Caddy modules, the WAF plugin, and other modules.
*   Download the GeoLite2 Country database.
*   Build the Caddy binary with the WAF plugin using `xcaddy`.
*   Copy the compiled Caddy binary, GeoIP database, configuration files (rules, blacklists, Caddyfile) into the final image.
*   Create a non-root user (`caddy`) for security.
*   Set appropriate permissions for the files inside the container.
*   Expose the required HTTP port (default is `8080`).
*   Define the command to execute when the container starts, which is to run Caddy using the specified Caddyfile.

Here's the complete Dockerfile shipped with the project, along with inline comments:

```dockerfile
# --- Stage 1: Builder Stage ---
# Use a Go base image to build the Caddy binary and the WAF module
FROM golang:1.22.3-alpine AS builder

# Install essential tools for building: git, wget
#   - git: required for cloning the repository
#   - wget: required for downloading files
#   - &&: combines commands
#   - no-cache: prevents the apk installer from using the cache (smaller image)
RUN apk add --no-cache git wget

# Install xcaddy for building custom Caddy binaries with modules.
#   - @latest will install the latest available version.
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Set the working directory for the build process
WORKDIR /app

# Clone the caddy-waf repository from GitHub
RUN git clone https://github.com/fabriziosalmi/caddy-waf.git

# Change to the cloned directory
WORKDIR /app/caddy-waf

# Fetch and install the necessary Go dependencies, including Caddy and its modules and the caddy-waf plugin.
#  - go get will fetch and install all required modules
#  - go.mod will be used to properly build the project.
RUN go get -v github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/caddyconfig/caddyfile github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/modules/caddyhttp github.com/oschwald/maxminddb-golang github.com/fsnotify/fsnotify github.com/fabriziosalmi/caddy-waf

# Clean up and update the go.mod file
# - go mod tidy will tidy up go.mod file, removing unused dependencies
RUN go mod tidy

# Download the GeoLite2 Country database from a known location.
# - Use a reliable download location for this file.
RUN wget https://git.io/GeoLite2-Country.mmdb -O GeoLite2-Country.mmdb

# Clean up previous build artifacts, to ensure a clean build
RUN rm -rf buildenv_*

# Build the Caddy binary using xcaddy with the caddy-waf module.
#   - This creates the custom caddy binary with the waf
RUN xcaddy build --with github.com/fabriziosalmi/caddy-waf=./

# --- Stage 2: Runtime Stage ---
# Use a minimal base image for the final container.
FROM alpine:latest

# Set the working directory for the running container.
WORKDIR /app

# Copy the Caddy binary from the builder stage.
#  - This copies the executable from the builder stage
COPY --from=builder /app/caddy-waf/caddy /usr/bin/caddy

# Copy the GeoLite2 database, rules, blacklists, and Caddyfile from the builder stage.
#  - This copies the files into the /app directory in the final image.
COPY --from=builder /app/caddy-waf/GeoLite2-Country.mmdb /app/
COPY --from=builder /app/caddy-waf/rules.json /app/
COPY --from=builder /app/caddy-waf/ip_blacklist.txt /app/
COPY --from=builder /app/caddy-waf/dns_blacklist.txt /app/
COPY Caddyfile /app/

# Create a 'caddy' group and user, with limited privileges to improve security.
#   - -S: Creates a system group and user
RUN addgroup -S caddy && adduser -S -G caddy caddy

# Change ownership of /app to the 'caddy' user and group to ensure proper permissions are set
RUN chown -R caddy:caddy /app

# Set the user to 'caddy' for running the container and the application.
# - all commands after this command will run with this user.
USER caddy

# Expose the HTTP port that Caddy will listen on.
#   - this does not expose the port on the host, for that use the `docker run -p` command.
EXPOSE 8080

# Set the command to run when the container starts.
#  - `caddy run`: starts the caddy server
#  --config /app/Caddyfile`: specifies the location of the Caddy configuration file.
CMD ["caddy", "run", "--config", "/app/Caddyfile"]
```

## Running the Docker Container

Once the Docker image is built, you can run a container using the following command:

```bash
docker run -p 8080:8080 caddy-waf
```

*   **`docker run`**: This is the Docker command to create and run a container from a specified image.
*   **`-p 8080:8080`**: The `-p` flag maps port `8080` on the host machine to port `8080` inside the container. This makes the WAF accessible via port `8080` on your host. You can adjust this mapping as needed. For example, `-p 80:8080` will map port `80` on the host to port `8080` in the container, and `-p 8081:8080` will map port `8081` on the host to port `8080` in the container.
*   **`caddy-waf`**: Specifies the name of the Docker image to run, which we built in the previous step.

**Run Command Options:**

*   **Port Mapping:** Adjust the `-p` flag to map the correct host port to the port exposed by the container if your WAF is using a port other than `8080`.
*   **Environment Variables:** Use the `-e` flag to pass environment variables to the container (e.g., `-e LOG_LEVEL=DEBUG`, `-e ANOMALY_THRESHOLD=30`). For example: `docker run -p 8080:8080 -e LOG_LEVEL=DEBUG caddy-waf`.
*   **Volume Mounts:** Use the `-v` flag to mount volumes for persistent configuration or data, ensuring that changes to configuration are not lost if the container is stopped or removed. For example, `-v /my/config:/etc/caddy` mounts the host's directory `/my/config` to `/etc/caddy` inside the container. This is particularly important for logs. For example: `docker run -p 8080:8080 -v /my/config:/etc/caddy -v /my/logs:/var/log/caddy caddy-waf`.
*   **Detached Mode:** Use the `-d` flag to run the container in the background: `docker run -d -p 8080:8080 caddy-waf`.
*  **Container Name**: Use `--name` to specify a name for the container for easy management: `docker run --name my-waf -d -p 8080:8080 caddy-waf`.

## Docker Compose

For more complex deployments, use Docker Compose to configure multiple containers and their dependencies using a `docker-compose.yml` file. An example `docker-compose.yml` file is:

```yaml
version: "3.9"
services:
  waf:
    image: caddy-waf
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/caddy/
      - ./logs:/var/log/caddy/
    environment:
      - LOG_LEVEL=DEBUG
```

To start the container using docker compose, execute `docker-compose up -d` from the directory containing the `docker-compose.yml` file.

## Best Practices:

*   **Immutable Containers:** Treat containers as immutable units. Any changes should be done by rebuilding the image rather than modifying it inside the running container.
*   **Configuration Outside the Image:** Store the WAF's configuration (e.g., `Caddyfile`, `rules.json`, blacklists) outside the container image using volume mounts. This allows for configuration updates without rebuilding the container image.
*  **Persistent Logging:** Configure logging to persist logs outside the container, making them accessible to log management and analysis tools by mounting a volume to the directory where logs are written.
*   **Security:** Follow Docker security best practices, such as running containers with non-root users, using a minimal base image, and keeping the container image up to date, using a specific version rather than `latest`.
* **Resource Management**: Set appropriate resource limits (CPU, memory) to ensure stable and predictable performance and prevent one container from consuming too many resources.
*  **Health Checks:** Add a health check to the Dockerfile so Docker knows if the container is running correctly and automatically restarts if it fails.
*   **Image Tagging:** Tag images with meaningful tags, like version numbers or build identifiers, to facilitate tracking and versioning.
*  **Environment variables:** Pass sensitive information (e.g API Keys) as environment variables, rather than hardcoding them in the image.

## Example Usage Scenarios:

**Example with Volume Mounts:**

```bash
docker run -p 8080:8080 -v /my/config:/etc/caddy -v /my/logs:/var/log/caddy caddy-waf
```

*   `/my/config` on the host is mounted to `/etc/caddy` inside the container, providing external configuration files to the container.
*   `/my/logs` is mounted to `/var/log/caddy`, persisting log data outside the container.

**Example with Environment Variables:**

```bash
docker run -p 8080:8080 -e LOG_LEVEL=DEBUG caddy-waf
```

*   The `LOG_LEVEL` environment variable is passed to the container, which then controls the log output within the application.

**Example using docker compose:**

```bash
docker-compose up -d
```

*   Starts the container using the provided `docker-compose.yml` file in detached mode.

## Summary

Leveraging Docker for the WAF provides a robust, scalable, and easily manageable deployment solution. By following these guidelines and best practices, you can create a production-ready containerized environment for your WAF, maximizing its efficiency and security. This extended guide will help you understand and implement the Docker support for the WAF effectively.
