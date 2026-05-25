## Contribution

### Get started

Please create your Python environment and install dependencies:

```sh
uv venv --clear \
&& uv sync --all-groups
```

Please reload the VSCode window:

- In VSCode, press `CTRL + SHIFT + P`
- Click on `Python: Clear Cache and Reload Window`

Please start the [local developement environment](../devops/README.md#installation).

Please adapt the [backend environment variables](./src/confs/envs_conf.py).

Please launch in development mode with the debugger:

- Open `main.py`
- Click on selection menu close to the ▶️ icon
- Click on `Python Debugger: Debug Python File`

If all worked, congratulations! You are ready to contribute!

### Commands

To update the dependencies:

```sh
uv lock --upgrade \
&& uv sync --all-groups
```

## Build docker images

### Local

To build local docker image:

```sh
docker build --target backend_analytics -t lovindata/private:event_bus_backend_analytics-local -f 'Dockerfile' ..
```

To investigate the content of the docker image:

```sh
docker run -it --rm --entrypoint /bin/sh lovindata/private:event_bus_backend_analytics-local
```