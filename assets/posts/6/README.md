## Contribution

### Installation

Please install [VSCode](https://code.visualstudio.com/) and its extensions:

- Prettier - Code formatter
- Git Graph
- Git History
- Python
- Pylance
- Ruff
- Even Better TOML
- Docker
- DotENV
- shell-format
- One Dark Pro (optional)
- Material Icon Theme (optional)

Please install [git](https://git-scm.com/download/linux):

```sh
sudo apt install git
```

Please install [Figma](https://www.figma.com/).

Please install [Node.js and npm](https://nodejs.org/en/download/package-manager).

```sh
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash \
&& source $HOME/.bashrc \
&& nvm install 22 \
&& node -v \
&& npm -v
```

Please install or update [Python](https://www.python.org/downloads/):

```sh
sudo apt install python3 python3-pip python3-venv
```

Please install or update [uv](https://docs.astral.sh/uv/getting-started/installation/):

```sh
curl -LsSf https://astral.sh/uv/0.9.22/install.sh | sh \
&& uv --version
```

Please install [Docker Desktop](https://www.docker.com/get-started/).

### Commands

To clear uv cache:

```sh
uv cache clean
```

To clear the Docker Buildx cache:

```sh
docker buildx prune -af
```
