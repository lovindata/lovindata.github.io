## Contribution

### Installation

Please install [VSCode](https://code.visualstudio.com/) and its extensions:

- Docker
- DotENV
- Prettier
- Git Graph
- Git History
- One Dark Pro (optional)
- Material Icon Theme (optional)

Please install [git](https://git-scm.com/download/mac):

```bash
sudo apt install git
```

Please install `docker-compose/.env`:

- Copy `docker-compose/.env.example` as `docker-compose/.env`

```bash
cp -f docker-compose/.env.example docker-compose/.env
```

- Modify `docker-compose/.env` with desired values

If all worked, congratulations! You are ready to contribute!

### Commands

To start large language models containers:

- In VSCode, right click on `docker-compose/docker-compose.yml`
- Click on `Compose Restart`

To stop large language models containers:

- In VSCode, right click on `docker-compose/docker-compose.yml`
- Click on `Compose Down`
