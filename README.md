<p align="center">
  <a href="https://lovindata.github.io/blog/" target="_blank">
      <img alt="LovinData" src="docs/assets/logo.png" width="150" style="max-width: 100%;">
  </a>
</p>

<p align="center">
  LovinData - Simplified Software Engineering
</p>

<p align="center">
    <a href="https://github.com/lovindata/blog/actions"><img src="https://img.shields.io/github/actions/workflow/status/lovindata/blog/ci.yml?branch=main" alt="Build Status"></a>
    <a href="https://github.com/lovindata/blog/blob/main/LICENSE"><img src="https://img.shields.io/github/license/lovindata/blog" alt="License"></a>
</p>

---

## Contribution

Please install [VSCode](https://code.visualstudio.com/) and its extensions:

- Even Better TOML
- Prettier

Please install [git](https://git-scm.com/download/linux):

```sh
sudo apt install git
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

Please create your Python environment and install dependencies:

```sh
uv venv --clear \
&& uv sync --all-groups
```

Please reload the VSCode window:

- In VSCode, press `CTRL + SHIFT + P`
- Click on `Python: Clear Cache and Reload Window`

To update the dependencies:

```sh
uv lock --upgrade \
&& uv sync --all-groups
```

To clear uv cache:

```sh
uv cache clean
```

To serve the blog, run the command:

```bash
uv run mkdocs serve
```
