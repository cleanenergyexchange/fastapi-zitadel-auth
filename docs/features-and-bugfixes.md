# Features and bugfixes

To contribute, follow these steps:

1. Create **[an issue](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/issues)** explaining what you want to add or fix
2. **Fork** the repository
3. Install [**uv**](https://docs.astral.sh/uv/)
4. Install **dependencies** with `uv sync --group dev`
5. Install **pre-commit hooks** with `uv run pre-commit install`
6. Create a **branch** for your feature or fix
7. Write code
8. **Format** code with `uv run ruff format src`
9. **Lint** code with `uv run ruff check --fix src`
10. Run **mypy** with `uv run mypy src`
11. Write and run **tests** with `uv run pytest` (only 100% coverage is accepted)
12. Create a **pull request**
13. Make sure the **CI checks** pass
14. **Link the issue** in the pull request
