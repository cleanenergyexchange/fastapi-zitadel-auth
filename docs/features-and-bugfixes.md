# Features and bugfixes

To contribute, follow these steps:

1. Create **[an issue](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/issues)** explaining what you want to add or fix.
2. **Fork** the repository.
3. Install [`uv`](https://docs.astral.sh/uv/) and **install the dependencies** with `uv sync --group dev`.
4. Install **pre-commit hooks** with `uv run pre-commit install`.
5. Create a **branch** for your feature or fix.
6. Write code.
7. **Format** code with `uv run format src`
8. **Lint** code with `uv run check --fix src`
9. Run **mypy** with `uv run mypy src`
10. Write and run **tests** with `uv run pytest`
11. Create a **pull request**.
12. Make sure the **CI checks** pass.
13. **Link the issue** in the pull request.
