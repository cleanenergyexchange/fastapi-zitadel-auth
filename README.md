# FastAPI Zitadel Auth

<p>
    <em>Simplify OAuth2 authentication and authorization in FastAPI apps using <b><a href="https://zitadel.com">Zitadel</a></b>.</em>
</p>

<a href="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/actions/workflows/test.yml" target="_blank">
    <img src="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/actions/workflows/test.yml/badge.svg" alt="Test status">
</a>
<a href="https://codecov.io/gh/cleanenergyexchange/fastapi-zitadel-auth">
    <img src="https://codecov.io/gh/cleanenergyexchange/fastapi-zitadel-auth/graph/badge.svg?token=A3TSXDVLQT" alt="Code coverage"/> 
</a>
<a href="https://pypi.org/pypi/fastapi-zitadel-auth">
    <img src="https://img.shields.io/pypi/v/fastapi-zitadel-auth.svg?logo=pypi&logoColor=white&label=pypi" alt="Package version">
</a>
<a href="https://pepy.tech/projects/fastapi-zitadel-auth">
    <img src="https://static.pepy.tech/badge/fastapi-zitadel-auth/month" alt="PyPI downloads">
</a>
<a href="https://python.org">
    <img src="https://img.shields.io/badge/python-v3.10+-blue.svg?logo=python&logoColor=white&label=python" alt="Python versions">
</a>
<a href="https://mypy-lang.org">
    <img src="https://www.mypy-lang.org/static/mypy_badge.svg" alt="mypy">
</a>
<a href="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/blob/main/LICENCE">
    <img src="https://badgen.net/github/license/cleanenergyexchange/fastapi-zitadel-auth/" alt="License"/>
</a>

---

**Documentation**: <a href="https://cleanenergyexchange.github.io/fastapi-zitadel-auth" target="_blank">https://cleanenergyexchange.github.io/fastapi-zitadel-auth</a>

**Source Code**: <a href="https://github.com/cleanenergyexchange/fastapi-zitadel-auth" target="_blank">https://github.com/cleanenergyexchange/fastapi-zitadel-auth</a>

---

## Features

* Authorization Code flow with PKCE
* JWT validation using JWKS
* Role-based access control using Zitadel roles
* Service user authentication (JWT Profile)
* Swagger UI integration
* Type-safe token validation
* Extensible claims and user models



> **Note:** This library implements JWT, locally validated using JWKS, as it prioritizes performance, 
see [Zitadel docs on Opaque tokens vs JWT](https://zitadel.com/docs/concepts/knowledge/opaque-tokens#use-cases-and-trade-offs). 
If you need to validate opaque tokens using Introspection, 
please [open an issue](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/issues?q=is%3Aissue%20state%3Aopen%20introspection) – PRs are welcome!


## License

This project is licensed under the terms of the [MIT license](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/blob/main/LICENCE).

## Acknowledgements

This package was heavily inspired by [intility/fastapi-azure-auth](https://github.com/intility/fastapi-azure-auth/). 
Give them a star ⭐️!