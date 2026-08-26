# Utilização de senha ROOT

> **Este arquivo é intencionalmente ignorado pelo git** (ver `.gitignore`).
> Contém referências a credenciais do servidor e não deve ser versionado.

- A variável `PWD_SERVER` em `.env` é a senha de login tanto do usuário `root` quanto do
usuário comum (`labs`) neste servidor — é a mesma senha para os dois. Toda vez que precisar
autenticar como root ou rodar um comando com `sudo`, use o valor de `PWD_SERVER`. Tome cuidado:
sempre me pergunte primeiro e me explique para o que vai precisar antes de usar.
