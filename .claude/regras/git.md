# Padrão de Versionamento (Git)

- Toda vez que eu solicitar um commit, você **DEVE** utilizar o padrão *Conventional Commits*
(ex: `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`).
- **AS MENSAGENS DE COMMIT DEVEM SER ESCRITAS ESTRITAMENTE EM PORTUGUÊS DO BRASIL (PT-BR).**
- As mensagens de commit devem ser inteligentes, contextuais e escritas no imperativo.
Demonstre que você entende o propósito de negócio ou de arquitetura por trás da modificação
(Exemplo bom: `fix(dashboard): corrige renderização fantasma durante falhas de rede`; Exemplo
ruim: `fix: atualiza arquivo js`).
- **Granularidade Cirúrgica:** Se houver vários arquivos modificados e eu pedir para comitar
arquivos específicos de forma separada, você **PROIBIDAMENTE** agrupará tudo em um único `git
commit`. Você deve realizar chamadas separadas para cada arquivo (ou escopo), criando uma
mensagem de commit cirúrgica e exclusiva para cada um, refletindo isoladamente a modificação
daquele respectivo arquivo.
