# Testando Injeção LDAP

|ID          |
|------------|
|WSTG-INPV-06|

## Resumo

O Lightweight Directory Access Protocol (LDAP) é usado para armazenar informações sobre usuários, hosts e muitos outros objetos. A [injeção LDAP](https://wiki.owasp.org/index.php/LDAP_injection) é um ataque do lado do servidor, que poderia permitir a divulgação, modificação ou inserção de informações sensíveis sobre usuários e hosts representados em uma estrutura LDAP. Isso é feito manipulando parâmetros de entrada passados posteriormente para funções internas de pesquisa, adição e modificação.

Uma aplicação web poderia usar o LDAP para permitir que os usuários se autentiquem ou busquem informações de outros usuários dentro de uma estrutura corporativa. O objetivo dos ataques de injeção LDAP é injetar metacaracteres de filtro de pesquisa LDAP em uma consulta que será executada pela aplicação.

[Rfc2254](https://www.ietf.org/rfc/rfc2254.txt) define uma gramática sobre como construir um filtro de pesquisa no LDAPv3 e estende [Rfc1960](https://www.ietf.org/rfc/rfc1960.txt) (LDAPv2).

Um filtro de pesquisa LDAP é construído em notação polonesa, também conhecida como [notação polonesa de notação prefixa](https://en.wikipedia.org/wiki/Polish_notation).

Isso significa que uma condição de pseudocódigo em um filtro de pesquisa como este:

`find("cn=John & userPassword=mypass")`

será representada como:

`find("(&(cn=John)(userPassword=mypass))")`

Condições booleanas e agregações de grupo em um filtro de pesquisa LDAP podem ser aplicadas usando os seguintes metacaracteres:

| Metacar   |  Significado         |
|----------|----------------------|
| &        |  AND booleano        |
| \|       |  OR booleano         |
| !        |  NOT booleano        |
| =        |  Igual                |
| ~=       |  Aprox               |
| >=       |  Maior que           |
| <=       |  Menor que           |
| *        |  Qualquer caractere  |
| ()       |  Parênteses de agrupamento |

Exemplos mais completos sobre como construir um filtro de pesquisa podem ser encontrados no RFC relacionado.

Uma exploração bem-sucedida de uma vulnerabilidade de injeção LDAP poderia permitir que o testador:

- Acesse conteúdo não autorizado
- Evite restrições de aplicação
- Reúna informações não autorizadas
- Adicione ou modifique Objetos dentro da estrutura de árvore LDAP.

## Objetivos do Teste

- Identificar pontos de injeção LDAP.
- Avaliar a gravidade da injeção.

## Como Testar

### Exemplo 1: Filtros de Pesquisa

Vamos supor que temos uma aplicação web usando um filtro de pesquisa como este:

`searchfilter="(cn="+user+")"`

que é instanciado por uma solicitação HTTP como esta:

`http://www.example.com/ldapsearch?user=John`

Se o valor `John` for substituído por um `*`, enviando a solicitação:

`http://www.example.com/ldapsearch?user=*`

o filtro ficará assim:

`searchfilter="(cn=*)"`

que corresponde a qualquer objeto com um atributo 'cn' igual a qualquer coisa.

Se a aplicação for vulnerável à injeção LDAP, ela exibirá alguns ou todos os atributos do usuário, dependendo do fluxo de execução da aplicação e das permissões do usuário conectado ao LDAP.

Um testador pode usar uma abordagem de tentativa e erro, inserindo nos parâmetros `(`, `|`, `&`, `*` e os outros caracteres, para verificar a aplicação em busca de erros.

### Exemplo 2: Login

Se uma aplicação web usar o LDAP para verificar as credenciais do usuário durante o processo de login e for vulnerável à injeção LDAP, é possível contornar a verificação de autenticação injetando uma consulta LDAP sempre verdadeira (de maneira semelhante à injeção SQL e XPATH).

Vamos supor que uma aplicação web use um filtro para corresponder ao par usuário/senha do LDAP.

`searchlogin= "(&(uid="+user+")(userPassword={MD5}"+base64(pack("H*",md5(pass)))+"))";`

Usando os seguintes valores:

```txt
user=*)(uid=*))(|(uid=*
pass=password
```

o filtro de pesquisa resultará em:

`searchlogin="(&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))";`

que está correto e sempre verdadeiro. Desta forma, o testador ganhará status de logado como o primeiro usuário na árvore LDAP.

## Ferramentas

- [Softerra LDAP Browser](https://www.ldapadministrator.com)

## Referências

- [Cheat Sheet de Prevenção de Injeção LDAP](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)

### Whitepapers

- [Sacha Faust: Injeção LDAP: Suas Aplicações Estão Vulneráveis?](http://www.networkdls.com/articles/ldapinjection.pdf)
- [IBM paper: Compreendendo o LDAP](https://www.redbooks.ibm.com/redbooks/pdfs/sg244986.pdf)
- [RFC 1960: Uma Representação de String de Filtros de Pesquisa LDAP](https://www.ietf.org/rfc/rfc1960.txt)
- [Injeção LDAP](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf)