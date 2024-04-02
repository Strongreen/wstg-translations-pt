# Testando a Poluição de Parâmetros HTTP

|ID          |
|------------|
|WSTG-INPV-04|

## Resumo

A Poluição de Parâmetros HTTP testa a resposta do aplicativo ao receber múltiplos parâmetros HTTP com o mesmo nome; por exemplo, se o parâmetro `username` estiver incluído nos parâmetros GET ou POST duas vezes.

O fornecimento de múltiplos parâmetros HTTP com o mesmo nome pode fazer com que um aplicativo interprete os valores de maneiras não antecipadas. Ao explorar esses efeitos, um atacante pode ser capaz de contornar a validação de entrada, provocar erros de aplicativo ou modificar valores de variáveis internas. Como a Poluição de Parâmetros HTTP (HPP - HTTP Parameter Pollution ) afeta um componente fundamental de todas as tecnologias web, existem ataques no lado do servidor e no lado do cliente.

As normas HTTP atuais não incluem orientações sobre como interpretar múltiplos parâmetros de entrada com o mesmo nome. Por exemplo, [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt) define simplesmente o termo *Query String* como uma série de pares de campo-valor e [RFC 2396](https://www.ietf.org/rfc/rfc2396.txt) define classes de caracteres de string de consulta reversa e não reservada. Sem uma norma estabelecida, os componentes de aplicativos web lidam com este caso limite de várias maneiras (consulte a tabela abaixo para mais detalhes).

Por si só, isso não é necessariamente uma indicação de vulnerabilidade. No entanto, se o desenvolvedor não estiver ciente do problema, a presença de parâmetros duplicados pode produzir um comportamento anômalo no aplicativo que pode ser potencialmente explorado por um atacante. Como frequentemente na segurança, comportamentos inesperados são uma fonte comum de fraquezas e poderiam levar a ataques de Poluição de Parâmetros HTTP neste caso. Para introduzir melhor esta classe de vulnerabilidades e o resultado dos ataques de HPP, é interessante analisar alguns exemplos da vida real que foram descobertos no passado.

### Validação de Entrada e Desvio de Filtros

Em 2009, imediatamente após a publicação da primeira pesquisa sobre Poluição de Parâmetros HTTP, a técnica recebeu atenção da comunidade de segurança como uma possível forma de contornar firewalls de aplicativos web.

Uma dessas falhas, afetando as *Regras de Injeção SQL do ModSecurity*, representa um exemplo perfeito da discrepância entre aplicativos e filtros que deveriam ser compativeis. O filtro ModSecurity aplicaria corretamente uma lista de negação para a seguinte string: `select 1,2,3 from table`, bloqueando assim este exemplo de URL de ser processado pelo servidor web: `/index.aspx?page=select 1,2,3 from table`. No entanto, ao explorar a concatenação de múltiplos parâmetros HTTP, um atacante poderia fazer com que o servidor de aplicativos concatenasse a string após o filtro ModSecurity já ter aceitado a entrada. Como exemplo, a URL `/index.aspx?page=select 1&page=2,3` não acionaria o filtro ModSecurity, mas a camada de aplicativo concatenaria a entrada de volta na string maliciosa completa.

Outra vulnerabilidade de HPP acabou afetando o *Apple Cups*, o conhecido sistema de impressão usado por muitos sistemas UNIX. Explorando a HPP, um atacante poderia facilmente acionar uma vulnerabilidade de Cross-Site Scripting usando a seguinte URL: `http://127.0.0.1:631/admin/?kerberos=onmouseover=alert(1)&kerberos`. O ponto de verificação de validação do aplicativo poderia ser contornado adicionando um argumento `kerberos` extra com uma string válida (por exemplo, uma string vazia). Como o ponto de verificação de validação consideraria apenas a segunda ocorrência, o primeiro parâmetro `kerberos` não seria adequadamente higienizado antes de ser usado para gerar conteúdo HTML dinâmico. A exploração bem-sucedida resultaria na execução de código JavaScript sob o contexto do site hospedeiro.

### Desvio de Autenticação

Uma vulnerabilidade de HPP ainda mais crítica foi descoberta no *Blogger*, a popular plataforma de blogs. O bug permitia que usuários mal-intencionados assumissem a propriedade do blog da vítima usando a seguinte solicitação HTTP (`https://www.blogger.com/add-authors.do`):

```html
POST /add-authors.do HTTP/1.1
[...]

security_token=attackertoken&blogID=attackerblogidvalue&blogID=victimblogidvalue&authorsList=goldshlager19test%40gmail.com(email do atacante)&ok=Invite
```

A falha residia no mecanismo de autenticação usado pelo aplicativo web, pois a verificação de segurança era realizada no primeiro parâmetro `blogID`, enquanto a operação real usava a segunda ocorrência.

### Comportamento Esperado pelo Servidor de Aplicativos

A tabela a seguir ilustra como diferentes tecnologias web se comportam na presença de múltiplas ocorrências do mesmo parâmetro HTTP.

Dada a URL e a string de consulta: `http://example.com/?color=red&color=blue`

  | Backend do Servidor de Aplicativos Web | Resultado da Análise | Exemplo |
  |-----------------------------------------|----------------------|---------|
  | ASP.NET / IIS | Todas as ocorrências concatenadas com uma vírgula |  color=red,blue |
  | ASP / IIS     | Todas as ocorrências concatenadas com uma vírgula | color=red,blue |
  | PHP / Apache  | Apenas a última ocorrência | color=blue |
  | PHP / Zeus | Apenas a última ocorrência | color=blue |
  | JSP, Servlet / Apache Tomcat | Apenas a primeira ocorrência | color=red |
  | JSP, Servlet / Oracle Application Server 10g | Apenas a primeira ocorrência | color=red |
  | JSP, Servlet / Jetty  | Apenas a primeira ocorrência | color=red |
  | IBM Lotus Domino | Apenas a última ocorrência | color=blue |
  | IBM HTTP Server | Apenas a primeira ocorrência | color=red |
  | mod_perl, libapreq2 / Apache | Apenas a primeira ocorrência | color=red |
  | Perl CGI / Apache | Apenas a primeira ocorrência | color=red |
  | mod_wsgi (Python) / Apache | Apenas a primeira ocorrência | color=red |
  | Python / Zope | Todas as ocorrências em um tipo de dados de Lista | color=['red','blue'] |

(fonte: [Appsec EU 2009 Carettoni & Paola](https://owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf))

## Objetivos do Teste

- Identificar o backend e o método de análise utilizado.
- Avaliar os pontos de injeção e tentar contornar os filtros de entrada usando HPP.

## Como Testar

Felizmente, como a atribuição de parâmetros HTTP é tipicamente tratada pelo servidor de aplicativos web e não pelo código do aplicativo em si, testar a resposta à poluição de parâmetros deve ser padrão em todas as páginas e ações. No entanto, como é necessário um conhecimento aprofundado da lógica de negócios, testar HPP requer testes manuais. Ferramentas automáticas só podem auxiliar parcialmente os auditores, pois tendem a gerar muitos falsos positivos. Além disso, a HPP pode se manifestar em componentes do lado do cliente e do lado do servidor.

### HPP do Lado do Servidor

Para testar vulnerabilidades de HPP, identifique qualquer formulário ou ação que permita entrada fornecida pelo usuário. Parâmetros de string de consulta em solicitações GET HTTP são fáceis de ajustar na barra de navegação do navegador. Se a ação do formulário enviar dados via POST, o testador precisará usar um proxy de interceptação para manipular os dados POST conforme são enviados para o servidor. Após identificar um parâmetro de entrada específico a ser testado, é possível editar os dados GET ou POST interceptando a solicitação ou alterando a string de consulta após a página de resposta ser carregada. Para testar vulnerabilidades de HPP, basta anexar o mesmo parâmetro aos dados GET ou POST, mas com um valor diferente atribuído.

Por exemplo: se estiver testando o parâmetro `search_string` na string de consulta, a URL da solicitação incluiria esse nome e valor de parâmetro:

```text
http://example.com/?search_string=kittens
```

O parâmetro específico pode estar oculto entre vários outros parâmetros, mas a abordagem é a mesma; deixe os outros parâmetros no lugar e anexe o duplicado:

```text
http://example.com/?mode=guest&search_string=kittens&num_results=100
```

Anexe o mesmo parâmetro com um valor diferente:

```text
http://example.com/?mode=guest&search_string=kittens&num_results=100&search_string=puppies
```

e envie a nova solicitação.

Analise a página de resposta para determinar quais valor(es) foram analisados. No exemplo acima, os resultados da pesquisa podem mostrar `kittens`, `puppies`, alguma combinação de ambos (`kittens,puppies` ou `kittens~puppies` ou `['kittens','puppies']`), podem dar um resultado vazio ou uma página de erro.

Este comportamento, seja usando a primeira, última ou combinação de parâmetros de entrada com o mesmo nome, é muito provável que seja consistente em toda a aplicação. Se este comportamento padrão revelar ou não uma vulnerabilidade potencial depende da validação de entrada específica e da filtragem específica de um aplicativo particular. Como regra geral: se a validação de entrada existente e outros mecanismos de segurança forem suficientes em entradas únicas e se o servidor atribuir apenas os primeiros ou últimos parâmetros poluídos, então a poluição de parâmetros não revela uma vulnerabilidade. Se os parâmetros duplicados forem concatenados, diferentes componentes de aplicativos web usarem diferentes ocorrências ou testes gerarem um erro, há uma probabilidade aumentada de ser capaz de usar a poluição de parâmetros para desencadear vulnerabilidades de segurança.

Uma análise mais aprofundada exigiria três solicitações HTTP para cada parâmetro HTTP:

1. Envie uma solicitação HTTP contendo o nome e o valor do parâmetro padrão e registre a resposta HTTP. Por exemplo, `page?par1=val1`
2. Substitua o valor do parâmetro por um valor adulterado, envie e registre a resposta HTTP. Por exemplo, `page?par1=HPP_TEST1`
3. Envie uma nova solicitação combinando as etapas (1) e (2). Novamente, salve a resposta HTTP. Por exemplo, `page?par1=val1&par1=HPP_TEST1`
4. Compare as respostas obtidas durante todas as etapas anteriores. Se a resposta de (3) for diferente de (1) e a resposta de (3) também for diferente de (2), há uma discrepância de impedância que pode eventualmente ser explorada para desencadear vulnerabilidades de HPP.

Elaborar uma exploração completa a partir de uma fraqueza de poluição de parâmetros está além do escopo deste texto. Consulte as referências para exemplos e detalhes.

### HPP do Lado do Cliente

Assim como na HPP do lado do servidor, os testes manuais são a única técnica confiável para auditar aplicativos web a fim de detectar vulnerabilidades de poluição de parâmetros afetando componentes do lado do cliente. Enquanto na variante do lado do servidor o atacante aproveita um aplicativo web vulnerável para acessar dados protegidos ou realizar ações que não são permitidas ou não devem ser executadas, os ataques do lado do cliente visam subverter componentes e tecnologias do lado do cliente.

Para testar vulnerabilidades de HPP do lado do cliente, identifique qualquer formulário ou ação que permita entrada do usuário e mostre um resultado dessa entrada de volta ao usuário. Uma página de pesquisa é ideal, mas uma caixa de login pode não funcionar (pois pode não mostrar um nome de usuário inválido de volta ao usuário).

Assim como na HPP do lado do servidor, polua cada parâmetro HTTP com `%26HPP_TEST` e procure por ocorrências *decodificadas de URL* da carga útil fornecida pelo usuário:

- `&HPP_TEST`
- `&amp;HPP_TEST`
- etc.

Em particular, preste atenção às respostas que têm vetores de HPP dentro de atributos `data`, `src`, `href` ou ações de formulários. Novamente,

 se este comportamento padrão revelar ou não uma vulnerabilidade potencial, depende da validação de entrada específica, filtragem e lógica de negócios da aplicação. Além disso, é importante notar que esta vulnerabilidade também pode afetar parâmetros de string de consulta usados em XMLHttpRequest (XHR), criação de atributos em tempo de execução e outras tecnologias de plugin (por exemplo, variáveis flashvars do Adobe Flash).

## Ferramentas

- [Verificadores Passivos/Ativos do OWASP ZAP](https://www.zaproxy.org)

## Referências

### Artigos Técnicos

- [Poluição de Parâmetros HTTP - Luca Carettoni, Stefano di Paola](https://owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf)
- [Exemplo de Poluição de Parâmetros HTTP do Lado do Cliente (falha do Yahoo! Classic Mail) - Stefano di Paola](https://blog.mindedsecurity.com/2009/05/client-side-http-parameter-pollution.html)
- [Como Detectar Ataques de Poluição de Parâmetros HTTP - Chrysostomos Daniel](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
- [CAPEC-460: Poluição de Parâmetros HTTP (HPP) - Evgeny Lebanidze](https://capec.mitre.org/data/definitions/460.html)
- [Descoberta Automatizada de Vulnerabilidades de Poluição de Parâmetros em Aplicações Web - Marco Balduzzi, Carmen Torrano Gimenez, Davide Balzarotti, Engin Kirda](http://s3.eurecom.fr/docs/ndss11_hpp.pdf)