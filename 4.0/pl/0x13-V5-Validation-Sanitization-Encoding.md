# V5 Walidacja, Czyszczenie (Sanitization) i Kodowanie

## Cele kontroli

Najczęstszym słabym punktem bezpieczeństwa aplikacji internetowych jest nieodpowiednie sprawdzanie danych wejściowych pochodzących od klienta lub ze środowiska przed ich bezpośrednim użyciem. Ta słabość prowadzi do niemal wszystkich istotnych podatności w aplikacjach internetowych, takich jak Cross-Site Scripting (XSS), SQL injection, interpreter injection, ataki na ustawienia regionalne/Unicode, ataki na system plików oraz przepełnienia bufora.

Upewnij się, że weryfikowana aplikacja spełnia następujące wymagania wysokiego poziomu:

- Architektura walidacji danych wejściowych i kodowania danych wyjściowych ma uzgodniony schemat, który zapobiega atakom typu injection.
- Dane wejściowe mają ściśle określony typ, są sprawdzane, poddawane kontroli zakresu lub długości, lub w najgorszym przypadku czyszczone (sanitized) lub filtrowane.
- Dane wyjściowe są kodowane lub zamieniane na encje zgodnie z kontekstem danych jak najbliżej interpretera. 

W przypadku nowoczesnej architektury aplikacji internetowych kodowanie danych wyjściowych (output encoding) jest ważniejsze niż kiedykolwiek. Trudno jest zapewnić solidną walidację danych wejściowych w niektórych scenariuszach, dlatego stosowanie bezpieczniejszych interfejsów API, takich jak parametryzowane zapytania (parameterized queries), auto-escaping templating frameworks lub starannie wybrane metody kodowania wyników, jest kluczowe dla bezpieczeństwa aplikacji.

## V5.1 Walidacja Danych Wejściowych

Prawidłowo zaimplementowane mechanizmy walidacji danych wejściowych, wykorzystujące listy dozwolonych wartości (allow lists) oraz silne typowanie danych, mogą wyeliminować ponad 90% wszystkich ataków typu "injection". Kontrola długości i zakresu może jeszcze bardziej to ograniczyć. Wbudowanie bezpiecznej walidacji danych wejściowych jest wymagane podczas architektury aplikacji, sprintów projektowych, implementacji oraz testów jednostkowych i integracyjnych. Chociaż wiele z tych elementów nie może być wykrytych podczas testów penetracyjnych, wyniki ich braku zwykle można znaleźć w sekcji V5.3 - Wymagania dotyczące kodowania danych wyjściowych oraz zapobiegania atakom typu "injection". Zaleca się, aby programiści i osoby przeglądające kod pod kątem bezpieczeństwa traktowali tę sekcję tak, jakby L1 był wymagany dla wszystkich pozycji w celu zapobiegania atakom typu "injection".

|     #     | Opis                                                                                                                                                                                                                                                                                                                                                                                                               | L1 | L2 | L3 | CWE |
|:---------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **5.1.1** | Sprawdź, czy aplikacja posiada mechanizmy obronne przeciwko atakom z zanieczyszczeniem parametrów HTTP (parameter pollution attacks), zwłaszcza jeśli framework aplikacji nie rozróżnia źródła parametrów żądania (GET, POST, ciasteczka, nagłówki czy zmienne środowiskowe).                                                                                                                                      | ✓  | ✓  | ✓  | 235 |
| **5.1.2** | Sprawdź, czy framework chroni przed atakami masowego przypisywania parametrów, lub czy aplikacja posiada środki zaradcze do ochrony przed niebezpiecznym przypisywaniem parametrów, takie jak oznaczanie pól jako prywatne lub podobne. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                    | ✓  | ✓  | ✓  | 915 |
| **5.1.3** | Sprawdź, czy wszystkie dane wejściowe (pola formularzy HTML, żądania REST, parametry URL, nagłówki HTTP, ciasteczka, pliki wsadowe, kanały RSS itp.) są walidowane za pomocą walidacji pozytywnej (list dozwolonych wartości - allow lists). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                               | ✓  | ✓  | ✓  | 20  |
| **5.1.4** | Sprawdź, czy dane strukturalne są ściśle typowane i walidowane w oparciu o zdefiniowany schemat, obejmujący dozwolone znaki, długość i wzór (np. numery kart kredytowych, adresy e-mail, numery telefonów, lub sprawdzenie, czy dwie powiązane ze sobą informacje są zgodne, takie jak weryfikacja zgodności dzielnicy i kodu pocztowego). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓  | ✓  | ✓  | 20  |
| **5.1.5** | Sprawdź, czy przekierowania i przekazywanie URL-ów zezwalają jedynie na docelowe adresy znajdujące się na liście dozwolonych lub wyświetlają ostrzeżenie podczas przekierowywania do potencjalnie niezaufanych treści.                                                                                                                                                                                             | ✓  | ✓  | ✓  | 601 |

## V5.2 czyszczenie i Sandboxing

|     #     | Description                                                                                                                                                                                                                                                                                                                                  | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **5.2.1** | Sprawdź, czy wszystkie niezaufane dane wejściowe HTML pochodzące z edytorów WYSIWYG lub podobnych są odpowiednio czyszczone (sanitized) za pomocą biblioteki do dezynfekcji HTML lub funkcji frameworka. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                             | ✓  | ✓  | ✓  | 116 |
| **5.2.2** | Sprawdź, czy dane nieustrukturyzowane są czyszczone (sanitized) w celu egzekwowania środków bezpieczeństwa, takich jak dozwolone znaki i długość.                                                                                                                                                                                            | ✓  | ✓  | ✓  | 138 |
| **5.2.3** | Sprawdź, czy aplikacja czyści (sanitizes) dane wprowadzone przez użytkownika przed przekazaniem ich do systemów pocztowych, aby uchronić się przed atakami typu SMTP lub IMAP injection.                                                                                                                                                     | ✓  | ✓  | ✓  | 147 |
| **5.2.4** | Sprawdź, czy aplikacja unika stosowania funkcji eval() lub innych funkcji umożliwiających dynamiczne wykonywanie kodu. Tam, gdzie nie ma alternatywy, wszelkie dane wejściowe użytkownika, które mają być uwzględnione, muszą być czyszczone (sanitized) lub umieszczone w środowisku piaskownicy przed wykonaniem.                          | ✓  | ✓  | ✓  | 95  |
| **5.2.5** | Sprawdź, czy aplikacja chroni przed atakami polegającymi na wstrzykiwaniu szablonów, poprzez upewnienie się, że wszelkie dane wprowadzone przez użytkownika są odpowiednio czyszczone (sanitized) lub umieszczone w środowisku piaskownicy.                                                                                                  | ✓  | ✓  | ✓  | 94  |
| **5.2.6** | Sprawdź, czy aplikacja chroni przed atakami SSRF (Server-Side Request Forgery), poprzez walidację lub dezynfekcję (sanitization) niezaufanych danych lub metadanych plików HTTP, takich jak nazwy plików czy pola wprowadzania adresów URL, oraz stosowanie list dozwolonych wartości (allow lists) dla protokołów, domen, ścieżek i portów. | ✓  | ✓  | ✓  | 918 |
| **5.2.7** | Sprawdź, czy aplikacja czyści (sanitizes), wyłącza lub umieszcza w środowisku piaskownicy treści z wektorowych grafik skalowalnych (SVG) dostarczanych przez użytkowników, zwłaszcza te, które dotyczą ataków XSS wynikających z osadzonych skryptów oraz foreignObject.                                                                     | ✓  | ✓  | ✓  | 159 |
| **5.2.8** | Sprawdź, czy aplikacja czyści (sanitizes), wyłącza lub umieszcza w środowisku piaskownicy treści z języków szablonów lub wyrażeń, które umożliwiają osadzanie skryptów lub kodu, takich jak Markdown, arkusze stylów CSS lub XSL, BBCode lub podobne.                                                                                        | ✓  | ✓  | ✓  | 94  |

## V5.3 Kodowanie Wyników i Zapobieganie Atakom typu "Injection"

Kodowanie danych wyjściowych (output encoding) w pobliżu lub tuż przy interpreterze używanym przez aplikację jest kluczowe dla bezpieczeństwa każdej aplikacji. Zwykle kodowanie wyników nie jest trwałe, ale jest wykorzystywane do bezpiecznego renderowania wyników w odpowiednim kontekście wyjściowym. Niezastosowanie kodowania danych wyjściowych skutkuje niezabezpieczoną, podatną na wstrzykiwanie, niebezpieczną aplikacją.

|     #      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | L1 | L2 | L3 | CWE |
|:----------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **5.3.1**  | Sprawdź, czy kodowanie danych wyjściowych jest odpowiednie dla danego interpretera i kontekstu. Na przykład, używaj konkretnych encoderów dla wartości HTML, atrybutów HTML, JavaScriptu, parametrów URL, nagłówków HTTP, SMTP i innych, zgodnie z wymaganiami kontekstu, szczególnie w przypadku danych wejściowych pochodzących z niezaufanych źródeł (np. nazwy z Unicode lub apostrofami, takie jak ねこ lub O'Hara). ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓  | ✓  | ✓  | 116 |
| **5.3.2**  | Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                                                    | ✓  | ✓  | ✓  | 176 |
| **5.3.3**  | Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                                                          | ✓  | ✓  | ✓  | 79  |
| **5.3.4**  | Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                              | ✓  | ✓  | ✓  | 89  |
| **5.3.5**  | Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection. ([C3, C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                               | ✓  | ✓  | ✓  | 89  |
| **5.3.6**  | Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                                                                           | ✓  | ✓  | ✓  | 830 |
| **5.3.7**  | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                                        | ✓  | ✓  | ✓  | 90  |
| **5.3.8**  | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                          | ✓  | ✓  | ✓  | 78  |
| **5.3.9**  | Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks.                                                                                                                                                                                                                                                                                                                                                                                 | ✓  | ✓  | ✓  | 829 |
| **5.3.10** | Verify that the application protects against XPath injection or XML injection attacks. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                                                                                                                                  | ✓  | ✓  | ✓  | 643 |

Note: Using parameterized queries or escaping SQL is not always sufficient; table and column names, ORDER BY and so on, cannot be escaped. The inclusion of escaped user-supplied data in these fields results in failed queries or SQL injection.

Note: The SVG format explicitly allows ECMA script in almost all contexts, so it may not be possible to block all SVG XSS vectors completely. If SVG upload is required, we strongly recommend either serving these uploaded files as text/plain or using a separate user supplied content domain to prevent successful XSS from taking over the application.

## V5.4 Memory, String, and Unmanaged Code

The following requirements will only apply when the application uses a systems language or unmanaged code.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.4.1** | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | | ✓ | ✓ | 120 |
| **5.4.2** | Verify that format strings do not take potentially hostile input, and are constant. | | ✓ | ✓ | 134 |
| **5.4.3** | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | | ✓ | ✓ | 190 |

## V5.5 Deserialization Prevention

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.5.1** | Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 502 |
| **5.5.2** | Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | ✓ | ✓ | ✓ | 611 |
| **5.5.3** | Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers). | ✓ | ✓ | ✓ | 502 |
| **5.5.4** | Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON. | ✓ | ✓ | ✓ | 95 |

## References

For more information, see also:

* [OWASP Testing Guide 4.0: Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README.html)
* [OWASP Cheat Sheet: Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [OWASP Testing Guide 4.0: Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html)
* [OWASP LDAP Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Testing Guide 4.0: Client Side Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/)
* [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP DOM Based Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP Java Encoding Project](https://owasp.org/owasp-java-encoder/)
* [OWASP Mass Assignment Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
* [DOMPurify - Client-side HTML Sanitization Library](https://github.com/cure53/DOMPurify)
* [XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

For more information on auto-escaping, please see:

* [Reducing XSS by way of Automatic Context-Aware Escaping in Template Systems](https://googleonlinesecurity.blogspot.com/2009/03/reducing-xss-by-way-of-automatic.html)
* [AngularJS Strict Contextual Escaping](https://docs.angularjs.org/api/ng/service/$sce)
* [AngularJS ngBind](https://docs.angularjs.org/api/ng/directive/ngBind)
* [Angular Sanitization](https://angular.io/guide/security#sanitization-and-security-contexts)
* [Angular Security](https://angular.io/guide/security)
* [ReactJS Escaping](https://reactjs.org/docs/introducing-jsx.html#jsx-prevents-injection-attacks)
* [Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

For more information on deserialization, please see:

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [OWASP Deserialization of Untrusted Data Guide](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
