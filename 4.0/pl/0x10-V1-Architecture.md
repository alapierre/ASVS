# V1 Architektura, Projektowanie i Modelowanie Zagrożeń

## Cele Kontrolne

Architektura bezpieczeństwa stała się niemal zaginioną sztuką w wielu organizacjach. Czasy architekta korporacyjnego minęły w epoce DevSecOps. Dziedzina bezpieczeństwa aplikacji musi nadrobić zaległości i przyjąć zwinne zasady bezpieczeństwa, jednocześnie wprowadzając na nowo czołowe zasady architektury bezpieczeństwa dla praktyków oprogramowania. Architektura to nie implementacja, ale sposób myślenia o problemie, który może mieć wiele różnych odpowiedzi i nie ma jednej jedynie "poprawnej" odpowiedzi. Zbyt często bezpieczeństwo postrzega się jako sztywne i wymagające od programistów naprawiania kodu w określony sposób, gdy programiści mogą znać znacznie lepszy sposób rozwiązania problemu. Nie ma jednego, prostego rozwiązania dla architektury, a twierdzenie przeciwne to krzywda dla dziedziny inżynierii oprogramowania.

Konkretna implementacja aplikacji internetowej prawdopodobnie będzie wielokrotnie modyfikowana w trakcie jej życia, ale ogólna architektura rzadko ulegnie zmianie, będzie się powoli rozwijać. Podobnie jest z architekturą bezpieczeństwa — potrzebujemy uwierzytelniania dziś, będziemy potrzebować uwierzytelniania jutro i będziemy go potrzebować za pięć lat. Jeśli podejmiemy właściwe decyzje dziś, możemy zaoszczędzić wiele wysiłku, czasu i pieniędzy, jeśli wybierzemy i będziemy ponownie wykorzystywać sprawdzone rozwiązania architektoniczne. Na przykład dekadę temu, rzadko stosowano wieloskładnikowe uwierzytelnianie.

Gdyby deweloperzy zainwestowali w jeden, bezpieczny model dostawcy tożsamości, taki jak federacyjna tożsamość SAML, dostawca tożsamości mógłby być aktualizowany, aby uwzględnić nowe wymagania, takie jak zgodność z NIST 800-63, bez konieczności zmiany interfejsów oryginalnej aplikacji. Jeśli wiele aplikacji współdzieliłoby tą samą architekturę bezpieczeństwa, a co za tym idzie ten sam komponent, wszystkie mogłyby korzystać z jej aktualizacji jednocześnie. Jednak SAML nie pozostanie zawsze najlepszym ani najbardziej odpowiednim rozwiązaniem uwierzytelniania — może być konieczna zamiana go na inne rozwiązania, gdy zmienią się wymagania. Takie zmiany są skomplikowane i kosztowne, często wymagają całkowitego przepisania i są niemożliwe bez architektury bezpieczeństwa.

W tym rozdziale ASVS omawia podstawowe aspekty każdej solidnej architektury bezpieczeństwa: dostępność, poufność, integralność przetwarzania, niezaprzeczalność i prywatność. Każda z tych zasad bezpieczeństwa musi być wbudowana i być nieodłączną częścią wszystkich aplikacji. Kluczowe jest "przesunięcie w lewo", zaczynając od zapoznania programistów z listami kontrolnymi bezpiecznego kodowania, mentoringiem i szkoleniem, kodowaniem i testowaniem, budowaniem, wdrażaniem, konfiguracją i operacjami, a kończąc na niezależnych testach kontrolnych, które mają na celu zapewnienie, że wszystkie kontrole bezpieczeństwa są obecne i funkcjonują. Ostatni krok był tym, co robiliśmy jako branża, ale nie jest już wystarczający dziś, gdy programiści wprowadzają kod do produkcji dziesiątki lub setki razy dziennie. Specjaliści ds. bezpieczeństwa aplikacji muszą nadążać za zwinnością technik, co oznacza przyjmowanie narzędzi programistycznych, uczenie się kodowania i współpracę z programistami, a nie krytykowanie projektu miesiącami po tym, jak wszyscy inni poszli dalej.

## V1.1 Bezpieczny rozwoj oprogramowania

|     #     | Opis                                                                                                                                                                                                                                                                                                                                | L1 | L2 | L3 | CWE  |
|:---------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|
| **1.1.1** | Sprawdź jaki proces bezpiecznego rozwoju oprogramowania wdrożono, oraz to czy uwzględnia on aspekty bezpieczeństwa we wszystkich etapach rozwoju. ([C1](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                           |    | ✓  | ✓  |      |
| **1.1.2** | Sprawdź wykorzystanie modelowania zagrożeń dla każdej zmiany w projekcie lub planowanie sprintu w celu identyfikacji zagrożeń, planowania środków zaradczych, ułatwienia odpowiedniej reakcji na ryzyko oraz sterowania testami bezpieczeństwa.                                                                                     |    | ✓  | ✓  | 1053 |
| **1.1.3** | Sprawdź, czy wszystkie `User Stories` i opisy funkcjonalności zawierają ograniczenia bezpieczeństwa, takie jak "Jako użytkownik, powinienem móc przeglądać i edytować swój profil. Nie powinienem mieć możliwości przeglądania ani edycji profilu innych osób".                                                                     |    | ✓  | ✓  | 1110 |
| **1.1.4** | Sprawdź dokumentację i uzasadnienie wszystkich granic zaufania, komponentów oraz istotnych przepływów danych w aplikacji.                                                                                                                                                                                                           |    | ✓  | ✓  | 1059 |
| **1.1.5** | Sprawdź definicję i analizę bezpieczeństwa wysokopoziomowej architektury aplikacji oraz wszystkich wykorzystywanych usług zdalnych. ([C1](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                         |    | ✓  | ✓  | 1059 |
| **1.1.6** | Sprawdź wdrożenie scentralizowanych, prostych (oszczędność projektu), sprawdzonych, bezpiecznych i nadających się do wielokrotnego użytku mechanizmów zabezpieczeń, aby uniknąć zduplikowanych, brakujących, nieskutecznych lub niebezpiecznych rozwiązań. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 637  |
| **1.1.7** | Sprawdź dostępność listy kontrolnej bezpiecznego kodowania, wymagań bezpieczeństwa, wytycznych lub polityki dla wszystkich programistów i testerów.                                                                                                                                                                                 |    | ✓  | ✓  | 637  |

## V1.2 Architektura Uwierzytelniania

Podczas projektowania uwierzytelniania nie ma znaczenia, czy posiadasz silne uwierzytelnianie wieloskładnikowe z obsługą sprzętu, jeśli atakujący może zresetować konto, dzwoniąc do centrum obsługi klienta i odpowiadając na powszechnie znane pytania. Podczas potwierdzania tożsamości, wszystkie ścieżki uwierzytelniania muszą mieć taką samą siłę.

|     #     | Opis                                                                                                                                                                                                                                                                             | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.2.1** | Sprawdź czy są wykorzystywane unikalne lub specjalne konta systemu operacyjnego o niskich uprawnieniach dla wszystkich komponentów aplikacji, usług i serwerów. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering))                                          |    | ✓  | ✓  | 250 |
| **1.2.2** | Sprawdź, czy komunikacja pomiędzy komponentami aplikacji, w tym API, warstwą pośrednią i warstwą danych, jest uwierzytelniana. Komponenty powinny posiadać minimalne niezbędne uprawnienia. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering))              |    | ✓  | ✓  | 306 |
| **1.2.3** | Sprawdź, czy aplikacja korzysta z pojedynczego sprawdzonego mechanizmu uwierzytelniania, który jest uznawany jako bezpieczny, może być rozszerzony o silne uwierzytelnianie oraz posiada wystarczające rejestrowanie i monitorowanie, aby wykryć nadużycia konta lub naruszenia. |    | ✓  | ✓  | 306 |
| **1.2.4** | Sprawdź, czy wszystkie ścieżki uwierzytelniania i interfejsy API do zarządzania tożsamością implementują spójną siłę kontroli bezpieczeństwa uwierzytelniania, tak aby nie istniały słabsze alternatywy w stosunku do poziomu ryzyka związanego z aplikacją.                     |    | ✓  | ✓  | 306 |

## V1.3 Session Management Architecture

This is a placeholder for future architectural requirements.

## V1.4 Access Control Architecture

|     #     | Description                                                                                                                                                                                                                                                                                                   | L1 | L2 | L3 | CWE |
|:---------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.4.1** | Verify that trusted enforcement points, such as access control gateways, servers, and serverless functions, enforce access controls. Never enforce access controls on the client.                                                                                                                             |    | ✓  | ✓  | 602 |
| **1.4.2** | [DELETED, NOT ACTIONABLE]                                                                                                                                                                                                                                                                                     |    |    |    |     |
| **1.4.3** | [DELETED, DUPLICATE OF 4.1.3]                                                                                                                                                                                                                                                                                 |    |    |    |     |
| **1.4.4** | Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this single mechanism to avoid copy and paste or insecure alternative paths. ([C7](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 284 |
| **1.4.5** | Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role. Permissions should still be allocated using roles. ([C7](https://owasp.org/www-project-proactive-controls/#div-numbering))                |    | ✓  | ✓  | 275 |

## V1.5 Input and Output Architecture

In 4.0, we have moved away from the term "server-side" as a loaded trust boundary term. The trust boundary is still concerning - making decisions on untrusted browsers or client devices is bypassable. However, in mainstream architectural deployments today, the trust enforcement point has dramatically changed. Therefore, where the term "trusted service layer" is used in the ASVS, we mean any trusted enforcement point, regardless of location, such as a microservice, serverless API, server-side, a trusted API on a client device that has secure boot, partner or external APIs, and so on.

The "untrusted client" term here refers to client-side technologies that render the presentation layer, commonly refered to as 'front-end' technologies. The term "serialization" here not only refers to sending data over the wire like an array of values or taking and reading a JSON structure, but also passing complex objects which can contain logic.

|     #     | Description                                                                                                                                                                                                                                                                       | L1 | L2 | L3 | CWE  |
|:---------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|
| **1.5.1** | Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws, regulations, and other policy compliance.                                                                                                    |    | ✓  | ✓  | 1029 |
| **1.5.2** | Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity controls (and possibly encryption if sensitive data is sent) are enforced to prevent deserialization attacks including object injection. |    | ✓  | ✓  | 502  |
| **1.5.3** | Verify that input validation is enforced on a trusted service layer. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                      |    | ✓  | ✓  | 602  |
| **1.5.4** | Verify that output encoding occurs close to or by the interpreter for which it is intended. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                               |    | ✓  | ✓  | 116  |

## V1.6 Cryptographic Architecture

Applications need to be designed with strong cryptographic architecture to protect data assets as per their classification. Encrypting everything is wasteful, not encrypting anything is legally negligent. A balance must be struck, usually during architectural or high level design, design sprints or architectural spikes. Designing cryptography as you go or retrofitting it will inevitably cost much more to implement securely than simply building it in from the start.

Architectural requirements are intrinsic to the entire code base, and thus difficult to unit or integrate test. Architectural requirements require consideration in coding standards, throughout the coding phase, and should be reviewed during security architecture, peer or code reviews, or retrospectives.

|     #     | Description                                                                                                                                                                     | L1 | L2 | L3 | CWE |
|:---------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.6.1** | Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key management standard such as NIST SP 800-57.   |    | ✓  | ✓  | 320 |
| **1.6.2** | Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API based alternatives.                                           |    | ✓  | ✓  | 320 |
| **1.6.3** | Verify that all keys and passwords are replaceable and are part of a well-defined process to re-encrypt sensitive data.                                                         |    | ✓  | ✓  | 320 |
| **1.6.4** | Verify that the architecture treats client-side secrets--such as symmetric keys, passwords, or API tokens--as insecure and never uses them to protect or access sensitive data. |    | ✓  | ✓  | 320 |

## V1.7 Errors, Logging and Auditing Architecture

|     #     | Description                                                                                                                                                                                        | L1 | L2 | L3 | CWE  |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|
| **1.7.1** | Verify that a common logging format and approach is used across the system. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                |    | ✓  | ✓  | 1009 |
| **1.7.2** | Verify that logs are securely transmitted to a preferably remote system for analysis, detection, alerting, and escalation. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  |      |

## V1.8 Data Protection and Privacy Architecture

|     #     | Description                                                                                                                                                                                                                                              | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.8.1** | Verify that all sensitive data is identified and classified into protection levels.                                                                                                                                                                      |    | ✓  | ✓  |     |
| **1.8.2** | Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity requirements, retention, privacy and other confidentiality requirements, and that these are applied in the architecture. |    | ✓  | ✓  |     |

## V1.9 Communications Architecture

|     #     | Description                                                                                                                                                                                                                                    | L1 | L2 | L3 | CWE |
|:---------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.9.1** | Verify the application encrypts communications between components, particularly when these components are in different containers, systems, sites, or cloud providers. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 319 |
| **1.9.2** | Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks. For example, application components should validate TLS certificates and chains.                      |    | ✓  | ✓  | 295 |

## V1.10 Malicious Software Architecture

|     #      | Description                                                                                                                                                                                                                                                      | L1 | L2 | L3 | CWE |
|:----------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.10.1** | Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system should have access control and identifiable users to allow traceability of any changes. |    | ✓  | ✓  | 284 |

## V1.11 Business Logic Architecture

|     #      | Description                                                                                                                                                                                      | L1 | L2 | L3 | CWE  |
|:----------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|
| **1.11.1** | Verify the definition and documentation of all application components in terms of the business or security functions they provide.                                                               |    | ✓  | ✓  | 1059 |
| **1.11.2** | Verify that all high-value business logic flows, including authentication, session management and access control, do not share unsynchronized state.                                             |    | ✓  | ✓  | 362  |
| **1.11.3** | Verify that all high-value business logic flows, including authentication, session management and access control are thread safe and resistant to time-of-check and time-of-use race conditions. |    |    | ✓  | 367  |

## V1.12 Secure File Upload Architecture

|     #      | Description                                                                                                                                                                                                                                                                                                                                       | L1 | L2 | L3 | CWE |
|:----------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **1.12.1** | [DELETED, DUPLICATE OF 12.4.1]                                                                                                                                                                                                                                                                                                                    |    |    |    |     |
| **1.12.2** | Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, such as a cloud file storage bucket. Implement a suitable Content Security Policy (CSP) to reduce the risk from XSS vectors or other attacks from the uploaded file. |    | ✓  | ✓  | 646 |

## V1.13 API Architecture

This is a placeholder for future architectural requirements.

## V1.14 Configuration Architecture

|     #      | Description                                                                                                                                                                                                                                                                                                                                  | L1 | L2 | L3 | CWE  |
|:----------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|
| **1.14.1** | Verify the segregation of components of differing trust levels through well-defined security controls, firewall rules, API gateways, reverse proxies, cloud-based security groups, or similar mechanisms.                                                                                                                                    |    | ✓  | ✓  | 923  |
| **1.14.2** | Verify that binary signatures, trusted connections, and verified endpoints are used to deploy binaries to remote devices.                                                                                                                                                                                                                    |    | ✓  | ✓  | 494  |
| **1.14.3** | Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions.                                                                                                                                                                                                                                    |    | ✓  | ✓  | 1104 |
| **1.14.4** | Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application infrastructure is software defined, such as cloud environment build scripts.                                                                                                |    | ✓  | ✓  |      |
| **1.14.5** | Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers from attacking other applications, especially when they are performing sensitive or dangerous actions such as deserialization. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 265  |
| **1.14.6** | Verify the application does not use unsupported, insecure, or deprecated client-side technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets.                                                                                                                                          |    | ✓  | ✓  | 477  |

## References

For more information, see also:

* [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
* [OWASP Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
* [OWASP Threat modeling](https://owasp.org/www-community/Application_Threat_Modeling)
* [OWASP Software Assurance Maturity Model Project](https://owasp.org/www-project-samm/)
* [Microsoft SDL](https://www.microsoft.com/en-us/sdl/)
* [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
