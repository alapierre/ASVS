# V7 Obsługa błędów i logowanie

## Cele kontroli

Głównym celem obsługi błędów i zapisywania logów jest dostarczenie przydatnych informacji dla użytkowników, administratorów i zespołów reagowania na incydenty. Celem nie jest tworzenie ogromnej ilości logów, lecz logów wysokiej jakości, z większą ilością pomocnych w rozwiązywaniu problemów informacji niż zbędnego szumu.

Logi wysokiej jakości często zawierają poufne dane i muszą być chronione zgodnie z lokalnymi przepisami o ochronie prywatności danych. Powinno to obejmować:

* Niezbieranie ani nierejestrowanie wrażliwych informacji, chyba że jest to wyraźnie wymagane.
* Zapewnienie, że wszystkie zarejestrowane informacje są obsługiwane w sposób bezpieczny i są chronione zgodnie z ich klasyfikacją danych.
* Zapewnienie, że logi nie są przechowywane w nieskończoność, ale mają jak najkrótszy czas przechowywania.

Jeśli logi zawierają prywatne lub poufne dane, których definicja różni się w zależności od kraju, logi te stają się jednymi z najbardziej wrażliwych informacji przechowywanych przez aplikację, a tym samym są bardzo atrakcyjnym celem dla atakujących.

Równie ważne jest, aby upewnić się, że aplikacja reaguje na błędy w sposób bezpieczny i nie ujawnia niepotrzebnych, zbyt szerokich informacji.

## V7.1 Zawartość logów

Rejestrowanie poufnych informacji jest niebezpieczne — logi stają się wówczas informacjami sklasyfikowanymi, co oznacza, że muszą być szyfrowane, podlegają politykom retencji danych. Logi często muszą być ujawniane "osobom trzecim" podczas audytów bezpieczeństwa, co może powodować naruszenie przepisów o ochronie danych osobowych lub naruszeniem tajemnicy przedsiębiorstwa. Upewnij się, że w logach przechowywane są tylko niezbędne informacje. Logi nie powinny zwierać informacji dotyczących płatności, poświadczeń (w tym tokenów sesji), informacji poufnych czy umożliwiających identyfikację osób fizycznych (dane osobowe zgodnie z definicją zawartą w artykule 4 RODO).

Sekcja `V7.1` dotyczy `OWASP Top 10 2017: A10`. Ponieważ wymagania tej sekcji nie są możliwe do przetestowania podczas testów penetracyjnych, ważne jest, aby:

* Deweloperzy zapewnili pełną zgodność z tą sekcją, tak jakby wszystkie pozycje były oznaczone jako L1.
* Audytorzy sprawdzili pełną zgodność wszystkich pozycji sekcji `V7.1` za pomocą wywiadów, zrzutów ekranu lub innych zapewnień ze strony zespołu.

|     #     | Opis                                                                                                                                                                                                                                                                                               | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **7.1.1** | Sprawdź, czy aplikacja nie rejestruje danych uwierzytelniających ani informacji o płatnościach. Tokeny sesji powinny być przechowywane w logach tylko w formie skrótów kryptograficznych. ([C9, C10](https://owasp.org/www-project-proactive-controls/#div-numbering))                             | ✓  | ✓  | ✓  | 532 |
| **7.1.2** | Sprawdź, czy aplikacja nie rejestruje innych poufnych informacji, zgodnie z lokalnymi przepisami o ochronie prywatności (np. RODO, Ustawa o Ochronie Danych Osobowych) lub polityką bezpieczeństwa stosowną w Organizacji. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓  | ✓  | ✓  | 532 |
| **7.1.3** | Sprawdź, czy aplikacja rejestruje zdarzenia istotne dla bezpieczeństwa, w tym udane i nieudane próby uwierzytelnienia, niepowodzenia kontroli dostępu, błędy deserializacji oraz błędy walidacji danych wejściowych. ([C5, C7](https://owasp.org/www-project-proactive-controls/#div-numbering))   |    | ✓  | ✓  | 778 |
| **7.1.4** | Sprawdź, czy każde zdarzenie logowania zawiera niezbędne informacje, które pozwolą określenie momentu wystąpienia danego zdarzenia. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                        |    | ✓  | ✓  | 778 |

## V7.2 Log Processing

Rejestrowanie logów w odpowiednim czasie w sposób świadomy i przemyślany jest kluczowe dla analizy zdarzeń, oceny sytuacji oraz eskalacji. Upewnij się, że logi aplikacji są czytelne i można je łatwo monitorować oraz analizować, zarówno na poziomie lokalnym, jak i w przypadku przesyłania ich do zdalnego systemu monitorowania.

Sekcja `V7.2` dotyczy `OWASP Top 10 2017: A10`. Ponieważ wymagania tej sekcji nie są możliwe do przetestowania podczas testów penetracyjnych, ważne jest, aby:

* Deweloperzy zapewnili pełną zgodność z tą sekcją, tak jakby wszystkie pozycje były oznaczone jako L1.
* Audytorzy sprawdzili pełną zgodność wszystkich pozycji sekcji `V7.1` za pomocą wywiadów, zrzutów ekranu lub innych zapewnień ze strony zespołu.

|     #     | Opis                                                                                                                                                                                                                                                                                                             | L1 | L2 | L3 | CWE |
|:---------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **7.2.1** | Sprawdź, czy wszystkie podjęte przez aplikacje decyzje dotyczące uwierzytelniania są rejestrowane, bez przechowywania wrażliwych tokenów sesji czy haseł. Powinno to obejmować żądania zawierające istotne metadane potrzebne do przeprowadzenia postępowania (dochodzenia) w zakresie bezpieczeństwa.           |    | ✓  | ✓  | 778 |
| **7.2.2** | Sprawdź, czy wszystkie decyzje dotyczące kontroli dostępu można w razie potrzeby rejestrować, oraz czy wszystkie nieudane próby dostępu są faktycznie rejestrowane. Powinno to obejmować żądania zawierające istotne metadane potrzebne do przeprowadzenia postępowania (dochodzenia) w zakresie bezpieczeństwa. |    | ✓  | ✓  | 285 |

## V7.3 Zabezpieczenie logów

Logi, które można łatwo modyfikować lub usuwać, są bezużyteczne dla śledztwa i postępowania sądowego. Kradzież lub przejęcie logów może ujawnić wewnętrzne szczegóły na temat aplikacji, lub danych, które aplikacja zawiera. Należy zachować ostrożność i chronić logi przed nieautoryzowanym ujawnieniem, modyfikacją lub usunięciem.

|     #     | Opis                                                                                                                                                                                                                                                                                                           | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **7.3.1** | Sprawdź, czy wszystkie komponenty logujące odpowiednio zapisują dane tak, aby zapobiec "log injection". ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                |    | ✓  | ✓  | 117 |
| **7.3.2** | [USUNIĘTE, DUPLIKAT 7.3.1]                                                                                                                                                                                                                                                                                     |    |    |    |     |
| **7.3.3** | Sprawdź, czy logi dotyczące bezpieczeństwa są chronione przed nieautoryzowanym dostępem i modyfikacją. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                 |    | ✓  | ✓  | 200 |
| **7.3.4** | Sprawdź, czy źródła czasu są zsynchronizowane z właściwym czasem i strefą czasową. W przypadku systemów globalnych rozważ rejestrowanie wyłącznie w czasie uniwersalnym (UTC), aby ułatwić analizę sądowo-informatyczną po incydencie. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  |     |

Uwaga: Log encoding (7.3.1) jest trudne do przetestowania i oceny za pomocą narzędzi automatycznych oraz testów penetracyjnych, jednak architekci, deweloperzy oraz osoby przeglądające kod źródłowy powinny traktować to jako wymóg na poziomie L1.

## V7.4 Obsługa błędów

Celem obsługi błędów jest umożliwienie aplikacji rejestrowania istotnych zdarzeń, również tych związanych z bezpieczeństwem, które mogą być monitorowane, oceniane i eskalowane. Celem nie jest tworzenie logów jako takich. Rejestrując zdarzenia związane z bezpieczeństwem, upewnij się, że logowanie ma określony cel i że może być przetwarzane przez oprogramowanie do analizy lub systemy SIEM (Security Information and Event Management).

|     #     | Opis                                                                                                                                                                                                                                                                                                                | L1 | L2 | L3 | CWE |
|:---------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **7.4.1** | Sprawdź, czy poza ogólnym komunikatem, w przypadku wystąpienia nieoczekiwanego błędu lub błędu związanego z bezpieczeństwem rejestrowany jest także unikalny identyfikator, który personel techniczny może wykorzystać do dalszej analizy. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓  | ✓  | ✓  | 210 |
| **7.4.2** | Sprawdź, czy obsługa wyjątków (lub równoważna funkcjonalność) jest stosowana w całej bazie kodu w celu uwzględnienia oczekiwanych i nieoczekiwanych warunków wystąpienia błędów. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                           |    | ✓  | ✓  | 544 |
| **7.4.3** | Zweryfikuj, że jest zdefiniowany "last resort error handler" (globalny mechanizm obsługo wyjątków), który obsługuje wszystkie nieobsłużone w inny sposób wyjątki. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                          |    | ✓  | ✓  | 431 |

Uwaga: Niektóre języki programowania, takie jak Swift i Go — a także wiele języków funkcyjnych poprzez przyjęte założenia projektowe — nie obsługują wyjątków lub "last resort error handler" (globalnego mechanizmu obsługo wyjątków). W takim przypadku architekci i programiści powinni użyć wzorca, języka lub przyjaznego frameworka w celu zapewnienia, że aplikacje mogą bezpiecznie obsługiwać wyjątkowe, nieoczekiwane lub związane z bezpieczeństwem zdarzenia.

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [OWASP Testing Guide 4.0 content: Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README.html)
* [OWASP Authentication Cheat Sheet section about error messages](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages)
