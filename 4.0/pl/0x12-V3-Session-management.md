# V3 Zarządzanie sesją

## Cel kontrolny

Jednym z podstawowych składników dowolnej aplikacji internetowej lub stanowego interfejsu API jest mechanizm, za pomocą którego kontroluje i utrzymuje stan interakcji użytkownika lub urządzenia. Zarządzanie sesją zmienia protokół bezstanowy na stanowy, co ma kluczowe znaczenie dla rozróżniania użytkowników lub urządzeń.

Upewnij się, że zweryfikowana aplikacja spełnia następujące ogólne wymagania dotyczące zarządzania sesją:

* Sesje są unikalne dla każdej osoby i nie można ich odgadnąć ani udostępnić.
* Sesje są unieważniane, gdy nie są już potrzebne i wygasają w okresach bezczynności.

Jak wcześniej zauważono, wymagania te zostały dostosowane do zgodnego podzbioru wybranych kontroli NIST 800-63b, koncentrując się na typowych zagrożeniach i często wykorzystywanych słabościach uwierzytelniania. Poprzednie wymagania weryfikacyjne zostały wycofane, usunięte lub w większości przypadków dostosowane, aby były ściśle zgodne z intencją obowiązkowych wymagań [NIST 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html).

## Wymagania dotyczące weryfikacji bezpieczeństwa

## V3.1 Podstawowe zabezpieczenia zarządzania sesją

|     #     | Opis                                                                             | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:---------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|:-------------------------------------------------------------:|
| **3.1.1** | Sprawdź, czy aplikacja nigdy nie ujawnia tokenów sesji w parametrach adresu URL. | ✓  | ✓  | ✓  | 598 |                                                               |

## V3.2 Wiązanie sesji

|     #     | Opis                                                                                                                                                                                                                                                             | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|:-------------------------------------------------------------:|
| **3.2.1** | Sprawdź, czy aplikacja generuje nowy token sesji podczas uwierzytelniania użytkownika. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                   | ✓  | ✓  | ✓  | 384 |                              7.1                              |
| **3.2.2** | Sprawdź, czy tokeny sesji mają co najmniej 64 bity entropii. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                             | ✓  | ✓  | ✓  | 331 |                              7.1                              |
| **3.2.3** | Sprawdź, czy aplikacja przechowuje tokeny sesji w przeglądarce tylko przy użyciu bezpiecznych metod, takich jak odpowiednio zabezpieczone pliki cookie (patrz sekcja 3.4) lub przechowuje dane sesji w pamięci podręcznej przeglądarki (HTML 5 session storage). | ✓  | ✓  | ✓  | 539 |                              7.1                              |
| **3.2.4** | Sprawdź, czy tokeny sesji są generowane przy użyciu zatwierdzonych algorytmów kryptograficznych. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                         |    | ✓  | ✓  | 331 |                              7.1                              |

TLS lub inny bezpieczny kanał transportowy jest obowiązkowy do zarządzania sesją. Jest to omówione w rozdziale poświęconym bezpieczeństwu komunikacji.

## V3.3 Zakończenie sesji

Limity czasu sesji zostały dostosowane do NIST 800-63, który zezwala na znacznie dłuższe limity czasu sesji niż tradycyjnie dozwolone przez standardy bezpieczeństwa. Organizacje powinny przejrzeć poniższą tabelę i jeśli na podstawie ryzyka związanego z aplikacją, wymagany jest dłuższy limit czasu, wartość NIST powinna być górną granicą limitów czasu bezczynności sesji.

L1 w tym kontekście to IAL1/AAL1, L2 to IAL2/AAL3, L3 to IAL3/AAL3. W przypadku IAL2/AAL2 i IAL3/AAL3 krótszy limit czasu bezczynności to dolna granica czasu bezczynności dla wylogowania lub ponownego uwierzytelnienia w celu wznowienia sesji.

|     #     | Opis                                                                                                                                                                                                                                                                                                        |   L1   |                          L2                          |                         L3                          | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------:|:----------------------------------------------------:|:---------------------------------------------------:|:---:|:-------------------------------------------------------------:|
| **3.3.1** | Sprawdź, czy wylogowanie i wygaśnięcie unieważniają token sesji, tak aby przycisk Wstecz lub wejście na inną stronę wymagającej sesji nie wznawiało uwierzytelnionej sesji. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                         |   ✓    |                          ✓                           |                          ✓                          | 613 |                              7.1                              |
| **3.3.2** | Jeśli mechanizmy autoryzujące pozwalają użytkownikom pozostać zalogowanymi, sprawdź, czy ponowne uwierzytelnianie odbywa się okresowo, zarówno podczas aktywnego używania, jak i po okresie bezczynności. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                           | 30 dni | 12 godzin lub 30 minut nieaktywności, 2FA opcjonalne | 12 godzin lub 15 minut nieaktywności, z użyciem 2FA | 613 |                              7.2                              |
| **3.3.3** | Sprawdź, czy aplikacja umożliwia zakończenie wszystkich innych aktywnych sesji po pomyślnej zmianie hasła (w tym zmianie poprzez zresetowanie/odzyskanie hasła) i czy jest to skuteczne w całej aplikacji, logowaniu federacyjnym (Federated identity) (jeśli istnieje) i wszystkich jednostkach ufających. |        |                          ✓                           |                          ✓                          | 613 |                                                               |
| **3.3.4** | Sprawdź, czy użytkownicy mogą przeglądać i (po ponownym wprowadzeniu danych logowania) wylogować się z dowolnej lub wszystkich aktualnie aktywnych sesji i urządzeń.                                                                                                                                        |        |                          ✓                           |                          ✓                          | 613 |                              7.1                              |

## V3.4 Zarządzanie sesją oparte na plikach cookie

|     #     | Opis                                                                                                                                                                                                                                                                                                                                                                              | L1 | L2 | L3 | CWE  | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:----:|:-------------------------------------------------------------:|
| **3.4.1** | Sprawdź, czy tokeny sesji oparte na plikach cookie mają ustawiony atrybut `Secure`. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                       | ✓  | ✓  | ✓  | 614  |                             7.1.1                             |
| **3.4.2** | Sprawdź, czy tokeny sesji oparte na plikach cookie mają ustawiony atrybut `HttpOnly`. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                                                                                                     | ✓  | ✓  | ✓  | 1004 |                             7.1.1                             |
| **3.4.3** | Sprawdź, czy tokeny sesji oparte na plikach cookie wykorzystują atrybut `SameSite`, aby ograniczyć narażenie na ataki polegające na fałszowaniu żądań między witrynami. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                                   | ✓  | ✓  | ✓  |  16  |                             7.1.1                             |
| **3.4.4** | Sprawdź, czy tokeny sesji oparte na plikach cookie używają prefiksu `__Host-`, aby pliki cookie były wysyłane tylko do hosta, który początkowo ustawił plik cookie.                                                                                                                                                                                                               | ✓  | ✓  | ✓  |  16  |                             7.1.1                             |
| **3.4.5** | Sprawdź, czy jeśli aplikacja jest opublikowana pod nazwą domeny wraz z innymi aplikacjami, które ustawiają lub używają sesyjnych plików cookie, które mogą ujawniać sesyjne pliki cookie, ustaw atrybut ścieżki w tokenach sesji opartych na plikach cookie, używając możliwie najdokładniejszej ścieżki. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓  | ✓  | ✓  |  16  |                             7.1.1                             |

## V3.5 Zarządzanie sesją oparte na tokenach

Zarządzanie sesjami w oparciu o tokeny obejmuje klucze JWT, OAuth, SAML i API. Spośród nich klucze API są uznawane za słabe i nie powinny być używane w nowym kodzie.

|     #     | Opis                                                                                                                                                                                                                                                                                                        | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|:-------------------------------------------------------------:|
| **3.5.1** | Sprawdź, czy aplikacja umożliwia użytkownikom odwoływanie tokenów OAuth, które tworzą relacje zaufania z połączonymi aplikacjami.                                                                                                                                                                           |    | ✓  | ✓  | 290 |                             7.1.2                             |
| **3.5.2** | Sprawdź, czy aplikacja używa tokenów sesji, a nie statycznych sekretów API i kluczy, z wyjątkiem starszych implementacji.                                                                                                                                                                                   |    | ✓  | ✓  | 798 |                                                               |
| **3.5.3** | Sprawdź, czy bezstanowe tokeny sesji używają podpisów cyfrowych, szyfrowania i innych środków zaradczych w celu ochrony przed manipulacją (tampering), otaczaniem (enveloping), powtarzaniem (replay), szyfrowaniem zerowym (null cipher) i atakami polegającymi na podstawieniu klucza (key substitution). |    | ✓  | ✓  | 345 |                                                               |

## V3.6 Federacyjne ponowne uwierzytelnianie

Ta sekcja dotyczy osób piszących kod strony uzależnionej (RP) lub dostawcy usług uwierzytelniających (CSP). Jeśli polegasz na kodzie implementującym te funkcje, upewnij się, że te problemy są obsługiwane poprawnie

|     #     | Opis                                                                                                                                                                                                                | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|:-------------------------------------------------------------:|
| **3.6.1** | Sprawdź, czy strony ufające (RP) określają maksymalny czas uwierzytelniania dostawców usług uwierzytelniających (CSP) i czy dostawcy CSP ponownie uwierzytelniają użytkownika, jeśli nie użyli sesji w tym okresie. |    |    | ✓  | 613 |                             7.2.1                             |
| **3.6.2** | Sprawdź, czy dostawcy usług uwierzytelniających (CSP) informują strony ufające (RP) o ostatnim zdarzeniu uwierzytelniania, aby umożliwić RP określenie, czy muszą ponownie uwierzytelnić użytkownika.               |    |    | ✓  | 613 |                             7.2.1                             |

## V3.7 Ochrona przed exploitami związanymi z zarządzaniem sesją

Istnieje niewielka liczba ataków związanych z zarządzaniem sesjami, niektóre związane z wrażeniami użytkownika (UX) sesji. Wcześniej, na podstawie wymagań ISO 27002, ASVS wymagał blokowania wielu jednoczesnych sesji. Blokowanie jednoczesnych sesji nie jest już właściwe, nie tylko dlatego, że współcześni użytkownicy mają wiele urządzeń lub aplikacja używa API bez sesji przeglądarki, ale w większości tych implementacji wygrywa ostatni uwierzytelniający, którym często jest atakujący. Ta sekcja zawiera zasadnicze wskazówki dotyczące odstraszania, opóźniania i wykrywania ataków zarządzania sesją przy użyciu kodu.

### Opis ataku półotwartego

Na początku 2018 r. kilka instytucji finansowych zostało narażonych na szwank przy użyciu tego, co atakujący nazwali 'atakami półotwartymi' (half-open attacks). Termin ten zakorzenił się w branży. Napastnicy uderzyli w wiele instytucji z różnymi zastrzeżonymi bazami kodu i rzeczywiście wydaje się, że w ramach tych samych instytucji istnieją różne bazy kodu. Atak półotwarty wykorzystuje lukę wzorca projektowego powszechnie występującą w wielu istniejących systemach uwierzytelniania, zarządzania sesjami i kontroli dostępu

Atakujący rozpoczynają atak półotwarty, próbując zablokować, zresetować lub odzyskać dane uwierzytelniające. Popularny wzorzec projektowy zarządzania sesją ponownie wykorzystuje obiekty/modele sesji profilu użytkownika między kodem nieuwierzytelnionym, częściowo uwierzytelnionym (resetowanie hasła, zapomniana nazwa użytkownika) i w pełni uwierzytelnionym. Ten wzorzec projektowy wypełnia prawidłowy obiekt sesji lub token zawierający profil ofiary, w tym skróty haseł i role. Jeśli sprawdzenie kontroli dostępu w kontrolerach lub routerach nie zweryfikuje poprawnie, czy użytkownik jest w pełni zalogowany, atakujący będzie mógł działać jako użytkownik. Ataki mogą obejmować zmianę hasła użytkownika na znaną wartość, aktualizację adresu e-mail w celu wykonania prawidłowego resetowania hasła, wyłączenie uwierzytelniania wieloskładnikowego lub zarejestrowanie nowego urządzenia MFA, ujawnienie lub zmianę kluczy API i tak dalej.

|     #     | Opis                                                                                                                                                                                                     | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|:-------------------------------------------------------------:|
| **3.7.1** | Sprawdź, czy aplikacja zapewnia pełną, ważną sesję logowania lub wymaga ponownego uwierzytelnienia lub dodatkowej weryfikacji przed zezwoleniem na jakiekolwiek poufne transakcje lub modyfikacje konta. | ✓  | ✓  | ✓  | 306 |                                                               |

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [OWASP Testing Guide 4.0: Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/README.html)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [Set-Cookie __Host- prefix details](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)
