# V9 Komunikacja

## Cel kontrolny

Upewnij się, że zweryfikowana aplikacja spełnia następujące ogólne wymagania:

* Wymagaj TLS lub silnego szyfrowania, niezależnie od wrażliwości treści.
* Postępuj zgodnie z najnowszymi wskazówkami, w tym:
  * Porady dotyczące konfiguracji
  * Preferowane algorytmy i szyfry
* Unikaj słabych lub wkrótce przestarzałych algorytmów i szyfrów, ***użyj tylko jako ostateczność***
* Wyłącz przestarzałe lub znane niebezpieczne algorytmy i szyfry.

W ramach tych wymagań:

* Na bieżąco śledź zalecenia branżowe dotyczące bezpiecznej konfiguracji TLS, ponieważ ulegają one ciągłym zmianom(często z powodu błędów w istniejących algorytmach i szyfrach).
* Użyj najnowszych wersji narzędzi do przeglądania konfiguracji TLS, aby skonfigurować preferowaną kolejność i wybór algorytmu.
* Okresowo sprawdzaj swoją konfigurację, aby upewnić się, że bezpieczna komunikacja jest zawsze włączona i skuteczna.

## V9.1 Bezpieczeństwo komunikacji klienta

Upewnij się, że wszystkie wiadomości klientów są wysyłane przez zaszyfrowaną komunikację przy użyciu protokołu TLS 1.2 lub nowszego.
Używaj aktualnych narzędzi do regularnego przeglądania konfiguracji klienta.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **9.1.1** | Sprawdź, czy protokół TLS jest używany do wszystkich połączeń klientów i nie ogranicza się do niezabezpieczonej lub niezaszyfrowanej komunikacji. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 319 |
| **9.1.2** | Za pomocą aktualnych narzędzi testowych TLS sprawdź, czy włączone są tylko silne zestawy szyfrów, przy czym najsilniejsze zestawy szyfrów są ustawione jako preferowane. | ✓ | ✓ | ✓ | 326 |
| **9.1.3** | Sprawdź, czy włączone są tylko najnowsze zalecane wersje protokołu TLS, takie jak TLS 1.2 i TLS 1.3. Najnowsza wersja protokołu TLS powinna być preferowaną opcją. | ✓ | ✓ | ✓ | 326 |

## Bezpieczeństwo komunikacji z serwerem w wersji 9.2

Komunikacja z serwerem to coś więcej niż tylko HTTP. Bezpieczeństwo połączeń pomiędzy systemami, takimi jak systemy monitorowania, narzędzia do zarządzania, dostęp zdalny i ssh, oprogramowanie pośrednie, baza danych, komputery typu mainframe, systemy partnerskie lub zewnętrzne systemy źródłowe — powinno być zachowane. Wszelkie połączenia muszą być zaszyfrowane, aby zapobiec sytuacji, w której ruch jest nie do zabezpieczony na zewnątrz a banalnie łatwy do przechwycenia wewnątrz”.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **9.2.1** | Sprawdź, czy połączenia do i z serwera korzystają z zaufanych certyfikatów TLS. W przypadku używania certyfikatów generowanych wewnętrznie lub z podpisem własnym, serwer należy skonfigurować tak, aby ufał tylko określonym wewnętrznym urzędom certyfikacji i określonym certyfikatom z podpisem własnym. Wszystkie inne należy odrzucić. | | ✓ | ✓ | 295 |
| **9.2.2** | Sprawdź, czy szyfrowana komunikacja, taka jak TLS, jest używana dla wszystkich połączeń przychodzących i wychodzących, w tym portów zarządzania, monitorowania, uwierzytelniania, API lub wywołań usług sieciowych, baz danych, chmury, bezserwerowych, mainframe, połączeń zewnętrznych i partnerskich. Serwer nie może używać niezabezpieczonych lub niezaszyfrowanych protokołów. | | ✓ | ✓ | 319 |
| **9.2.3** | Sprawdź, czy wszystkie szyfrowane połączenia z systemami zewnętrznymi, które obejmują poufne informacje lub funkcje, są uwierzytelniane. | | ✓ | ✓ | 287 |
| **9.2.4** | Sprawdź, czy włączono i skonfigurowano odpowiednie unieważnianie certyfikatów, takie jak OCSP(Online Certificate Status Protocol) Stapling. | | ✓ | ✓ | 299 |
| **9.2.5** | Sprawdź, czy rejestrowane są błędy połączeń TLS zaplecza. | | | ✓ | 544 |

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [OWASP – Ściągawka TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP – Przewodnik przypinania](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
* Uwagi dotyczące „Zatwierdzonych trybów TLS”:
    * W przeszłości ASVS odwoływał się do amerykańskiego standardu FIPS 140-2, ale jako standard globalny stosowanie standardów amerykańskich może być trudne, sprzeczne lub mylące.
    * Lepszą metodą osiągnięcia zgodności z sekcją 9.1 byłoby przejrzenie przewodników, takich jak [Mozilla's Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) lub [generowanie znanych dobrych konfiguracji](https:// mozilla.github.io/server-side-tls/ssl-config-generator/) i korzystać ze znanych i aktualnych narzędzi oceny TLS w celu uzyskania pożądanego poziomu bezpieczeństwa.
