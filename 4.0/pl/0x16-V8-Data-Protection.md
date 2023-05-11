# V8 Ochrona danych

## Cel kontrolny

Istnieją trzy kluczowe elementy silnej ochrony danych: poufność, integralność i dostępność (PID). Norma ta zakłada, że ochrona danych jest wymuszana na zaufanym systemie, takim jak serwer, który został utwardzony i ma wystarczające zabezpieczenia.

Aplikacje muszą zakładać, że wszystkie urządzenia użytkowników są w jakiś sposób zagrożone. Gdy aplikacja przesyła lub przechowuje poufne informacje na niezabezpieczonych urządzeniach, takich jak wspólne komputery, telefony i tablety, aplikacja jest odpowiedzialna za zapewnienie, że dane przechowywane na tych urządzeniach są szyfrowane i nie można ich łatwo nielegalnie uzyskać, zmienić lub ujawnić.

Upewnij się, że zweryfikowana aplikacja spełnia następujące wysokie wymagania dotyczące ochrony danych:

* Poufność: Dane powinny być chronione przed nieupoważnionym dostępem lub ujawnieniem zarówno podczas transportu, jak i podczas przechowywania.
* Integralność: Dane powinny być chronione przed złośliwą ingerencją podczas tworzenia, zmiany lub usunięciem przez nieautoryzowanych napastników.
* Dostępność: Dane powinny być dostępne dla upoważnionych użytkowników zgodnie z wymaganiami.

## V8.1 Ogólna ochrona danych

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.1.1** | Sprawdź, czy aplikacja chroni poufne dane przed buforowaniem w takich modułach, jak load balancery i pamięć podręczna aplikacji. | | ✓ | ✓ | 524 |
| **8.1.2** | Sprawdź, czy wszystkie buforowane lub tymczasowe kopie poufnych danych przechowywanych na serwerze są chronione przed nieautoryzowanym dostępem lub usuwane/unieważniane po uzyskaniu dostępu do poufnych danych przez upoważnionego użytkownika. | | ✓ | ✓ | 524 |
| **8.1.3** | Sprawdź, czy aplikacja ogranicza liczbę parametrów w żądaniu, takich jak ukryte pola, zmienne Ajax, pliki cookie i wartości nagłówków. | | ✓ | ✓ | 233 |
| **8.1.4** | Sprawdź, czy aplikacja może wykrywać anomalia związane ze zwiększoną liczbą zapytań i ostrzegać o nich, na przykład według adresu IP, użytkownika, ilości zapytań na godzinę lub dzień oraz inne kryteria, które mają sens dla aplikacji. | | ✓ | ✓ | 770 |
| **8.1.5** | Sprawdź, czy regularnie wykonywane są kopie zapasowe ważnych danych i czy przeprowadzane są testowe przywracanie danych. | | | ✓ | 19 |
| **8.1.6** | Sprawdź, czy kopie zapasowe są bezpiecznie przechowywane, aby zapobiec kradzieży lub uszkodzeniu danych. | | | ✓ | 19 |

## V8.2 Ochrona danych po stronie klienta

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.2.1** | Sprawdź, czy aplikacja ustawia wystarczającą liczbę nagłówków zapobiegających buforowaniu, aby poufne dane nie były buforowane w nowoczesnych przeglądarkach. | ✓ | ✓ | ✓ | 525 |
| **8.2.2** | Sprawdź, czy dane przechowywane w pamięci przeglądarki (takie jak localStorage, sessionStorage, IndexedDB lub pliki cookie) nie zawierają danych wrażliwych. | ✓ | ✓ | ✓ | 922 |
| **8.2.3** | Sprawdź, czy uwierzytelnione dane są usuwane z pamięci klienta, takiej jak DOM przeglądarki, po zakończeniu klienta lub sesji. | ✓ | ✓ | ✓ | 922 |

## Wersja 8.3 Wrażliwe dane prywatne

Ta sekcja pomaga chronić poufne dane przed tworzeniem, odczytywaniem, aktualizowaniem lub usuwaniem bez autoryzacji, zwłaszcza w dużych ilościach.

Zgodność z tą sekcją oznacza zgodność z Kontrolą dostępu w wersji 4, a w szczególności w wersji 4.2. Na przykład ochrona przed nieautoryzowanymi aktualizacjami lub ujawnieniem poufnych danych osobowych wymaga przestrzegania wersji 4.2.1. Aby uzyskać pełne pokrycie, należy postępować zgodnie z tą sekcją i wersją 4.

Uwaga: Regulacje i przepisy prawa dotyczące prywatności, takie jak australijskie zasady prywatności APP-11 lub RODO, mają bezpośredni wpływ na sposób, w jaki aplikacje muszą podchodzić do wdrażania przechowywania, wykorzystywania i przesyłania poufnych danych osobowych. Obejmuje to zarówno surowe kary, jak i pouczenia. Należy zapoznać się z lokalnymi przepisami i regulacjami oraz w razie potrzeby skonsultować się z wykwalifikowanym specjalistą.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.3.1** | Sprawdź, czy poufne dane są wysyłane do serwera w treści lub nagłówkach wiadomości HTTP oraz czy parametry ciągu z dowolnego zapytania HTTP nie zawierają poufnych danych. | ✓ | ✓ | ✓ | 319 |
| **8.3.2** | Sprawdź, czy użytkownicy mają metodę usuwania lub eksportowania swoich danych na żądanie. | ✓ | ✓ | ✓ | 212 |
| **8.3.3** | Zweryfikuj, czy użytkownicy otrzymali jasny język dotyczący gromadzenia i wykorzystywania dostarczonych danych osobowych oraz czy użytkownicy wyrazili zgodę na wykorzystanie tych danych przed ich wykorzystaniem w jakikolwiek sposób. | ✓ | ✓ | ✓ | 285 |
| **8.3.4** | Sprawdź, czy wszystkie wrażliwe dane tworzone i przetwarzane przez aplikację zostały zidentyfikowane i upewnij się, że istnieje polityka postępowania z wrażliwymi danymi. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 200 |
| **8.3.5** | Sprawdź, czy dostęp do danych wrażliwych jest kontrolowany (bez rejestrowania samych danych wrażliwych), czy dane są gromadzone zgodnie z odpowiednimi dyrektywami o ochronie danych lub gdy wymagane jest rejestrowanie dostępu. | | ✓ | ✓ | 532 |
| **8.3.6** | Zweryfikuj, czy poufne informacje zawarte w pamięci są zastępowane, gdy tylko nie są już potrzebne do łagodzenia ataków zrzucających pamięć, przy użyciu zer lub losowych danych. | | ✓ | ✓ | 226 |
| **8.3.7** | Sprawdź, czy poufne lub prywatne informacje, które mają być szyfrowane, są szyfrowane przy użyciu zatwierdzonych algorytmów, które zapewniają zarówno poufność, jak i integralność. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 327 |
| **8.3.8** | Sprawdź, czy wrażliwe dane osobowe podlegają klasyfikacji przechowywania danych, tak aby stare lub nieaktualne dane były usuwane automatycznie, zgodnie z harmonogramem lub w zależności od sytuacji. | | ✓ | ✓ | 285 |

Rozważając ochronę danych, należy przede wszystkim zwrócić uwagę na masową ekstrakcję lub modyfikację lub nadmierne użycie. Na przykład wiele systemów mediów społecznościowych pozwala użytkownikom dodawać tylko 100 nowych znajomych dziennie, ale nie ma znaczenia, z którego systemu pochodzą te prośby. Platforma bankowa może chcieć zablokować więcej niż 5 transakcji na godzinę, przekazując ponad 1000 euro środków do instytucji zewnętrznych. Wymagania każdego systemu mogą być bardzo różne, więc podjęcie decyzji o „nienormalności” musi uwzględniać model zagrożenia i ryzyko biznesowe. Ważnymi kryteriami są zdolność do wykrywania, powstrzymywania, a najlepiej blokowania takich nienormalnych działań masowych.

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [Rozważ skorzystanie z witryny Security Headers, aby sprawdzić nagłówki bezpieczeństwa i zapobiegające buforowaniu](https://securityheaders.io)
* [Projekt OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
* [Projekt OWASP dotyczący zagrożeń dla prywatności](https://owasp.org/www-project-top-10-privacy-risks/)
* [Ściągawka ochrony prywatności użytkowników OWASP](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [Przegląd ogólnego rozporządzenia Unii Europejskiej o ochronie danych (RODO)](https://edps.europa.eu/data-protection_en)
* [Inspektor Ochrony Danych Unii Europejskiej – Internet Privacy Engineering Network](https://edps.europa.eu/data-protection/ipen-internet-privacy-engineering-network_en)
