# V10 Złośliwy kod

## Cel kontrolny

Upewnij się, że kod spełnia następujące wymagania:

* Złośliwa aktywność jest obsługiwana w sposób bezpieczny i kontrolowany, aby nie wpływać na resztę aplikacji.
* Nie ma bomb zegarowych ani innych ataków opartych na czasie.
* Nie kontaktuje się z serwerami, które są złośliwe lub nieautoryzowane.
* Nie ma tylnych furtek, "easter eggs", "salami attacks", rootkitów ani nieautoryzowanego kodu, który może być kontrolowany przez atakującego.

Znalezienie złośliwego kodu jest dowodem negatywnym, którego nie można całkowicie zweryfikować. Należy dołożyć wszelkich starań, aby kod nie zawierał złośliwych oraz niepożądanych funkcji.

## V10.1 Integralność kodu 

Najlepszą obroną przed złośliwym kodem jest „ufaj, ale weryfikuj”. Wprowadzenie nieautoryzowanych lub złośliwych komend do kodu aplikacji jest często przestępstwem w wielu jurysdykcjach. Zasady i procedury powinny jasno określać sankcje dotyczące złośliwego kodu.

Programiści powinni regularnie dokonywać sprawdzania kodu, szczególnie tego, który może uzyskiwać dostęp do funkcji czasu, we/wy lub sieciowych.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.1.1** | Sprawdź, czy używane jest narzędzie do analizy kodu, które może wykryć potencjalnie złośliwy kod, taki jak funkcje czasowe, niebezpieczne operacje na plikach i połączenia sieciowe. | | | ✓ | 749 |

## V10.2 Wyszukiwanie złośliwego kodu

Złośliwy kod jest niezwykle rzadki i trudny do wykrycia. Ręczny przegląd kodu wiersz po wierszu może pomóc w wyszukiwaniu bomb logicznych, ale nawet najbardziej doświadczony recenzent kodu będzie miał trudności ze znalezieniem złośliwego kodu, nawet jeśli wie, że istnieje.

Zgodność z tą sekcją nie jest możliwa bez pełnego dostępu do kodu źródłowego, w tym bibliotek stron trzecich.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.2.1** | Sprawdź, czy kod źródłowy aplikacji i biblioteki stron trzecich nie zawiera nieautoryzowanych telefonów domowych lub możliwości gromadzenia danych. Jeśli taka funkcja istnieje, przed zebraniem jakichkolwiek danych należy uzyskać zgodę użytkownika na jej działanie. | | ✓ | ✓ | 359 |
| **10.2.2** | Sprawdź, czy aplikacja nie prosi o niepotrzebne lub nadmierne uprawnienia do funkcji lub czujników związanych z prywatnością, takich jak kontakty, kamery, mikrofony lub lokalizacja. | | ✓ | ✓ | 272 |
| **10.2.3** | Sprawdź, czy kod źródłowy aplikacji i biblioteki stron trzecich nie zawierają tylnych drzwi, takich jak zakodowane na stałe lub dodatkowe nieudokumentowane konta lub klucze, zaciemnianie kodu, nieudokumentowane binarne obiekty blob, rootkity lub anty-debugowanie, niebezpieczne funkcje debugowania lub w inne nieaktualne, niezabezpieczone lub ukryte funkcje, które w przypadku wykrycia mogą zostać użyte w złośliwy sposób. | | | ✓ | 507 |
| **10.2.4** | Sprawdź, czy kod źródłowy aplikacji i biblioteki stron trzecich nie zawierają bomb zegarowych, wyszukując funkcje związane z datą i godziną. | | | ✓ | 511 |
| **10.2.5** | Sprawdź, czy kod źródłowy aplikacji i biblioteki stron trzecich nie zawierają złośliwego kodu, takiego jak ***ataki salami***, obejścia logiki lub bomby logiczne. | | | ✓ | 511 |
| **10.2.6** | Sprawdź, czy kod źródłowy aplikacji i biblioteki stron trzecich nie zawierają easter eggs ani żadnych innych potencjalnie niepożądanych funkcji. | | | ✓ | 507 |

## V10.3 Integralność aplikacji

Po wdrożeniu aplikacji nadal można wstawić złośliwy kod. Aplikacje muszą chronić się przed typowymi atakami, takimi jak wykonywanie niepodpisanego kodu z niezaufanych źródeł i przejmowanie subdomen.

Przestrzeganie tej sekcji prawdopodobnie będzie operacyjne i ciągłe.

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.3.1** | Sprawdź, czy jeśli aplikacja ma funkcję automatycznej aktualizacji klienta lub serwera, aktualizacje powinny być uzyskiwane za pośrednictwem bezpiecznych kanałów i podpisywane cyfrowo. Kod musi weryfikować podpis cyfrowy aktualizacji przed zainstalowaniem lub wykonaniem aktualizacji. | ✓ | ✓ | ✓ | 16 |
| **10.3.2** | Sprawdź, czy aplikacja stosuje zabezpieczenia integralności, takie jak podpisywanie kodu lub integralność zasobów podrzędnych. Aplikacja nie może ładować ani wykonywać kodu z niezaufanych źródeł, takich jak ładowanie stałych, makr , modułów, wtyczek, kodu lub bibliotek z niezaufanych źródeł lub Internetu. | ✓ | ✓ | ✓ | 353 |
| **10.3.3** | Sprawdź, czy aplikacja ma ochronę przed przejęciem subdomen, jeśli opiera się na wpisach DNS lub subdomenach DNS, takich jak wygasłe nazwy domen, nieaktualne wskaźniki DNS lub CNAME, wygasłe projekty w publicznych repozytoriach kodu źródłowego lub przejściowe interfejsy API w chmurze, funkcje bezserwerowe, lub zasobniki do przechowywania (*autogen-bucket-id*.cloud.example.com) lub podobne. Zabezpieczenia mogą obejmować zapewnienie, że nazwy DNS używane przez aplikacje są regularnie sprawdzane pod kątem wygaśnięcia lub zmiany. | ✓ | ✓ | ✓ | 350 |

## Bibliografia

* [Wrogie przejęcie subdomeny, Detectify Labs](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
* [Przejęcie opuszczonych subdomen, część 2, Detectify Labs](https://labs.detectify.com/2014/12/08/hijacking-of-abandoned-subdomains-part-2/)
