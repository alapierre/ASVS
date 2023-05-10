# V12 Files and Resources

## Cele kontroli

Upewnij się, że zweryfikowana aplikacja spełnia następujące ogólne wymagania::

* Niezaufane pliki danych należy traktować odpowiednio i w bezpieczny sposób.
* Niezaufane dane plików uzyskane z niezaufanych źródeł są przechowywane poza głównym katalogiem internetowym i z ograniczonymi uprawnieniami.

## V12.1 Przesyłanie plików 

Chociaż bomby zip są wyjątkowo testowalne przy użyciu technik testów penetracyjnych, są one uważane za L2 i wyższe, aby zachęcić do rozważenia projektowania i rozwoju przy dokładnym testowaniu ręcznym oraz aby uniknąć zautomatyzowanych lub niewykwalifikowanych manualnych testów penetracyjnych powodujących odmowę usługi.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.1.1** | Sprawdź, czy aplikacja nie akceptuje dużych plików, które mogłyby zapełnić pamięć lub spowodować odmowę usługi. | ✓ | ✓ | ✓ | 400 |
| **12.1.2** | Sprawdź, czy aplikacja sprawdza skompresowane pliki (np. zip, gz, docx, odt) pod kątem maksymalnego dozwolonego rozmiaru po rozpakowaniu i maksymalnej liczby plików przed rozpakowaniem pliku. | | ✓ | ✓ | 409 |
| **12.1.3** | Sprawdź, czy limit rozmiaru pliku i maksymalna liczba plików na użytkownika są wymuszane, aby upewnić się, że pojedynczy użytkownik nie może zapełnić pamięci zbyt dużą liczbą plików lub zbyt dużymi plikami. | | ✓ | ✓ | 770 |

## V12.2 Integralność plików

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.2.1** | Sprawdź, czy pliki uzyskane z niezaufanych źródeł są sprawdzane pod kątem oczekiwanego typu na podstawie zawartości pliku. | | ✓ | ✓ | 434 |

## V12.3 Wykonowanie plików

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.3.1** | Sprawdź, czy metadane nazw plików przesłane przez użytkowników nie są używane bezpośrednio w systemie lub przez platformy programistyczne oraz czy interfejs API jest chroniony przed atakiem umożliwiającym niekontrolowany dostęp do plików i katalogów (Path Traversal). | ✓ | ✓ | ✓ | 22 |
| **12.3.2** | Sprawdź, czy przesłane przez użytkownika metadane nazw plików są sprawdzane lub ignorowane, aby zapobiec ujawnianiu, tworzeniu, aktualizowaniu lub usuwaniu plików lokalnych (LFI). | ✓ | ✓ | ✓ | 73 |
| **12.3.3** | Sprawdź, czy przesłane przez użytkownika metadane nazw plików są weryfikowane lub ignorowane, aby zapobiec ujawnieniu lub wykonaniu zdalnych plików za pomocą ataków Remote File Inclusion (RFI) lub Server-side Request Forgery (SSRF). | ✓ | ✓ | ✓ | 98 |
| **12.3.4** | VSprawdź, czy aplikacja chroni przed odblaskowym pobieraniem plików (RFD), sprawdzając lub ignorując nazwy plików przesłane przez użytkownika w parametrze JSON, JSONP lub URL, nagłówek Content-Type odpowiedzi powinien być ustawiony na tekst/zwykły, a nagłówek Content-Disposition powinien mieć stałą nazwę pliku. | ✓ | ✓ | ✓ | 641 |
| **12.3.5** | Sprawdź, czy niezaufane metadane plików nie są używane bezpośrednio z systemowym interfejsem API lub bibliotekami, aby chronić się przed wstrzykiwaniem poleceń systemu operacyjnego.. | ✓ | ✓ | ✓ | 78 |
| **12.3.6** | Sprawdź, czy aplikacja nie zawiera i nie wykonuje funkcji z niezaufanych źródeł, takich jak niezweryfikowane sieci dystrybucji treści, biblioteki JavaScript, biblioteki węzłów npm lub biblioteki DLL po stronie serwera. | | ✓ | ✓ | 829 |

## V12.4 Przechowywanie plików

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.4.1** | Sprawdź, czy pliki uzyskane z niezaufanych źródeł są przechowywane poza głównym katalogiem internetowym, z ograniczonymi uprawnieniami. | ✓ | ✓ | ✓ | 552 |
| **12.4.2** | Sprawdź, czy pliki uzyskane z niezaufanych źródeł są skanowane przez skanery antywirusowe, aby zapobiec przesyłaniu i udostępnianiu znanych złośliwych treści. | ✓ | ✓ | ✓ | 509 |

## V12.5 Pobieranie pliku

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.5.1** | Sprawdź, czy warstwa internetowa jest skonfigurowana do obsługiwania tylko plików z określonymi rozszerzeniami plików, aby zapobiec niezamierzonym informacjom i wyciekowi kodu źródłowego. Na przykład pliki kopii zapasowych (np. .bak), tymczasowe pliki robocze (np. .swp), pliki skompresowane (.zip, .tar.gz itp.) oraz inne rozszerzenia powszechnie używane przez redaktorów powinny być blokowane, chyba że jest to wymagane. | ✓ | ✓ | ✓ | 552 |
| **12.5.2** | Sprawdź, czy bezpośrednie żądania przesłanych plików nigdy nie będą wykonywane jako treść HTML/JavaScript. | ✓ | ✓ | ✓ | 434 |

## V12.6 Ochrona przed SSRF

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.6.1** | Sprawdź, czy serwer WWW lub serwer aplikacji jest skonfigurowany z listą dozwolonych zasobów lub systemów, do których serwer może wysyłać żądania lub ładować dane/pliki. | ✓ | ✓ | ✓ | 918 |

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [File Extension Handling for Sensitive Information](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [Reflective file download by Oren Hafif](https://www.trustwave.com/Resources/SpiderLabs-Blog/Reflected-File-Download---A-New-Web-Attack-Vector/)
* [OWASP Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
