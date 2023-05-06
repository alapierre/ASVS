# Wykorzystanie ASVS

ASVS ma dwa główne cele:

* pomagać organizacjom tworzyć i utrzymywać bezpieczne oprogramowanie;
* umożliwić dostawcom usług związanych z bezpieczeństwem, producentom narzędzi związanych z bezpieczeństwem oraz użytkownikom, dostosowanie swoich wymagań i ofert.

## Poziomy Weryfikacji Bezpieczeństwa

Standard Weryfikacji Bezpieczeństwa Aplikacji (ASVS) definiuje trzy poziomy weryfikacji bezpieczeństwa, przy czym każdy kolejny poziom jest bardziej zaawansowany.

* Poziom `ASVS 1` jest przeznaczony dla aplikacji o niskim poziomie wymagań bezpieczeństwa i jest w pełni testowalny za pomocą testów penetracyjnych
* Poziom `ASVS 2` jest przeznaczony dla aplikacji zawierających wrażliwe dane, które wymagają ochrony, i jest zalecanym poziomem dla większości aplikacji
* Poziom `ASVS 3` jest przeznaczony dla najbardziej krytycznych aplikacji — takich, które przeprowadzają transakcje o wysokiej wartości, zawierają wrażliwe dane medyczne lub inne poufne informacje, które wymagają najwyższego poziomu zaufania.

Każdy poziom `ASVS` zawiera listę wymagań związanych z bezpieczeństwem. Każde z tych wymagań można również przyporządkować do konkretnych funkcji i możliwości związanych z bezpieczeństwem, które muszą być zaimplementowane przez deweloperów.

![ASVS Levels](https://raw.githubusercontent.com/OWASP/ASVS/master/4.0/images/asvs_40_levels.png "ASVS Levels")

Rysunek 1 - OWASP Application Security Verification Standard 4.0 Levels

`Level 1` jest jedynym poziomem, który jest w pełni testowalny za pomocą testów penetracyjnych wykonywanych przez człowieka. Wszystkie inne poziomy wymagają dostępu do dokumentacji, kodu źródłowego, konfiguracji oraz zespołów zaangażowanych w proces tworzenia oprogramowania. Jednak nawet jeśli `L1` pozwala na "czarne skrzynki" (bez dokumentacji i bez kodu źródłowego) takie testowanie nie jest skutecznym zabezpieczeniem i należy ją aktywnie odradzać. Złośliwi atakujący mają wiele czasu, a większość testów penetracyjnych trwa zaledwie kilka tygodni. Zespoły muszą w rozsądnym czasie budować kontrole bezpieczeństwa, chronić, znajdować i usuwać wszystkie słabości oraz wykrywać i reagować na działania atakujących. Atakujący mają praktycznie nieskończony czas i potrzebują tylko jednej słabości lub błędu konfiguracji, aby odnieść sukces. Testowanie "czarnej skrzynki", często przeprowadzane "na szybko", na końcu procesu deweloperskiego, nie jest w stanie poradzić sobie z tą asymetrią.

Przez ponad 30 lat testowanie "czarnej skrzynki" udowodniło wiele razy, że pomija kluczowe problemy związane z bezpieczeństwem, które prowadziły bezpośrednio do coraz większych naruszeń. Zdecydowanie zachęcamy do stosowania szerokiego zakresu zapewniania bezpieczeństwa i weryfikacji, w tym do zastępowania testów penetracyjnych testami penetracyjnymi opartymi na kodzie źródłowym (hybrydowymi) na poziomie 1, z pełnym dostępem do dokumentacji i deweloperów przez cały proces tworzenia oprogramowania. Regulatorzy finansowi nie akceptują zewnętrznych audytów finansowych bez dostępu do ksiąg, próbnych transakcji lub ludzi wykonujących kontrole. Przemysł i rządy muszą wymagać tego samego standardu przejrzystości w dziedzinie inżynierii oprogramowania.

Zdecydowanie zachęcamy do korzystania z narzędzi bezpieczeństwa w samym procesie tworzenia oprogramowania. Narzędzia DAST i SAST mogą być stosowane ciągle przez proces budowania (build pipeline), aby znaleźć łatwe do zdiagnozowania problemy bezpieczeństwa, które nigdy nie powinny występować.

Automatyczne narzędzia i skany online nie są w stanie pokryć więcej niż połowy wymagań ASVS bez pomocy ludzkiej. Jeśli wymagane jest kompleksowe automatyzowanie testów dla każdej kompilacji, wtedy używa się kombinacji niestandardowych testów jednostkowych i integracyjnych, wraz z inicjowaniem skanów online w procesie budowania. Testowanie błędów biznesowych i kontrola dostępu jest możliwa tylko przy pomocy ludzkiej. Należy je zamienić na testy jednostkowe i integracyjne.

## Jak używać standardu

Jednym z najlepszych sposobów wykorzystania Standardu Weryfikacji Bezpieczeństwa Aplikacji jest użycie go jako szablonu do stworzenia Listy Kontrolnej Bezpiecznego Kodowania, specyficznej dla Twojej aplikacji, platformy lub organizacji. Dostosowanie ASVS do Twojego przypadku użycia zwiększy skupienie na wymaganiach bezpieczeństwa, które są najważniejsze dla Twoich projektów i środowiska.

### Poziom 1 - Pierwsze kroki, zautomatyzowane lub widok całego portfela

Aplikacja otrzymuje poziom ASVS Level 1, jeśli skutecznie obroni się przed podatnościami bezpieczeństwa aplikacji, które są łatwe do odkrycia i uwzględnione w `OWASP Top 10` oraz innych podobnych listach kontrolnych.

Poziom 1 to absolutne minimum, do którego powinny dążyć wszystkie aplikacje. Jest również przydatny jako pierwszy krok w wieloetapowym procesie lub gdy aplikacje nie przechowują ani nie obsługują wrażliwych danych i dlatego nie wymagają bardziej rygorystycznych kontroli poziomu 2 lub 3. Kontrole poziomu 1 mogą być sprawdzane automatycznie przez narzędzia lub po prostu ręcznie bez dostępu do kodu źródłowego. Uważamy, że poziom 1 jest minimalnym wymaganym dla wszystkich aplikacji.

Zagrożenia dla aplikacji będą prawdopodobnie pochodzić od atakujących, którzy używają prostych i wymagających niskiego wysiłku technik, aby zidentyfikować łatwe do znalezienia i łatwe do wykorzystania podatności bezpieczeństwa. W przeciwieństwie do zdeterminowanego atakującego, który poświęci dużo wysiłku i energii, aby celowo zaatakować aplikację. Jeśli Twoja aplikacja przetwarza poufne informacje, które mają wysoką wartość, rzadko chcesz zatrzymać się na przeglądzie poziomu 1.

### Poziom 2 - Większość aplikacji

Aplikacja otrzymuje ASVS Level 2, jeśli skutecznie broni się przed większością dzisiejszych zagrożeń związanych z oprogramowaniem.

Poziom 2 zapewnia, że kontrole bezpieczeństwa są na swoim miejscu, skuteczne i stosowane w aplikacji. Zwykle jest on odpowiedni dla aplikacji, które obsługują znaczące transakcje między firmami, w tym tych, które przetwarzają informacje medyczne, wdrażają funkcje biznesowe lub wrażliwe, przetwarzają inne wrażliwe aktywa lub dla branż, gdzie integralność jest kluczowym elementem do ochrony ich biznesu, takich jak branża gier, aby przeciwdziałać oszustom i łamaniom gier.

Zagrożenia dla aplikacji na poziomie 2 zwykle będą pochodzić od zdolnych i zmotywowanych atakujących, którzy skupiają się na konkretnych celach, używając narzędzi i technik, które są często praktykowane i skuteczne w odkrywaniu i wykorzystywaniu słabości w aplikacjach.

### Level 3 - Wysoka wartość, wysokie wymaganie bezpieczeństwa

Poziom ASVS 3 to najwyższy poziom weryfikacji w ramach `ASVS`. Ten poziom jest zwykle przeznaczony dla aplikacji wymagających znacznego poziomu weryfikacji bezpieczeństwa, takich jak te znajdujące się w obszarach wojskowości, zdrowia i bezpieczeństwa, krytycznej infrastruktury itp.

Organizacje mogą wymagać poziomu ASVS Level 3 dla aplikacji wykonujących krytyczne funkcje, w których awaria może znacząco wpłynąć na funkcjonowanie organizacji, a nawet zdolność do jej przetrwania. Poniżej przedstawiono przykładowe wytyczne dotyczące stosowania poziomu ASVS 3. Aplikacja osiąga poziom ASVS 3 (lub Poziom Zaawansowany), jeśli skutecznie obroni się przed zaawansowanymi podatnościami bezpieczeństwa aplikacji i jednocześnie wykazuje zasady dobrego projektowania zabezpieczeń.

Aplikacja na poziomie ASVS 3 wymaga bardziej szczegółowej analizy architektury, kodowania i testowania niż wszystkie inne poziomy. Bezpieczna aplikacja jest w znaczący sposób modularna (aby ułatwić odporność, skalowalność i przede wszystkim wyznaczyć warstwy zabezpieczeń), a każdy moduł (oddzielony przez połączenie sieciowe i/lub fizyczną instancję) dba o swoje własne odpowiedzialności i zabezpieczenia (obrona w głąb), które muszą być właściwie udokumentowane. Odpowiedzialności obejmują kontrole zapewniające poufność (np. szyfrowanie), integralność (np. transakcje, walidacja danych wejściowych), dostępność (np. eleganckie radzenie sobie z obciążeniem), uwierzytelnienie (w tym między systemami), autoryzację i audytowanie (logowanie).

## Stosowanie ASVS w praktyce

Różne zagrożenia są spowodowane różnymi motywacjami. Niektóre branże posiadają unikalne aktywa informacyjne i technologiczne oraz specyficzne wymagania regulacyjne związane z daną dziedziną.

Zachęcamy Organizacje do szczegółowej analizy ich unikalnych cech ryzyka, opartych na charakterze ich działalności i na podstawie tych czynników określenie odpowiedniego poziomu ASVS.

## Jak odnosić się do wymagań ASVS

Każde wymaganie posiada identyfikator w formacie `<rozdział>.<sekcja>.<wymaganie>`, gdzie każdy element to liczba, na przykład: `1.11.3`.
- Wartość `<chapter>` odpowiada rozdziałowi, z którego pochodzi wymaganie, na przykład: wszystkie wymagania w formacie `1.#.#` pochodzą z rozdziału Architektura.
- Wartość `<sekcja>` odpowiada sekcji w ramach danego rozdziału, w którym pojawia się wymaganie, na przykład: wszystkie wymagania `1.11.#` znajdują się w sekcji Business Logic Architecture w rozdziale Architektura.
- Wartość `<wymaganie>` identyfikuje konkretne wymaganie w rozdziale i sekcji. Na przykład, `1.11.3`, które w wersji 4.0.3 tego standardu brzmmi: 

> Zweryfikuj, że wszystkie ważne przepływy logiki biznesowej, w tym uwierzytelnianie, zarządzanie sesją i kontrola dostępu są bezpieczne dla wątków i odporne na wyścigi czasowe typu time-of-check i time-of-use.

Identyfikatory mogą ulec zmianie między wersjami standardu, dlatego preferowane jest, aby inne dokumenty, raporty lub narzędzia używały formatu: `v<wersja>-<rozdział>.<sekcja>.<wymaganie>`, gdzie 'wersja' to oznaczenie wersji ASVS. Na przykład: `v4.0.3-1.11.3` oznaczałoby specyficzne wymaganie numer 3 w sekcji 'Business Logic Architecture' rozdziału 'Architecture' z wersji `4.0.3`. (Można to streścić jako `v<wersja>-<identyfikator_wymagania>`.)

Uwaga: Litera "v" przed numerem wersji powinna być pisana małą literą.

Jeśli identyfikatory są używane bez uwzględniania elementu v<wersja>, to powinno się przyjąć, że odnoszą się do najnowszej treści Standardu Weryfikacji Bezpieczeństwa Aplikacji. Oczywiście, w miarę rozwoju i zmian standardu, może to stanowić problem, dlatego autorzy publikacji lub deweloperzy powinni uwzględniać element wersji.

Listy wymagań ASVS są udostępniane w formacie CSV, JSON i innych, które mogą być przydatne do odwoływania się do nich lub do użytku programistycznego.
