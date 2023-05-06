# Ocena i Certyfikacja

## Stanowisko OWASP w sprawie certyfikacji ASVS i znaków zaufania

OWASP, jako neutralna wobec dostawców organizacja non-profit, obecnie nie certyfikuje żadnych dostawców, weryfikatorów lub oprogramowania.

Wszystkie takie zapewnienia, znaki zaufania lub certyfikaty nie są oficjalnie zweryfikowane, zarejestrowane ani nie są certyfikowane przez OWASP, więc organizacja polegająca na takiej opinii musi być ostrożna w zaufaniu jakimkolwiek podmiotom trzecim lub znakom zaufania twierdzącym o certyfikacji `ASVS`.

Nie powinno to jednak hamować organizacji w oferowaniu takich usług zapewniających o zgodności z `ASVS`, o ile nie twierdzą, że posiadają oficjalny certyfikat OWASP.

## Wskazówki dla organizacji certyfikujących

Standard Weryfikacji Bezpieczeństwa Aplikacji może być wykorzystany jako weryfikacja aplikacji na zasadzie "otwartej książki", obejmująca swobodny dostęp do kluczowych zasobów, takich jak architekci i programiści, dokumentacja projektowa, kod źródłowy, uwierzytelniony dostęp do systemów testowych (w tym dostęp do jednego lub więcej kont w każdej roli), zwłaszcza dla weryfikacji L2 i L3.

Historycznie, testowanie penetracyjne i przeglądy bezpieczeństwa kodu obejmowały problemy "wyjątkowe" - to znaczy tylko niezdane testy pojawiły się w raporcie końcowym. Organizacja certyfikująca musi uwzględnić w każdym raporcie zakres weryfikacji (zwłaszcza jeśli kluczowy komponent jest poza zakresem, np. uwierzytelnianie SSO), podsumowanie wyników weryfikacji, w tym zdane i niezdane testy, z jasnymi wskazówkami dotyczącymi sposobów rozwiązania podatności bezpieczeństwa wynikających z niezdanych testów.

Niektóre wymagania mogą nie być zastosowane do testowanej aplikacji. Na przykład, jeśli udostępniasz bezstanową warstwę API swoim klientom, wiele wymagań z sekcji 'V3 Zarządzanie Sesją' nie ma zastosowania. W takich przypadkach organizacja certyfikująca może wciąż potwierdzić pełne spełnienie wymagań ASVS, ale musi jasno wskazać w każdym raporcie powód niestosowania takich wykluczonych wymagań.

Utrzymywanie szczegółowych dokumentów roboczych, zrzutów ekranów lub filmów, skryptów służących do niezawodnego i powtarzalnego wykorzystania problemu oraz elektronicznych rejestrów testów, takich jak logi proxy i związane z nimi notatki, takie jak lista czyszczenia (cleanup list), jest uważane za standardową praktykę w branży i może być naprawdę przydatne jako dowody dla najbardziej niedowierzających programistów. Nie wystarczy po prostu uruchomić narzędzia i zgłosić niepowodzenia; to nie zapewnia (w ogóle) wystarczających dowodów na to, że wszystkie problemy na poziomie certyfikacji zostały przetestowane i dokładnie przetestowane. W przypadku sporu powinny istnieć wystarczające dowody zapewniające potwierdzenie, że każde wymaganie zostało rzeczywiście przetestowane.

### Metody Testowania

Organizacje certyfikujące mają pełną swobodę wyboru odpowiedniej metody lub metod testowania, ale powinny je wskazać w raporcie.

W zależności od testowanej aplikacji i wymagań weryfikacji mogą być wykorzystane różne metody testowania, w celu uzyskania podobnych wyników. Na przykład, sprawdzenie skuteczności mechanizmów weryfikacji wejściowej aplikacji można przeprowadzić przez manualny test penetracyjny lub poprzez analizę kodu źródłowego.

#### Rola narzędzi do automatycznych testów bezpieczeństwa

Używanie narzędzi do automatycznych testów penetracyjnych jest pożądane, aby zapewnić jak największy zasięg testów.

Nie jest możliwe w pełni ukończenie weryfikacji ASVS przy użyciu wyłącznie narzędzi do automatycznych testów penetracyjnych. Podczas gdy większość wymagań poziomu L1 może być wykonywana przy użyciu automatycznych testów, ogromna część pozostałych wymagań nie jest odpowiednia do testów automatycznych.

Należy zauważyć, że granice między testowaniem automatycznym i manualnym zacierają się w miarę dojrzewania branży bezpieczeństwa aplikacji. Narzędzia automatyczne są często ręcznie dostrojone przez ekspertów, a testujący ręcznie często korzystają z różnorodnych narzędzi automatycznych.

#### Rola testów penetracyjnych

W wersji 4.0 postanowiliśmy, że poziom L1 będzie w pełni testowalny poprzez testy penetracyjne bez dostępu do kodu źródłowego, dokumentacji lub programistów. Dwa elementy, wymagane do spełnienia `OWASP Top 10 2017 A10`, będą wymagały wywiadów, zrzutów ekranu lub innych dowodów. Jednakże, testowanie bez dostępu do niezbędnych informacji nie jest idealną metodą weryfikacji bezpieczeństwa, ponieważ pomija możliwość przejrzenia źródła, zidentyfikowania zagrożeń i brakujących kontroli, oraz przeprowadzenia znacznie bardziej szczegółowego testu w krótszym czasie.

Tam, gdzie to możliwe, przy weryfikacji L2 lub L3 wymagany jest dostęp do programistów, dokumentacji, kodu oraz dostęp do aplikacji testowej z fikcyjnymi danymi na środowiskach testowych Testowanie penetracyjne przeprowadzane na tych poziomach wymaga tego rodzaju dostępu, nazywamy je "hybrydowymi przeglądami" lub "hybrydowymi testami penetracyjnymi".

## Inne przypadki użycia ASVS

Oprócz wykorzystania do oceny bezpieczeństwa aplikacji zidentyfikowaliśmy kilka innych potencjalnych zastosowań `ASVS`.

### Szczegółowe wytyczne architektury bezpieczeństwa

Jednym z bardziej powszechnych zastosowań Standardu Weryfikacji Bezpieczeństwa Aplikacji jest wykorzystanie go jako zasobu dla architektów bezpieczeństwa. Sherwood Applied Business Security Architecture (SABSA) nie zawiera wielu informacji, które są niezbędne do przeprowadzenia szczegółowej analizy architektury bezpieczeństwa aplikacji. ASVS może być wykorzystany do uzupełnienia tych luk, pozwalając architektom bezpieczeństwa na wybór lepszych kontroli dla powszechnych problemów, takich jak wzorce ochrony danych i strategie walidacji wejść.

### Jako zamiennik gotowych list kontrolnych dotyczących bezpiecznego programowania

Wiele organizacji może skorzystać z przyjęcia `ASVS`, wybierając jeden z trzech poziomów, lub poprzez skopiowanie `ASVS` i zmianę wymagań dla każdego poziomu ryzyka aplikacji w sposób specyficzny dla danej domeny. Zachęcamy do tego typu kopiowania, o ile zachowane jest odniesienie do oryginalnej numeracji, tak aby jeśli aplikacja przeszła wymaganie 4.1, oznaczało to to samo dla skopiowanych wersji, jak i do standardu, w miarę jego rozwoju.

### Jako przewodnik dla automatycznych testów jednostkowych i integracyjnych

`ASVS` jest zaprojektowany tak, aby był łatwy do przetestowania, z jedynym wyjątkiem wymagań architektonicznych i dotyczących złośliwego kodu. Poprzez tworzenie testów jednostkowych i integracyjnych, które testują konkretne i istotne przypadki fuzzingowe i nadużycia, aplikacja staje się praktycznie samoweryfikująca przy każdej kompilacji. Na przykład, do zestawu testów dla kontrolera logowania można dodać dodatkowe testy, które sprawdzają parametr nazwy użytkownika pod kątem popularnych domyślnych nazw użytkowników, wyliczanie kont, atak brute-force, wstrzykiwanie LDAP i SQL, oraz XSS. Podobnie, test dla parametru hasła powinny obejmować popularne hasła, długość hasła, wstrzykiwanie znaku null, usunięcie parametru, XSS i wiele innych.

### Do szkoleń z bezpiecznego wytwarzania oprogramowania

`ASVS` może również być wykorzystany do określenia cech bezpiecznego oprogramowania. Wiele kursów "bezpiecznego programowania" to po prostu kursy etycznego hakerstwa z lekkim akcentem na porady dotyczące programowania. To może niekoniecznie pomóc programistom w pisaniu bardziej bezpiecznego kodu. Zamiast tego, kursy dotyczące bezpiecznego rozwoju oprogramowania mogą wykorzystać `ASVS`, skupiając się na proaktywnych kontrolach znajdujących się w `ASVS`, zamiast na Top 10 negatywnych rzeczy, których należy unikać.

### Jako narzędzie do prowadzenia zwinnego bezpieczeństwa aplikacji

`ASVS` może być wykorzystywany w procesie rozwoju zwinnego jako ramy do określenia konkretnych zadań, które zespół musi zaimplementować, aby stworzyć bezpieczny produkt. Jednym z podejść może być: rozpoczęcie od poziomu 1, weryfikacja konkretnej aplikacji lub systemu zgodnie z wymaganiami `ASVS` dla określonego poziomu, znalezienie brakujących kontroli i utworzenie konkretnych zgłoszeń/zadań w backlogu. Pomaga to w priorytetyzacji konkretnych zadań (lub groomingu) oraz czyni bezpieczeństwo widocznym w procesie agile. Może to również służyć do priorytetyzacji zadań audytowych i przeglądowych w organizacji, gdzie konkretny wymóg `ASVS` może być driverem dla przeglądu, refaktoryzacji lub audytu dla określonego członka zespołu i być widoczny jako "dług technologiczny" w backlogu, który w końcu musi zostać spłacony.

### Jako ramy do kierowania zakupem bezpiecznego oprogramowania

ASVS to świetna struktura, która pomaga w zakupie bezpiecznego oprogramowania lub usług niestandardowego rozwoju. Kupujący może po prostu postawić wymaganie, że oprogramowanie, które chcą nabyć, musi zostać opracowane na poziomie X według `ASVS`, i zażądać od sprzedawcy udowodnienia, że oprogramowanie spełnia wymagania `ASVS` na poziomie X. To działa dobrze, gdy jest połączone z OWASP Secure Software Contract Annex.
