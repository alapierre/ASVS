# V11 Logika Biznesowa

## Cele kontroli

Upewnij się, że audytowana aplikacja spełnia następujące wysokopoziomowe wymagania:

* Logika biznesowa jest sekwencyjna, przetwarzana w kolejności i nie można jej ominąć.
* Logika biznesowa obejmuje limity w celu wykrywania i zapobiegania atakom zautomatyzowanym, takim jak ciągłe, małe przelewy funduszy, dodawanie miliona znajomych pojedynczo itp.
* Przepływy logiki biznesowej o wysokiej wartości uwzględniają przypadki nadużyć i działania złoczyńców, a także mają zabezpieczenia przed atakami polegającymi na podszywaniu się, manipulacji, ujawnianiu informacji i podnoszeniu uprawnień.

## V11.1 Bezpieczeństwo Logiki Biznesowej

Bezpieczeństwo logiki biznesowej jest tak indywidualne dla każdej aplikacji, że żadna lista kontrolna nie będzie miała zastosowania. Bezpieczeństwo logiki biznesowej musi być zaprojektowane, aby chronić przed prawdopodobnymi zagrożeniami zewnętrznymi — nie można go dodać za pomocą zapór sieciowych dla aplikacji internetowych ani bezpiecznych komunikacji. Rekomendujemy stosowanie modelowania zagrożeń podczas sprintów projektowych, na przykład za pomocą narzędzi takich jak OWASP Cornucopia czy podobnych.

|     #      | Opis                                                                                                                                                                                                                                                                                                       | L1 | L2 | L3 | CWE |
|:----------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **11.1.1** | Upewnij się, że aplikacja przetwarza przepływy logiki biznesowej dla tego samego użytkownika wyłącznie w sekwencyjnej kolejności kroków, bez pomijania żadnych etapów.                                                                                                                                     | ✓  | ✓  | ✓  | 841 |
| **11.1.2** | Sprawdź, czy aplikacja przetwarza przepływy logiki biznesowej z uwzględnieniem wszystkich kroków przetwarzanych w realistycznym czasie dla człowieka, tj. transakcje nie są przesyłane zbyt szybko[^1].                                                                                                    | ✓  | ✓  | ✓  | 799 |
| **11.1.3** | Sprawdź, czy aplikacja ma odpowiednie limity dla konkretnych działań biznesowych lub transakcji, które są właściwie egzekwowane indywidualnie dla każdego użytkownika.                                                                                                                                     | ✓  | ✓  | ✓  | 770 |
| **11.1.4** | Sprawdź, czy aplikacja posiada mechanizmy przeciwdziałające automatyzacji wywołań (excessive calls) w celu ochrony przed nadmiernymi wywołaniami, takimi jak masowe wydobycie danych, żądania dotyczące logiki biznesowej, przesyłanie plików lub ataki typu odmowa usługi (DoS).                          | ✓  | ✓  | ✓  | 770 |
| **11.1.5** | Sprawdź, czy aplikacja posiada limity logiki biznesowej lub mechanizmy walidacji służące ochronie przed prawdopodobnymi ryzykami biznesowymi lub zagrożeniami, zidentyfikowanymi za pomocą modelowania zagrożeń lub podobnych metodyk.                                                                     | ✓  | ✓  | ✓  | 841 |
| **11.1.6** | Sprawdź, czy aplikacja nie jest narażona na problemy związane z "Time Of Check to Time Of Use"[^2] (TOCTOU) lub inne konkurencyjne warunki wyścigowe (race conditions) dla wrażliwych operacji.                                                                                                            |    | ✓  | ✓  | 367 |
| **11.1.7** | Sprawdź, czy aplikacja monitoruje nietypowe zdarzenia lub aktywności z perspektywy logiki biznesowej. Na przykład, próby wykonania działań w nieprawidłowej kolejności lub działań, których zwykły użytkownik nigdy by nie podjął. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 754 |
| **11.1.8** | Sprawdź, czy aplikacja posiada konfigurowalne powiadomienia, które są aktywowane, gdy wykryte zostaną zautomatyzowane ataki lub nietypowa aktywność.                                                                                                                                                       |    | ✓  | ✓  | 390 |

[^1]: Takie sprawdzenie jest ważne z punktu widzenia bezpieczeństwa, ponieważ pomaga wykryć i zapobiegać atakom automatycznym oraz nadużyciom. Ograniczenie prędkości przetwarzania transakcji zmusza potencjalnych napastników do działania w tempie bliższym ludzkiemu, co utrudnia przeprowadzenie ataków masowych, takich jak brute-force czy DDoS (Distributed Denial of Service). Wprowadzenie realistycznego czasu dla przetwarzania kroków logiki biznesowej może również pomóc w monitorowaniu nietypowych zachowań użytkowników oraz wykrywaniu prób oszustw lub nadużyć, takich jak wielokrotne tworzenie kont, próby prania brudnych pieniędzy czy inne działania niezgodne z prawem. (Przypis tłumacza)


[^2]: Time Of Check to Time Of Use (TOCTOU) to rodzaj ataku polegający na wykorzystaniu zmiany stanu systemu między momentem sprawdzenia (weryfikacji) a momentem użycia (wykonania operacji). W przypadku aplikacji, TOCTOU może wystąpić, gdy dane są sprawdzane przed ich użyciem, ale istnieje okno czasowe, w którym ich stan może ulec zmianie przed faktycznym użyciem. Przykład TOCTOU: Przypuśćmy, że aplikacja sprawdza, czy użytkownik ma uprawnienia do dostępu do określonego pliku przed jego otwarciem. Jeśli atakujący może zmienić plik między sprawdzeniem a otwarciem (np. przez stworzenie dowiązania symbolicznego), może dojść do nieautoryzowanego dostępu do tego pliku. TOCTOU może prowadzić do naruszeń bezpieczeństwa, takich jak nieautoryzowany dostęp, przechwytywanie danych lub podmiana zasobów. Aby zminimalizować ryzyko związane z TOCTOU, ważne jest stosowanie odpowiednich technik blokowania i synchronizacji oraz wykonywanie sprawdzenia i użycia w jednej atomowej operacji, jeśli to możliwe. (Przypis tłumacza)

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [OWASP Web Security Testing Guide 4.1: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README.html)
* Przeciwdziałanie automatyzacji można osiągnąć na wiele sposobów, w tym poprzez użycie: [OWASP AppSensor](https://github.com/jtmelton/appsensor) and [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [OWASP AppSensor](https://github.com/jtmelton/appsensor) może również pomóc w wykrywaniu ataków i reagowaniu na nie.
* [OWASP Cornucopia](https://owasp.org/www-project-cornucopia/)
