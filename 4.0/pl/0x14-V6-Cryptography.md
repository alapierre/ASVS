# V6 Kryptografia

## Cele kontroli

Upewnij się, że audytowana aplikacja spełnia następujące wymagania na wysokim poziomie:

* Wszystkie moduły kryptograficzne zawodzą w bezpieczny sposób, a błędy są poprawnie obsługiwane[^1].
* Używany jest odpowiedni generator liczb losowych.
* Dostęp do kluczy jest bezpiecznie zarządzany.

## V6.1 Klasyfikacja informacji

Najważniejszym zasobem jest przetwarzana, przechowywana lub przesyłana przez aplikację informacja. Zawsze przeprowadzaj ocenę wpływu na prywatność, aby właściwie sklasyfikować wymagania dotyczące ochrony danych przechowywanych w aplikacji.

|     #     | Opis                                                                                                                                                                                                                                                                                                                                      | L1 | L2 | L3 | CWE |
|:---------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **6.1.1** | Zweryfikuj, czy dane które podlegają ochronie prawnej są przechowywane w postaci zaszyfrowanej w spoczynku, np. dane identyfikujące osobę (PII), wrażliwe informacje osobiste (dane szczególnych kategorii) lub dane, które są prawdopodobnie objęte regulacjami dotyczącymi ochrony prywatności, takimi jak RODO w UE.                   |    | ✓  | ✓  | 311 |
| **6.1.2** | Zweryfikuj, czy chronione prawem dane medyczne są przechowywane w postaci zaszyfrowanej w spoczynku, np. dokumentacja medyczna, szczegóły urządzeń medycznych lub dane używane do badań naukowych, które można połączyć z możliwą do identyfikacji osobą fizyczną.                                                                        |    | ✓  | ✓  | 311 |
| **6.1.3** | Zweryfikuj, że chronione prawem dane finansowe są przechowywane w postaci zaszyfrowanej w spoczynku, np. konta finansowe, informacje o zadłużeniu lub historii kredytowej, dokumenty podatkowe, historia wynagrodzeń, beneficjenci lub dane używane do badań naukowych, które można połączyć z możliwą do identyfikacji osobą fizyczną. . |    | ✓  | ✓  | 311 |

## V6.2 Algorytmy

Najnowsze postępy w dziedzinie kryptografii pokazują, że uważane za bezpieczne algorytmy i długości kluczy nie są już wystarczająco dobre do ochrony informacji. Dlatego ważne jest, aby zmieniana używanych algorytmów była możliwa w przyszłości.

Chociaż ta sekcja nie jest łatwa do przetestowania poprzez penetrowanie aplikacji, to deweloperzy powinni uznać całą tę sekcję za obowiązkową, nawet jeśli większość elementów nie posiada oznaczenia `L1`.

|     #     | Opis                                                                                                                                                                                                                                                                                                                                                                                      | L1 | L2 | L3 | CWE |
|:---------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **6.2.1** | Zweryfikuj, że wszystkie moduły kryptograficzne zawierają mechanizm bezpiecznego zawodzenia[^2] i że błędy są obsługiwane w taki sposób, aby nie umożliwiać ataków typu Padding Oracle.                                                                                                                                                                                                   | ✓  | ✓  | ✓  | 310 |
| **6.2.2** | Zweryfikuj, że używane są powszechnie stosowane, standardowe lub zatwierdzone przez rządy algorytmy, tryby i biblioteki kryptograficzne, a nie niestandardowe rozwiązania kryptograficzne. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                                                                                        |    | ✓  | ✓  | 327 |
| **6.2.3** | Zweryfikuj, że wektory inicjalizacji szyfrowania, konfiguracja szyfru oraz tryby blokowe są bezpiecznie skonfigurowane zgodnie z najnowszymi wytycznymi.                                                                                                                                                                                                                                  |    | ✓  | ✓  | 326 |
| **6.2.4** | Zweryfikuj, że algorytmy generowania liczb losowych, szyfrowania lub funkcji skrótu, długość kluczy, liczba rund, szyfry lub tryby blokowe, mogą być w każdej chwili rekonfigurowane, uaktualniane lub zmieniane, aby chronić zaszyfrowane dane przed ujawnieniem w przypadku odkrycia słabości danego algorytmu. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 326 |
| **6.2.5** | Zweryfikuj, że nie są używane uznawane za niebezpieczne tryby blokowe (np. ECB, itp.), tryby dopełnienia (np. PKCS#1 v1.5, itp.), szyfry o małych rozmiarach bloków (np. Triple-DES, Blowfish, itp.) i słabe algorytmy skrótu (np. MD5, SHA1, itp.), chyba że są one wymagane ze względu na zgodność wsteczną.                                                                            |    | ✓  | ✓  | 326 |
| **6.2.6** | Zweryfikuj, że wartości `nonce`, wektory inicjalizacji oraz inne liczby jednorazowego użytku nie są używane więcej niż raz z danym kluczem szyfrującym. Metoda generowania musi być odpowiednia dla używanego algorytmu.                                                                                                                                                                  |    | ✓  | ✓  | 326 |
| **6.2.7** | Zweryfikuj, że zaszyfrowane dane są uwierzytelniane poprzez podpisy cyfrowe, uwierzytelnione tryby szyfrowania lub HMAC, aby upewnić się, że tekst jawny nie został zmieniony przez nieuprawnioną osobę.                                                                                                                                                                                  |    |    | ✓  | 326 |
| **6.2.8** | Zweryfikuj, że wszystkie operacje kryptograficzne są realizowane w czasie stałym (ang. constant-time), bez żadnych "skrótów" (ang. short-circuit) w porównaniach, obliczeniach lub zwracaniu, aby uniknąć wycieków informacji.                                                                                                                                                            |    |    | ✓  | 385 |

## V6.3 Wartości losowe

Generowanie prawdziwych liczb losowych (PRNG) jest niezwykle trudne do realizacji. W ogólności, dobre źródła entropii w systemie szybko zostaną wyczerpane, jeśli będą nadużywane, ale źródła z mniejszą losowością mogą prowadzić do przewidywalnych kluczy i sekretów [^3].

|     #     | Opis                                                                                                                                                                                                                                                                                                          | L1 | L2 | L3 | CWE |
|:---------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **6.3.1** | W przypadku gdy wartości losowe mają być trudne do odgadnięcia przez atakującego, upewnij się, że wszystkie liczby losowe, nazwy plików, GUIDy i ciągi znaków są generowane za pomocą bezpiecznego generatora liczb losowych modułu kryptograficznego.                                                        |    | ✓  | ✓  | 338 |
| **6.3.2** | Sprawdź, czy GUID-y są tworzone z wykorzystaniem algorytmu GUID v4 oraz kryptograficznie bezpiecznego generatora liczb pseudolosowych (CSPRNG). GUID-y tworzone z wykorzystaniem innych generatorów liczb pseudolosowych mogą być przewidywalne.                                                              |    | ✓  | ✓  | 338 |
| **6.3.3** | Upewnij się, że aplikacja generuje liczby losowe z wystarczającą entropią nawet pod dużym obciążeniem, lub że aplikacja może płynnie zmniejszać swoją wydajność w takich okolicznościach. Jest to istotne, aby zapewnić, że generowane liczby losowe są faktycznie losowe i nieprzewidywalne dla atakującego. |    |    | ✓  | 338 |

## V6.4 Zarządzanie Sekretami 

Mimo że ta sekcja jest trudna do przetestowania podczas penetracji, programiści powinni uważać tę sekcję za obowiązkową, nawet jeśli większość elementów nie ma określonego poziomu `L1`.

|     #     | Opis                                                                                                                                                                                                                                                                       | L1 | L2 | L3 | CWE |
|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:---:|
| **6.4.1** | Sprawdź, czy w aplikacji jest używane narzędzie do zarządzania sekretami, takie jak `key vault`, które pozwala na bezpieczne tworzenie, przechowywanie, kontrolowanie dostępu i usuwanie sekretów. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) |    | ✓  | ✓  | 798 |
| **6.4.2** | Zweryfikuj, że klucze kryptograficzne nie są zapisane na stałe w aplikacji, lecz zamiast tego wykorzystywany jest izolowany moduł zabezpieczeń, taki jak np. `key vault`. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering))                          |    | ✓  | ✓  | 320 |

## References

Aby uzyskać więcej informacji, zobacz także:

* [OWASP Testing Guide 4.0: Testing for weak Cryptography](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)

[^1]: "Fail in a secure manner" odnosi się do sytuacji, kiedy moduł kryptograficzny zawodzi lub nie działa poprawnie. W takim przypadku ważne jest, aby moduł ten nie narażał aplikacji na dodatkowe zagrożenia związane z bezpieczeństwem. Innymi słowy, "fail in a secure manner" oznacza, że w przypadku wystąpienia błędu w module kryptograficznym, aplikacja powinna być zaprojektowana tak, aby ten błąd nie naraził poufnych danych lub kluczowych funkcjonalności na ryzyko ataków. (przypis tłumacza)

[^2]: Zobacz przypis 1

[^3]: Aby zapewnić wysoką jakość generowania liczb pseudolosowych, ważne jest, aby wykorzystać jako źródło entropii fizyczne zjawiska, takie jak hałas termiczny, zmienność czasu rzeczywistego lub ruch myszki kierowanej przez człowieka. Należy także unikać powtarzalnych wartości, ponieważ mogą one prowadzić do łamania kluczy lub innych podobnych ataków. Dlatego ważne jest, aby zapewnić odpowiednie ustawienia losowości dla algorytmów kryptograficznych, aby zapobiec wykorzystaniu niskiej entropii i tym samym zapewnienie bezpieczeństwa danych (przypis tłumacza).
