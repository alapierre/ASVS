# V4 Kontrola Dostępu

## Cele kontroli

Autoryzacja to koncepcja zezwalania na dostęp do zasobów tylko tym, którzy mogą z nich korzystać. Upewnij się, że zweryfikowana aplikacja spełnia następujące wymagania wysokiego poziomu:

* Osoby uzyskujące dostęp do zasobów posiadają ważne poświadczenia, aby to zrobić.
* Użytkownicy są powiązani z dobrze zdefiniowanym zestawem ról i uprawnień.
* Metadane roli i uprawnień są chronione przed ponownym odtworzeniem lub manipulacją.

## Wymagania weryfikacji bezpieczeństwa

## V4.1 Ogólny projekt kontroli dostępu

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.1.1** | Sprawdź, czy aplikacja wymusza reguły kontroli dostępu w zaufanej warstwie usług, zwłaszcza jeśli kontrola dostępu po stronie klienta jest obecna i można ją ominąć.. | ✓ | ✓ | ✓ | 602 |
| **4.1.2** | Zweryfikuj, czy użytkownicy końcowi nie mogą manipulować wszystkimi atrybutami użytkownika i danych oraz zasadami używanymi przez kontrolę dostępu, chyba że zostaną specjalnie upoważnieni. | ✓ | ✓ | ✓ | 639 |
| **4.1.3** | Sprawdź, czy istnieje zasada najniższych uprawnień — użytkownicy powinni mieć dostęp tylko do funkcji, plików danych, adresów URL, kontrolerów, usług i innych zasobów, do których posiadają określone uprawnienia. Oznacza to ochronę przed fałszowaniem i podnoszeniem uprawnień. ([C7](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 285 |
| **4.1.4** | [USUNIĘTO, DUPLIKAT 4.1.3] | | | | |
| **4.1.5** | Sprawdź, czy kontrola dostępu nie działa bezpiecznie, w tym w przypadku wystąpienia wyjątku. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 285 |

## V4.2 Operation Level Access Control

| # | Opis | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.2.1** | Sprawdź, czy wrażliwe dane i interfejsy API są chronione przed atakami typu Insecure Direct Object Reference (IDOR), których celem jest tworzenie, odczytywanie, aktualizowanie i usuwanie rekordów, na przykład tworzenie lub aktualizowanie rekordu innej osoby, przeglądanie rekordów wszystkich osób lub usuwanie wszystkich rekordów. | ✓ | ✓ | ✓ | 639 |
| **4.2.2** | Sprawdź, czy aplikacja lub platforma wymusza silny mechanizm ochrony przed CSRF w celu ochrony uwierzytelnionej funkcjonalności oraz czy skuteczna ochrona przed automatyzacją lub ochrona przed CSRF chroni nieuwierzytelnioną funkcjonalność. | ✓ | ✓ | ✓ | 352 |

## V4.3 Other Access Control Considerations

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.3.1** | Sprawdź, czy interfejsy administracyjne używają odpowiedniego uwierzytelniania wieloskładnikowego, aby zapobiec nieautoryzowanemu użyciu. | ✓ | ✓ | ✓ | 419 |
| **4.3.2** | Sprawdź, czy przeglądanie katalogów jest wyłączone, chyba że celowo tego chcesz. Ponadto aplikacje nie powinny umożliwiać wykrywania ani ujawniania metadanych plików lub katalogów, takich jak foldery Thumbs.db, .DS_Store, .git lub .svn. | ✓ | ✓ | ✓ | 548 |
| **4.3.3** | Sprawdź, czy aplikacja ma dodatkowe uprawnienia (takie jak uwierzytelnianie podwyższające lub uwierzytelnianie adaptacyjne) dla systemów o niższej wartości i/lub podział obowiązków dla aplikacji o dużej wartości w celu egzekwowania kontroli przed oszustwami zgodnie z ryzykiem związanym z aplikacją i przeszłymi oszustwami.| | ✓ | ✓ | 732 |

## Bibliografia

Aby uzyskać więcej informacji, zobacz także:

* [OWASP Testing Guide 4.0: Authorization](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/README.html)
* [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
* [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [OWASP REST Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
