# password-manager
Jednostavan i siguran prototip alata za pohranu zaporki koji koristi simetričnu kriptografiju / A simple and secure prototype of a password storage tool using symmetric cryptography


Alat za baratanje zaporkama prepoznaje naredbe "init", "put" i "get".
Ukoliko nije unesen potreban broj argumenata za svaku od naredaba, ispisuje se odgovarajuća poruka koja daje informacije o korištenju naredaba.

Alat je ostvaren tako da enkriptira i dekriptira cijeli tekstualni sadržaj, a ne pojedini par adresa-lozinka posebno. 
Napadaču tako ne dajemo informaciju o tome koliko je lozinki pohranjeno. Za šifriranje lozinki koristi se AES-GCM, a za provjeru integriteta HMAC-SHA256.
Funkcija za derivaciju ključa koju sam koristio je PBKDF2.
Prilikom svakog spremanja novog para adresa-lozinka (ili inicijalizacije) sadržaj datoteke se enkriptira pomoću AES-GCM bez paddinga. 
AES-GCM kao inpute prima: ključ, tekst koji je potrebno šifrirati, inicijalizacijski vektor te dodatne podatke. 
Zatim se za očuvanje integriteta koristi HMAC-SHA256. Glavna(master) lozinka nam je potrebna pri derivaciji ključa te pri očuvanju integriteta. 
U datoteku se zapisuje redom IV, sifrirani tekst te mac za kasniju provjeru integriteta.
Prilikom učitavanja sadržaja datoteke, odnosno parova adresa-lozinka sadržaj datoteke se odvaja u polja bitova, tj. IV, sifrirani tekst i mac. 
Zatim se sifrirani tekst uspješno dekriptira AES-GCM-om bez paddinga ako je upisana ispravna glavna zaporka, 
odnosno ako je provedena uspješna provjera integriteta (pročitani mac jednak onome ponovo izračunatom pomoću glavne lozinke).

Prevođenje koda: javac PohranaZaporki.java

Primjeri izvođenja:

1) inicijalizacija: java PohranaZaporki.java init glavnaZaporka (2 argumenta)
2) stavljanje zaporke: java PohranaZaporki.java put glavnaZaporka fer zapZaFer (4 argumenta)
3) dohvaćanje zaporke: java PohranaZaporki.java get glavnaZaporka fer (3 argumenta)

Dakle: prevesti kod, inicijalizirati bazu te zatim proizvoljno koristiti naredbe get i put (ili init za ponovnu inicijalizaciju/brisanje baze).
