# Onderhoud & Voorraad (Node.js + Postgres, voor Render)

Multi-tenant webapp voor onderhoudsbeheer en voorraadbeheer. Functioneel gelijk
aan de eerdere single-file PHP-versie, herbouwd in Node.js + Express +
PostgreSQL zodat het op Render kan draaien (Render ondersteunt geen PHP en
heeft een tijdelijke schijf, wat SQLite ongeschikt maakt voor productie daar).

## Functionaliteit
- **Multi-tenant**: elk bedrijf heeft volledig gescheiden data.
- **Onderhoud**: storingen met prioriteit/status/toewijzing, opmerkingen, geschiedenis.
- **Voorraad**: producten met categorie/leverancier/locatie, voorraadmutaties
  (levering/afschrijving/telling/correctie), historie, bestellijst, CSV-export.
- **Gebruikersbeheer**: rollen (Beheerder/Manager/Technicus), makkelijk toevoegen.
- **Platform super-admin**: overzicht van alle bedrijven, ertussen schakelen,
  bedrijven aanmaken/verwijderen.

## Lokaal draaien
```bash
npm install
cp .env.example .env   # vul DATABASE_URL in (lokale of Render Postgres)
npm start
```
Open http://localhost:3000. Bij de eerste start wordt het schema aangemaakt en
gevuld met demodata. Demo-login: `admin@demo.local` / `Demo1234!`.

## Deployen op Render
1. Zet deze map in een (nieuwe) GitHub-repository.
2. In Render: maak een **PostgreSQL**-database aan.
3. Maak een **Web Service** aan vanaf die repo:
   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
   - Environment variable `DATABASE_URL` → de "Internal Database URL" van de Postgres-instantie
   - Environment variable `SESSION_SECRET` → een willekeurige lange string
4. Na de eerste deploy maakt de app zelf de tabellen aan en zet demodata klaar.

## Technisch
- `src/db.js` — Postgres-verbinding, migraties, seed.
- `src/helpers.js` — pure logica (rechten, voorraadmutaties, datums) — apart
  getest met unit tests.
- `src/views.js` — gedeelde HTML-layout/componenten.
- `src/server.js` — Express-routes voor alle pagina's en acties.
- Sessies via ondertekende cookies (`cookie-session`), geen sessie-opslag nodig.
- CSRF-bescherming op elke formulier-POST.
- Wachtwoorden gehasht met bcrypt.
