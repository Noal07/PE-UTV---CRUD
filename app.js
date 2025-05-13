const express = require("express");
const path = require("path");
const http = require("http");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const port = 3000;
const server = http.createServer(app);

/** Serverer statiske filer fra public-mappen */
app.use(express.static(path.join(__dirname, "public")));

/** Middleware for å tolke JSON- og URL-kodet data */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/** Konfigurerer sesjonshåndtering */
app.use(
  session({
    secret: "hemmeligNøkkel",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
  })
);

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

/** Kobler til SQLite-database */
const db = new sqlite3.Database("FreiaVGS.db", (err) => {
  if (err) {
    console.error("Feil ved tilkobling til database:", err.message);
  } else {
    console.log("Koblet til SQLite-database.");
  }
});

/** Rute: Viser forsiden (kun for autentiserte brukere) */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "view", "index.html"));
});

/** Rute: Viser innloggingssiden */
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "view", "login.html"));
});

/** Rute: Viser siden for å opprette ny bruker */
app.get("/ny-bruker", (req, res) => {
  res.sendFile(path.join(__dirname, "view", "ny-bruker.html"));
});

/** Rute: Viser privat side (kun for autentiserte brukere) */
app.get("/oversikt", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "view", "oversikt.html"));
});

/** Rute: Logger ut brukeren og avslutter sesjonen */
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.clearCookie("connect.sid");
  res.redirect("/login");
});

/**
 * Rute: Håndterer innlogging
 * Sjekker epost og passord mot databasen
 */
app.post("/login", (req, res) => {
  const { epost, passord } = req.body;
  if (!epost || !passord) {
    return res.redirect("/login?error=Mangler data fra skjema");
  }
  const sql = "SELECT * FROM Bruker WHERE Epost = ?";
  db.get(sql, [epost], async (err, row) => {
    if (err) {
      console.error("Databasefeil:", err.message);
      return res.redirect("/login?error=En uventet feil har oppstått");
    }
    if (row && (await bcrypt.compare(passord, row.Passord))) {
      req.session.user = {
        id: row.ID_bruker,
        navn: row.Navn,
        epost: row.Epost,
      };
      res.redirect("/");
    } else {
      res.redirect("/login?error=Ugyldig epost eller passord");
    }
  });
});

/**
 * Rute: Håndterer registrering av ny bruker
 * Lagrer brukeren i databasen med kryptert passord
 */
app.post("/ny-bruker", async (req, res) => {
  const { epost, navn, passord, rolle } = req.body;
  if (!epost || !passord || !navn || !rolle) {
    return res.redirect("/login?error=Mangler data fra skjema");
  }
  const sql =
    "INSERT INTO Bruker (Navn, Epost, Passord, ID_Rolle) VALUES (?, ?, ?, ?)";
  const hashedPassword = await bcrypt.hash(passord, 10);
  db.run(sql, [navn, epost, hashedPassword, Number(rolle)], function (err) {
    if (err) {
      console.error("Databasefeil:", err.message);
      return res.redirect("/login?error=En uventet feil har oppstått");
    }
    res.redirect("/?melding=Bruker opprettet");
  });
});

/** Henter alle brukere for oversikt (krever autentisering) */
app.get("/brukere", isAuthenticated, (req, res) => {
  const sql = "SELECT ID_bruker, Navn, Epost, ID_Rolle FROM Bruker";
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Databasefeil ved henting:", err.message);
      return res.status(500).send("Feil ved henting av brukerdata.");
    }
    res.json(rows);
  });
});

/** Sletter en spesifikk bruker (krever autentisering) */
app.delete("/brukere/:brukerId", isAuthenticated, (req, res) => {
  const brukerId = req.params.brukerId;
  const sql = "DELETE FROM Bruker WHERE ID_bruker = ?";
  db.run(sql, [brukerId], function (err) {
    if (err) {
      console.error("Databasefeil ved sletting:", err.message);
      return res.status(500).send("Feil ved sletting av bruker.");
    }
    this.changes > 0
      ? res.sendStatus(200)
      : res.status(404).send(`Bruker med ID ${brukerId} ikke funnet.`);
  });
});

/** Starter serveren */
server.listen(port, () => {
  console.log(`Server kjører på http://localhost:${port}`);
});
