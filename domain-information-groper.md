---
title: dig
layout: default
---

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

