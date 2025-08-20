---

# 🛡️ Sécurité bancaire 360° : SIEM, SOAR, IDS/IPS, DLP, NAC ,  EDR et XDR dans un SOC(Security Operations Center) moderne

---

## 📑 Table des matières
- [1. SIEM (Security Information and Event Management)](#siem)
- [2. SOAR (Security Orchestration, Automation & Response)](#soar)
- [3. IDS / IPS (Intrusion Detection / Prevention System)](#ids-ips)
- [4. EDR (Endpoint Detection & Response)](#edr)
- [5. XDR (Extended Detection & Response)](#xdr)
- [6. DLP (Data Loss Prevention)](#dlp)
- [7. NAC (Network Access Control)](#nac)
- [8. WAF et Protection Applicative (F5 + Akamai)](#waf-f5-akamai)
- [9. Intégration SOC](#integration-soc)
- [🎯 Exemple concret d’attaque stoppée](#exemple-attaque)

---

<a id="siem"></a>
## 🔹 SIEM (Security Information and Event Management)

* Collecte les **logs** (firewall, IDS/IPS, serveurs, AD, cloud, EDR, DLP, NAC, F5, Akamai…).
* Fait de la **corrélation** (ex : 10 échecs de login + scan de port + upload suspect).
* Génère des **alertes** pour le SOC (Security Operations Center).

👉 **Œil du SOC** 👀 : il voit tout, mais **n’agit pas directement**.

---

<a id="soar"></a>
## 🔹 SOAR (Security Orchestration, Automation and Response)

* Reçoit les **alertes du SIEM**.
* Permet d’**automatiser les réponses** via playbooks.
* Exemples :

  * Bloquer une IP sur le firewall ou F5.
  * Isoler une machine compromise via EDR/XDR.
  * Désactiver un compte AD.
  * Créer automatiquement un ticket et notifier les équipes.

👉 **Bras et jambes du SOC** 💪.

---

<a id="ids-ips"></a>
## 🔹 IDS (Intrusion Detection System)

* **Détecte** les attaques réseau (sniffing, scans, signatures malveillantes).
* Génère des **logs et alertes** → envoyés au SIEM.
* Ex : Snort, Suricata, Zeek.

👉 IDS = **capteurs passifs** pour la détection.

---

## 🔹 IPS (Intrusion Prevention System)

* **Bloque en temps réel** les attaques (inline).
* Peut aussi envoyer des logs vers le SIEM.
* Ex : Cisco Firepower, Palo Alto Threat Prevention.

👉 IPS = **réaction automatique réseau**.

---

<a id="dlp"></a>
## 🔹 DLP (Data Loss Prevention)

* Empêche la **fuite de données sensibles** (CB, fichiers confidentiels).
* Analyse mails, impressions, transferts USB/cloud.
* Ex : Symantec DLP, Microsoft Purview DLP.

👉 **Détective** 🕵️ qui surveille les fuites.

---

<a id="nac"></a>
## 🔹 NAC (Network Access Control)

* Contrôle **qui peut se connecter** au réseau.
* Vérifie l’identité et la conformité des postes (patchs, antivirus).
* Peut isoler les invités ou les machines suspectes dans un VLAN restreint.
* Ex : Cisco ISE, Aruba ClearPass.

👉 **Vigile à l’entrée du bâtiment** 🚪.

---

<a id="edr"></a>
## 🔹 EDR (Endpoint Detection & Response)

* Protège et surveille les **endpoints** (PC, serveurs, laptops).
* Détecte ransomwares, malwares, comportements suspects.
* Peut **isoler une machine du réseau**.
* Ex : CrowdStrike, SentinelOne, Defender ATP.

👉 **Garde du corps personnel** 🛡️.

---

<a id="xdr"></a>
## 🔹 XDR (Extended Detection & Response)

* Évolution de l’EDR → couvre **endpoints + réseau + cloud + email + identité**.
* Corrélation **native** entre sources multiples pour réduire le bruit.
* Permet une **réponse coordonnée** sur tout l’écosystème IT.
* Ex : Microsoft Defender XDR, Palo Alto Cortex XDR, Trend Micro Vision One.

👉 **Équipe de sécurité coordonnée** 👮‍♂️👩‍💻 qui protège toute l’entreprise.

---

<a id="waf-f5-akamai"></a>
## 🔹 F5 BIG-IP (ADC, WAF, Proxy)

* **Load balancing** (ADC).
* **Web Application Firewall (WAF)** → bloque SQLi, XSS, injections HTTP.
* **APM (Access Policy Manager)** → proxy d’authentification, MFA/SSO.
* Fournit des **logs applicatifs** (tentatives malveillantes, échecs login, anomalies) vers le SIEM.
* Le SOAR peut **pousser des règles dynamiques** (bloquer une IP, exiger MFA).

👉 **Le portier VIP à l’entrée de l’application** 🎭.

---

## 🔹 Akamai (CDN + Edge Security)

* **Kona Site Defender** → WAF distribué mondialement.
* **Bot Manager** → bloque scraping, fraude, bots.
* **Edge DNS** → protection contre attaques DNS.
* **Zero Trust Access** → alternative VPN sécurisée.
* Absorbe DDoS massifs avant même d’atteindre le réseau interne.
* Fournit aussi des **logs vers SIEM**.

👉 **La barrière de sécurité placée loin du bâtiment, sur l’autoroute** 🛣️.

---

## 🔹 Analogie simple

* **Akamai** = barrière éloignée 🏰.
* **F5** = portier d’élite 🎭.
* **Firewall** = contrôle d’identité classique 📑.
* **IDS** = caméra 🎥.
* **IPS** = vigile 🚓.
* **SIEM** = salle de contrôle 🖥️.
* **SOAR** = chef qui orchestre 👮.
* **DLP** = détective 📂.
* **NAC** = vigile à l’entrée 🚪.
* **EDR** = garde du corps 🕶️.
* **XDR** = équipe de sécurité coordonnée 👥.

---

## 🔹 Schéma logique global

**\[Akamai Edge] → \[F5 BIG-IP WAF/Proxy] → \[Firewall] → \[IDS/IPS] → \[SIEM ↔ SOAR] → \[XDR (incluant EDR)] → \[DLP / NAC] → \[SOC]**

---

## 🎯 Exemple d’attaque stoppée (Ransomware + Exfiltration)

1. **Intrusion** via phishing → EDR/XDR détecte exécution PowerShell suspecte.
2. **Mouvement latéral** → IDS détecte scans internes.
3. **Exploitation applicative** → Akamai bloque massifs, F5 filtre injections.
4. **Exfiltration** → DLP bloque transferts sensibles.
5. **Corrélation SIEM** → relie IDS + AD + EDR + DLP.
6. **SOAR** → exécute playbook (isolement via EDR/XDR, blocage IP, ticket).
7. **NAC** → met en quarantaine la machine.
8. **SOC** → supervise et ajuste règles.

👉 **Résultat** : Attaque stoppée à chaque niveau grâce à la **défense en profondeur**.

---
Parfait 👍 je t’ai mis à jour ton document pour **intégrer aussi XDR** (comme évolution de l’EDR) et harmoniser toutes les briques :

---

## 🔹 Comment ça marche ensemble ?

1. **Akamai** → bloque les attaques massives en périphérie (DDoS, bots, campagnes web).
2. **F5 BIG-IP** → proxy + WAF + authentification (MFA/SSO) avant d’atteindre l’app bancaire.
3. **Firewall** → filtrage réseau traditionnel (ports, IP, protocoles).
4. **IDS/IPS** → surveillent et bloquent les attaques réseau en temps réel.
5. **EDR/XDR** → protègent postes, serveurs et étendent la détection au réseau, au cloud, aux emails.
6. **DLP** → surveille et empêche les fuites de données sensibles.
7. **NAC** → contrôle l’accès réseau, isole les machines non conformes.
8. **SIEM** → centralise, corrèle et génère des alertes.
9. **SOAR** → orchestre les réponses automatiques (playbooks).
10. **SOC (analystes)** → investiguent, supervisent et prennent les décisions stratégiques.

---

## 🔥 Scénario d’attaque concret : Ransomware + Exfiltration (banque/finance)

### 1. Intrusion (phishing)

* L’attaquant envoie un email piégé.
* **Akamai Email/Edge Security** filtre une partie des campagnes massives.
* L’email atteint un utilisateur interne → pièce jointe ouverte.
* **EDR/XDR** (CrowdStrike, Defender XDR) alerte sur exécution suspecte (PowerShell anormal).

---

### 2. Mouvement latéral

* Le malware tente d’attaquer Active Directory et serveurs internes.
* **IDS** (Suricata/Zeek) détecte connexions SMB/LDAP anormales.
* **SIEM** (Splunk/QRadar/Elastic) corrèle avec logs AD → détection brute-force Kerberos.

---

### 3. Propagation réseau & exploitation applicative

* L’attaquant cible l’application bancaire exposée sur Internet.
* **Akamai Kona WAF** bloque SQLi/XSS en périphérie.
* Requêtes résiduelles arrivent sur **F5 BIG-IP WAF** → bloque injections, applique MFA/APM.
* Tentatives SMB internes bloquées par **IPS** (Cisco Firepower / Palo Alto).

---

### 4. Exfiltration de données

* Le malware tente d’envoyer des fichiers sensibles (numéros CB, SWIFT, contrats) vers un cloud externe.
* **DLP** (Symantec / Microsoft Purview) détecte les données sensibles et bloque l’upload.
* **SIEM** corrèle : alerte EDR/XDR + IDS + DLP = incident critique.

---

### 5. Réponse orchestrée

* **SOAR** (Cortex XSOAR / Splunk SOAR) exécute un playbook automatique :

  * Isoler la machine compromise via **EDR/XDR**.
  * Désactiver le compte AD compromis.
  * Bloquer l’IP externe sur **firewall** et **F5 BIG-IP**.
  * Créer un ticket Jira/ServiceNow pour le SOC et notifier l’équipe.

---

### 6. Contrôle d’accès réseau

* **NAC** (Cisco ISE / Aruba ClearPass) coupe l’accès de la machine compromise → quarantaine VLAN.

---

## ✅ Résultat

L’attaque est stoppée **à plusieurs niveaux** :

* **Akamai** → protection edge (DDoS, bots, attaques massives).
* **F5 BIG-IP** → WAF + proxy + MFA/SSO pour les apps bancaires.
* **Firewall / IDS / IPS** → filtrage + détection/prévention réseau.
* **EDR/XDR** → détection et réponse sur postes/serveurs + extension cloud/email.
* **DLP** → empêche fuite/exfiltration de données sensibles.
* **SIEM** → corrèle les événements pour créer une vision unique.
* **SOAR** → automatise la réponse.
* **NAC** → isole physiquement/logiquement les machines compromises.
* **SOC** → supervise, ajuste et chasse les menaces (threat hunting).

---

## 🔹 Schéma logique global

**\[Akamai Edge] → \[F5 BIG-IP WAF/Proxy] → \[Firewall] → \[IDS/IPS] → \[SIEM ↔ SOAR] → \[EDR/XDR + DLP + NAC] → \[SOC]**

---
<a id="integration-soc"></a>
# 🏦 Mise en place d’une architecture de sécurité dans une banque

## 🔹 1. **SIEM (Security Information and Event Management)**

👉 Cœur du SOC, collecte et corrèle tous les logs.

* **Objectif bancaire** :

  * Centraliser les logs (core banking system, SWIFT, trading apps, API exposées, F5, Akamai).
  * Détecter fraudes, anomalies, menaces persistantes (APT).

* **Logiciels utilisés** :

  * **Splunk Enterprise Security** (beaucoup utilisé en banque).
  * **IBM QRadar** (forte adoption secteur bancaire).
  * **Azure Sentinel** (banques cloud Microsoft).

* **Configuration clé** :

  * Collecteurs de logs sur **firewall, proxy, Active Directory, SWIFT, applis internes, F5 BIG-IP, Akamai WAF**.
  * Cas d’usage : *« 10 échecs login SWIFT + tentative transfert frauduleux + IP hors pays → alerte critique »*.

---

## 🔹 2. **SOAR (Security Orchestration, Automation & Response)**

👉 L’automatisation des réponses, pour compenser le manque d’analystes.

* **Objectif bancaire** :

  * Réduire le **temps moyen de réponse (MTTR)**.
  * Standardiser la gestion des incidents (fraude, malware, exfiltration).

* **Logiciels utilisés** :

  * **Palo Alto Cortex XSOAR**.
  * **Splunk SOAR**.
  * **IBM Resilient**.

* **Exemple Playbook** :

  * Alerte *« brute force SWIFT »* →

    1. Désactivation compte AD.
    2. Blocage IP sur firewall / F5 BIG-IP.
    3. Isolation poste avec EDR/XDR.
    4. Notification SOC + ticket ServiceNow.

---

## 🔹 3. **IDS / IPS (Intrusion Detection / Prevention System)**

👉 Protection réseau temps réel.

* **Objectif bancaire** :

  * Bloquer attaques sur **API bancaires, systèmes SWIFT, extranets clients**.
  * Détecter exfiltrations (C2 servers).

* **Logiciels utilisés** :

  * **Cisco Firepower**, **Palo Alto Threat Prevention**.
  * **Snort / Suricata** (IDS open-source en complément).

* **Configuration clé** :

  * IPS **inline** sur flux Internet.
  * IDS en mode **monitoring** sur trafic interne (east-west).

---

## 🔹 4. **EDR (Endpoint Detection & Response)**

👉 Sécurité des postes de travail + serveurs critiques.

* **Objectif bancaire** :

  * Détection malware/ransomware **avant propagation**.
  * Fournir **forensics** (commandes, fichiers, hash).

* **Logiciels utilisés** :

  * **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **SentinelOne**.

* **Configuration clé** :

  * Agents sur **postes traders, caisses, serveurs SWIFT**.
  * Réponse auto : *« isoler poste si C2 détecté »*.

---

## 🔹 5. **XDR (Extended Detection & Response)**

👉 Évolution de l’EDR : corrèle signaux **endpoints + réseau + cloud + email**.

* **Objectif bancaire** :

  * Détection avancée des menaces persistantes (APT).
  * Réduire le temps de détection (MTTD) en agrégeant plusieurs sources.
  * Fournir une visibilité **globale** (poste, réseau, identité, cloud).

* **Logiciels utilisés** :

  * **Microsoft Defender XDR**, **CrowdStrike Falcon Insight XDR**, **Palo Alto Cortex XDR**.

* **Configuration clé** :

  * Intégration avec **SIEM** et **SOAR**.
  * Corrélation IoC/IoA multi-domaines (hash malveillants, adresses IP C2, phishing emails).
  * Déclenchement de **playbooks SOAR** (isolation auto, blocage IP, désactivation comptes).

---

## 🔹 6. **Threat Intelligence Platform (TIP)**

👉 Alimente le SOC avec des **indicateurs de compromission (IoC)** et du **contexte de menace**.

* **Objectif bancaire** :

  * Anticiper les attaques ciblant les banques (fraudes SWIFT, APT financières).
  * Fournir aux analystes SOC du **contexte enrichi** (TTPs MITRE ATT\&CK, acteurs de la menace).
  * Partager des flux avec d’autres banques ou **FS-ISAC** (Financial Services ISAC).

* **Logiciels utilisés** :

  * **MISP (Malware Information Sharing Platform)** – open-source, très répandu.
  * **Anomali ThreatStream**.
  * **Recorded Future**.
  * **ThreatQuotient**.

* **Configuration clé** :

  * Intégration avec **SIEM/XDR** pour alimenter la corrélation.
  * Exemple : blocage automatique d’IP listées comme **C2** par MISP.
  * Règles dynamiques : si un **hash** est identifié comme malware par Threat Intel → blocage via **EDR/XDR**.

---

## 🔹 7. **DLP (Data Loss Prevention)**

👉 Empêche fuite d’infos sensibles (IBAN, SWIFT, données clients).

* **Objectif bancaire** :

  * Bloquer fuites **par email, USB, cloud**.
  * Détecter patterns sensibles (n° CB, messages SWIFT).

* **Logiciels utilisés** :

  * **Symantec DLP (Broadcom)**.
  * **Forcepoint DLP**.
  * **Microsoft Purview DLP**.

* **Configuration clé** :

  * Exemples de règles :

    * Pas d’email externe avec **>5 IBAN**.
    * Blocage upload Dropbox/Google Drive.
    * Blocage impression fichiers SWIFT hors horaires.

---

## 🔹 8. **NAC (Network Access Control)**

👉 Contrôle des connexions réseau.

* **Objectif bancaire** :

  * Vérifier qu’un poste est **conforme** (EDR/XDR actif, patchs OK).
  * Séparer réseaux **internes, invités, prestataires**.

* **Logiciels utilisés** :

  * **Cisco ISE**, **Aruba ClearPass**.

* **Configuration clé** :

  * Quarantaine auto si agent EDR/XDR désactivé.
  * VLAN restreint pour consultants externes.

---

## 🔹 9. **WAF et Protection Applicative (F5 + Akamai)**

👉 Sécurité des applis bancaires exposées.

* **Objectif bancaire** :

  * Stopper attaques web (SQLi, XSS, injection) avant qu’elles atteignent le SI bancaire.
  * Gérer charge et **DDoS** via protection distribuée.

* **Logiciels utilisés** :

  * **Akamai Kona Site Defender** (WAF/DDoS cloud, protection en edge).
  * **F5 BIG-IP Advanced WAF / APM** (WAF interne, contrôle MFA/SSO).

* **Configuration clé** :

  * Akamai = filtre en **périmètre Internet (edge)**.
  * F5 = filtre **intra-banque**, devant applications SWIFT, e-banking, APIs partenaires.
  * Intégration logs vers SIEM pour corrélation.

---

## 🔹 10. **Intégration SOC**

👉 Tout converge vers le SOC bancaire :

1. **Akamai + F5 + IDS/IPS + EDR + XDR + TIP + DLP + NAC** → envoient logs & IoCs au **SIEM**.
2. **SIEM** → corrèle et génère alertes.
3. **SOAR** → automatise la réponse (isoler poste, bloquer IP, alerter SOC).
4. **TIP** → enrichit les alertes avec contexte (IoC, TTP, campagnes actives).
5. **SOC analysts** → investiguent, ajustent règles, font du **threat hunting**.

---

# 🎯 Exemple concret d’attaque stoppée

### Cas : tentative d’exfiltration SWIFT avec APT connue

1. **TIP (MISP)** signale qu’une campagne APT ciblant le secteur bancaire utilise une IP malveillante.
2. **XDR** détecte communication d’un poste interne vers cette IP.
3. **SIEM** corrèle : alerte DLP + IOC TIP + trafic suspect XDR.
4. **SOAR** applique le playbook :

   * Isolement poste via **XDR**.
   * Blocage IP au firewall + F5.
   * Désactivation du compte AD.
5. **SOC analysts** consultent le TIP → confirment que l’IP est liée à une attaque sur d’autres banques (partage via FS-ISAC).

---

👉 **Résultat** :

* La menace est stoppée **proactivement** grâce à la Threat Intelligence.
* Les flux TIP alimentent la **défense prédictive** du SOC.
* Conformité et partage avec régulateurs garantis.

---

# 🔎 Corrélation des logs et événements dans un SIEM

## 1️⃣ Collecte et normalisation

* Les **logs** arrivent de partout : firewall, IDS/IPS, AD, proxy, EDR, DLP, applis métier, bases de données…
* Chaque log a un **format différent** (ex : syslog, JSON, CSV, messages bruts).
* Le SIEM les **normalise** → transforme en un schéma commun (ex : `timestamp`, `user`, `src_ip`, `dst_ip`, `action`, `status`).

👉 Exemple :

* Firewall : `SRC=10.10.1.2 DST=8.8.8.8 PORT=53 ACTION=ALLOW`
* AD : `User=hamza Action=Failed login IP=10.10.1.2`
  ➡️ Normalisés dans le SIEM en un format unique :

```json
{
  "timestamp": "2025-08-20T10:12:00Z",
  "src_ip": "10.10.1.2",
  "dst_ip": "8.8.8.8",
  "event_type": "login_failed",
  "user": "hamza"
}
```

---

## 2️⃣ Agrégation

Le SIEM peut **agréger plusieurs événements identiques** pour éviter le bruit.

* Exemple : 1 000 tentatives de login échouées en 1 minute = **1 seul événement agrégé "Bruteforce détecté"**.

---

## 3️⃣ Corrélation simple (règles de détection)

C’est du **rule-based correlation** : le SIEM applique des règles prédéfinies ou custom.

* Exemple règle :

  * **SI** plus de 10 échecs de login AD en moins de 2 minutes
  * **ET** l’IP source correspond à une alerte IDS de scan réseau
  * **ALORS** → générer une alerte "Brute force suspect".

👉 On parle ici de **use cases SIEM**.

---

## 4️⃣ Corrélation avancée (multi-source / multi-événement)

Le SIEM combine **des événements de différentes sources**.

### Exemple concret :

1. **IDS** détecte un scan de ports venant de `192.168.10.50`.
2. 2 heures après, **AD** reçoit 50 tentatives échouées de connexion venant de la même IP.
3. 10 minutes plus tard, **Firewall** loggue une tentative d’accès au serveur SWIFT depuis cette IP.

➡️ Le SIEM corrèle :

* Même IP attaquante.
* Étapes successives (Reconnaissance → Bruteforce → Tentative accès critique).
* Génère une alerte critique "Kill Chain en cours".

---

## 5️⃣ Corrélation temporelle

* Certains SIEM utilisent des **fenêtres de temps**.
* Exemple :

  * "Si un même utilisateur se connecte depuis Paris **et** New York dans un intervalle de 5 minutes → alerte (impossible travel)".

---

## 6️⃣ Corrélation contextuelle (Threat Intelligence & enrichissement)

* Le SIEM enrichit les logs avec :

  * **GeoIP** (IP localisée en Russie → suspect).
  * **Threat intelligence feeds** (IP connue comme C2 server → danger).
  * **CMDB/AD** (le serveur touché est "core banking" → criticité haute).

👉 Exemple :

* Un téléchargement de fichier `.exe` peut être **low risk** sur un poste test, mais **critical** sur un serveur SWIFT.

---

## 7️⃣ Corrélation avec scoring / machine learning

* Certains SIEM modernes (**UEBA – User and Entity Behavior Analytics**) font de la détection par **anomalies**.
* Exemple :

  * L’utilisateur "hamza" télécharge en moyenne 5 Mo/jour.
  * Aujourd’hui il a téléchargé 10 Go vers un cloud inconnu.
  * Score de risque = 95% → alerte "Data Exfiltration probable".

---

# 🎯 Résumé visuel

1. **Logs bruts** → normalisation
2. **Agrégation** → réduire le bruit
3. **Corrélation règles** → SI/ALORS
4. **Corrélation multi-source** → IDS + Firewall + AD
5. **Corrélation temporelle** → séquence dans le temps
6. **Corrélation contextuelle** → enrichissement (GeoIP, Threat Intel, AD)
7. **Corrélation avancée (UEBA)** → anomalies comportementales

---

👉 En gros :

* **Sans SIEM** → tu as 1 million de logs isolés.
* **Avec SIEM** → tu as 10 alertes pertinentes qui décrivent une **attaque structurée** (kill chain).



<a id="exemple-attaque"></a>
---

Voici des **exemples concrets** de corrélation dans 3 SIEM populaires : **Splunk (SPL)**, **QRadar (AQL)** et **Microsoft Sentinel (KQL)**.
Chaque règle inclut l’idée, la fenêtre temporelle et ce qu’elle émet.

---

# 1) Brute force AD (≥10 échecs puis 1 succès) — 10 min

### 🧠 Idée

Si un compte a ≥10 échecs de connexion en 10 minutes suivis d’un succès, alerte critique (compte potentiellement compromis).

### Splunk (SPL)

```spl
index=winsec sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4624,"success","failure")
| bin _time span=1m
| stats count(eval(outcome="failure")) as fails
        max(eval(outcome="success")) as has_success
        earliest(_time) as first_seen latest(_time) as last_seen
        by user, src_ip
| where fails>=10 AND has_success=1 AND last_seen-first_seen<=600
```

### QRadar (AQL)

```sql
SELECT userName AS user, sourceIP AS src_ip,
       COUNT(*) AS fails,
       MIN(startTime) AS first_seen, MAX(startTime) AS last_seen
FROM events
WHERE (eventName = 'Logon Failure' OR eventName='Logon Success')
  AND startTime > NOW() - 10 MINUTES
GROUP BY userName, sourceIP
HAVING SUM(CASE WHEN eventName='Logon Failure' THEN 1 ELSE 0 END) >= 10
   AND SUM(CASE WHEN eventName='Logon Success' THEN 1 ELSE 0 END) >= 1;
```

### Microsoft Sentinel (KQL)

```kusto
let window=10m;
let failures = SecurityEvent
| where TimeGenerated > ago(window) and EventID == 4625
| summarize fails=count() by Account, IpAddress;
let success  = SecurityEvent
| where TimeGenerated > ago(window) and EventID == 4624
| summarize has_success=count() by Account, IpAddress;
failures
| where fails >= 10
| join kind=inner success on Account, IpAddress
```

---

# 2) Impossible travel (connexion depuis 2 pays éloignés) — 5 min

### Splunk (SPL)

```spl
index=auth action=success
| iplocation src_ip
| stats earliest(_time) as t1, latest(_time) as t2
        values(Country) as countries
        by user, src_ip
| eventstats dc(countries) as country_count by user
| where country_count > 1 AND (t2 - t1) <= 300
```

### Sentinel (KQL)

```kusto
let window=5m;
let logins =
SigninLogs
| where TimeGenerated > ago(window) and ResultType == 0
| project UserPrincipalName, IPAddress, TimeGenerated
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion);
logins
| summarize make_set(Country), min(TimeGenerated), max(TimeGenerated) by UserPrincipalName
| where array_length(set_Country) > 1 and (max_TimeGenerated - min_TimeGenerated) < 5m
```

---

# 3) Kill chain réseau (Scan → Bruteforce → Accès critique) — 2h

### 🧠 Idée

Même IP source : d’abord **scan** (IDS), puis **échecs de login massifs** (AD/LDAP), puis **tentative d’accès** à un serveur sensible (Firewall). Corrélation multi-sources.

### Splunk (SPL)

```spl
( index=ids tag=scan ) OR
( index=winsec EventCode=4625 ) OR
( index=firewall action=allowed dst=10.0.10.50 )   /* serveur critique */
| eval phase=case(
    index="ids","recon",
    index="winsec" AND EventCode=4625,"bruteforce",
    index="firewall","targeting",
    true(),"other")
| stats
    min(_time) as first_seen max(_time) as last_seen
    values(phase) as phases
    count(eval(phase="bruteforce")) as bf_count
  by src_ip
| where mvfind(phases,"recon")>=0
  AND bf_count >= 20
  AND mvfind(phases,"targeting")>=0
  AND last_seen - first_seen <= 7200
```

### QRadar (AQL) — vue simple

```sql
/* 2h window */
SELECT sourceIP
FROM events
WHERE startTime > NOW() - 2 HOURS
GROUP BY sourceIP
HAVING
  SUM(CASE WHEN category='Network Scan' THEN 1 ELSE 0 END) > 0
  AND SUM(CASE WHEN eventName='Logon Failure' THEN 1 ELSE 0 END) >= 20
  AND SUM(CASE WHEN destinationHost='core-banking' AND action='Allowed' THEN 1 ELSE 0 END) > 0;
```

---

# 4) Exfiltration suspecte (DLP + Proxy/Firewall) — 30 min

### 🧠 Idée

Un poste envoie >2 Go vers un domaine non approuvé ET DLP voit des patterns sensibles.

### Splunk (SPL)

```spl
index=proxy OR index=dlp
| eval bytes = coalesce(bytes_out,bytes,0)
| eval signal = case(index="proxy","net", index="dlp","dlp", true(),"other")
| bin _time span=5m
| stats sum(eval(signal="net", bytes)) as out_bytes
        max(eval(signal="dlp", severity)) as dlp_sev
  by src_ip, user, dstdomain, _time
| where out_bytes >= 2000000000 AND dlp_sev >= 3
```

### Sentinel (KQL)

```kusto
let window=30m;
let net = ProxyLogs
| where TimeGenerated > ago(window)
| summarize out_bytes=sum(SentBytes) by SrcIpAddr, User, DestinationHost;
let dlp = DlpAlerts
| where TimeGenerated > ago(window)
| summarize max_sev=max(Severity) by SrcIpAddr, User;
net
| where out_bytes > 2g
| join kind=inner dlp on SrcIpAddr, User
| where max_sev >= 3
```

---

# 5) EDR : Processus à haut risque + C2 bloqué par IPS — 15 min

### Splunk (SPL)

```spl
( index=edr rule="suspicious_process" )
OR ( index=ips action="blocked" threat="C2" )
| stats values(host) as hosts
        earliest(_time) as first_seen latest(_time) as last_seen
  by src_ip
| where mvcount(hosts) >= 1 AND (last_seen - first_seen) <= 900
```

---

## Conseils pratiques (quel que soit le SIEM)

* **Fenêtres temporelles** : commence par des fenêtres modestes (5–15 min), élargis si besoin.
* **Seuils** : évite les chiffres absolus trop bas (source de faux positifs). Ajuste par **utilisateur/segment/heure**.
* **Enrichissement** : ajoute **GeoIP**, **Threat Intel**, **CMDB (criticité des actifs)**, **listes d’applications autorisées**.
* **Suppression de bruit** : agrège par **src\_ip/user** et déduplique.
* **Sortie** : envoie l’alerte au **SOAR** avec un **contexte complet** (logs bruts, timeline, host, user, IOC) pour l’automatisation.

Si tu me dis quel SIEM tu utilises (Splunk, QRadar, Sentinel, Elastic), je te fournis la **syntaxe finale prête à coller** avec les bons noms d’index/sources de ton contexte.
