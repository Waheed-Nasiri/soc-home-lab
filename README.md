# 🛡️ SOC Home Lab — Détection, Threat Hunting & Réponse à Incident

Laboratoire personnel de cybersécurité défensive, monté de zéro pour démontrer des compétences
concrètes de **SOC Analyst** : construction de règles de détection, threat hunting, orchestration
SOAR et analyse post-compromission.

Chaque projet suit la même logique : **jouer l'attaque → la détecter → construire la règle →
l'industrialiser**, avec un mapping systématique sur **MITRE ATT&CK**.

---

## Architecture du lab

Environnement isolé sous VirtualBox (réseau interne, aucune exposition externe).

| Machine | Rôle | OS |
|---------|------|----|
| `WIN-DC` | Contrôleur de domaine Active Directory (`esdown.local`) | Windows Server |
| `W10-1` | Poste client joint au domaine (endpoint surveillé) | Windows 10 |
| `SPLUNK` | SIEM — collecte et détection | Ubuntu Server |
| `SHUFFLE` | SOAR — orchestration et réponse automatisée | Ubuntu Server |
| `KALI` | Machine attaquante | Kali Linux |

**Collecte :** Splunk Universal Forwarder + Sysmon sur les machines Windows, remontant les
journaux Security / System / Sysmon vers un index dédié.

---

## 📂 Projets

| # | Projet | Techniques MITRE | Compétences clés |
|---|--------|------------------|------------------|
| 01 | [Détection de Kerberoasting](./01-kerberoasting-detection/) | T1558.003 | Détection AD, SPL, tuning, Sigma |
| 02 | [Orchestration SOAR (Shuffle)](./02-soar-shuffle/) | — | Playbook, webhook, enrichissement, réponse |
| 03 | [Threat Hunting](./03-threat-hunting/) | T1087, T1110, T1053 | Chasse par hypothèse, analyse de fréquence |
| 04 | [Détection sur poste client](./04-endpoint-detection/) | T1059, T1033, T1547 | Sysmon, chaîne parent-enfant, EDR |
| 05 | [Détection de Ransomware](./05-ransomware-detection/) | T1486 | Détection comportementale, config Sysmon, Sigma |

---

## 🛠️ Stack technique

**SIEM / Détection :** Splunk Enterprise · SPL · Sysmon
**SOAR :** Shuffle (Docker)
**Offensif (pour générer les attaques) :** Impacket · CrackMapExec · John the Ripper
**Framework :** MITRE ATT&CK · Sigma (Detection-as-Code)
**Analyse / Forensic :** REMnux · Tsurugi

---

## Compétences démontrées

- Création et **tuning** de règles de détection (réduction des faux positifs)
- Maîtrise du langage de requête **SPL** et du format **Sigma**
- Conception de **use cases SOC** de bout en bout
- **Threat hunting** et transformation des résultats en détections
- Orchestration **SOAR** : playbooks, enrichissement, réponse automatisée
- Mapping **MITRE ATT&CK**
- Connaissance des sources de logs : **AD, endpoint, Sysmon**

---

## 👤 Auteur

**Waheed Nasiri** — en route vers l'analyse SOC / réponse à incident.
Profil réseau & sécurité (FortiGate, Cisco, SD-WAN) en reconversion vers la cyberdéfense.

