# 🧠 Karton Intelligence Pipeline

## 🎯 Objectif

Ce projet permet l'intégration complète de **CAPEv2 Sandbox** et **CAPA** dans une pipeline de threat intelligence.

Il transforme automatiquement un échantillon malware en :

- analyse dynamique CAPEv2
- analyse des capacités 
- extraction IOCs / TTPs / MBCs / signatures / payloads / config / processtree
- Rapport enrichie vers MWDB
- rapport consolidé exploitable par un analyste.

---

## 🧩 Position dans la pipeline

```text
MWDB Core "submit sample"
        ↓
KartonCAPEv2 plugin
        ↓
CAPEv2 Sandbox execution
        ↓
Extraction intelligence (IOC / TTP / behavior)
        ↓
Consolidated CTI report
        ↓
Karton "analyzed sample"
        ↓
SOC / CTI / MWDB / SIEM
```

---

## ⚙️ Composant principal

### 🧠 KartonCapev2

Service Karton responsable de :

- sélection des fichiers analysables
- soumission CAPE API avec le choix du guest intélligent 
- polling de l’analyse
- récupération du rapport complet
- extraction intelligence
- génération rapport consolidé
- émission d’un task Karton enrichi

---

### 🧠 KartonFlareCapa
Service Karton responsable de :

- sélection des fichiers analysables
- soumission CAPE API avec le choix du guest intélligent 
- polling de l’analyse
- récupération du rapport complet
- extraction intelligence
- génération rapport consolidé
- émission d’un task Karton enrichi

---


### 🧠 KartonStrings
Service Karton responsable de :

- Extraire les chaine de caractére via le binaire strings
- Rapport MWDB complet
---

## 🔁 Flux de traitement

### 1. Filtrage initial

- type: sample
- stage: recognized
- taille fichier (100B → 200MB)
- extension supportée
- heuristique exécutable

---

### 2. Soumission CAPE

**Endpoint :**

```
POST /apiv2/tasks/create/file/
```

Options :

- screenshots
- procmon
- CAPE extraction
- behavioral analysis
- config extraction

Auto package :

- doc / pdf / archive / script / exe

---

### 3. Suivi d’exécution

```
GET /apiv2/tasks/view/{task_id}/
```

États :

- reported → success
- failure, timeout, failed_* → error
- timeout global (30 min)

---

### 4. Récupération rapport

```
GET /apiv2/tasks/get/report/{task_id}/
```

---

## 🧠 Intelligence extraite

### 📡 IOC (Indicators of Compromise)

- domains
- IPs
- URLs
- network flows
- mutexes
- registry keys
- files
- processes

Relations :

- domain ↔ IP
- IP ↔ URL
- process ↔ file/registry
- flow ↔ destination IP

---

### 🧬 TTP (MITRE / MBC)

- ATT&CK TTP IDs
- MBC mappings
- CAPE signatures

---

### 🚨 Signatures comportementales

| Score CAPE | Severity |
|------------|----------|
| 0 | Informational |
| 1 | Low |
| 2 | Medium |
| 3 | High |

---

### 📦 Payloads & configs

- CAPE payloads
- dropped files
- configs
- YARA matches
- hashes (MD5 / SHA1 / SHA256)

---

### 🌳 Process tree

- arbre hiérarchique
- vue flatten (cmdline, user, path)

---

## 🧾 Rapport consolidé

```json
{
  "analysis_metadata": {},
  "sample_information": {},
  "threat_assessment": {},
  "summary": {}
}
```

---

## 🏷️ Tags Karton

- karton:capeV2
- karton:capeV2:iocs
- karton:capeV2:signatures
- karton:capeV2:ttps
- karton:capeV2:payloads
- karton:capeV2:processtree
- cape:id:{task_id}
- karton:capeV2:threat:*

---

## 📤 Output Karton

```python
Task(
    type="sample",
    stage="analyzed",
    payload={
        parent: sample,
        sample: consolidated_report,
        attributes: CTI_data,
        comments: [
            CAPE link,
            VirusTotal link
        ],
        tags: [...]
    }
)
```

---

## ⚙️ Configuration

```ini
[cape]
api_url = http://cape-web:8000
api_token = ""
poll_interval = 30
max_wait_time = 1800
timeout = 300
package = exe
screenshots = true
procmon = true
```

---

## 🧪 Cas d’usage

- SOC automation
- malware triage
- CTI enrichment
- SIEM IOC ingestion
- Purple Team analysis

---

## 🚨 Gestion d’erreurs

En cas d’échec :

- report d’erreur structuré
- task Karton stage: analyzed
- traçabilité complète

---

## 🔐 Résultat final

👉 CAPE devient un moteur CTI automatisé intégré à Karton
