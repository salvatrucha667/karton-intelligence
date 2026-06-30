# 🧠 Karton Intelligence Pipeline

## 🎯 Objectif

Karton Intelligence Pipeline est une chaîne d'orchestration d'analyse de
malwares basée sur **Karton**, **MWDB**, **CAPEv2** et **CAPA**.

L'objectif est d'automatiser l'enrichissement d'échantillons déposés
dans MWDB en exécutant plusieurs analyseurs spécialisés, puis de
réinjecter les résultats dans MWDB afin de centraliser l'ensemble des
informations utiles aux analystes SOC, CTI et pour un analyste CSIRT.

Le pipeline permet notamment :

-   la récupération automatique des échantillons depuis MWDB ;
-   l'envoie de l'échatillions vers une instance CAPEv2 pour l'analyse dynamique ;
-   l'analyse statique via CAPA ;
-   l'extraction de chaînes de caractères ;
-   l'extraction d'IOCs, TTPs, MBCs, signatures et artefacts ;
-   l'enrichissement des objets MWDB ;

L'instance CAPEv2 n'est pas intégrer au projet

------------------------------------------------------------------------

# 🏗️ Architecture

Le pipeline repose sur une architecture **event-driven** utilisant
Karton.

Composants :

-   MWDB
-   Karton
-   CAPA
-   Strings
-   CAPEv2 --> instance externe non implementer sur le projet

------------------------------------------------------------------------

# 🧩 Pipeline d'intelligence

``` text
                           +----------------+
                           | Submit Sample  |
                           +-------+--------+
                                   |
                                   v
                           +----------------+
                           |   MWDB Core    |
                           +-------+--------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
          v                        v                        v
 +----------------+       +----------------+       +----------------+
 | Karton-CAPEv2  |       | Karton-CAPA    |       | Karton-Strings |
 +-------+--------+       +-------+--------+       +-------+--------+
         |                        |                        |
         |                        |                        |
         |              Execute CAPA binary       Extract strings
         |                        |                        |
         |                        |                        |
         |                +-------v--------+       +-------v--------+
         |                |     Error ?    |       |     Error ?    |
         |                +-------+--------+       +-------+--------+
         |                        |                        |
         |                        |                        |
         |               +--------v---------+      +-------v--------+
         |               |  MWDB Reporter   |      | MWDB  Reporter |
         |               +--------+---------+      +----------------+
         |                                               
         |                                               
         |                
         |
         v
 +----------------------+
 | Linux or Windows ?   |
 +----------+-----------+
            |
      +-----+-----+
      |           |
      v           v
  Guest Linux  Guest Windows
      \           /
       \         /
        v       v
 +----------------------+
 | CAPEv2 Sandbox       |
 +----------+-----------+
            |
            v
 +----------------------+
 | Wait for completion  |
 +----------+-----------+
            |
            v
 +----------------------+
 | Extract report data  |
 | - IOCs               |
 | - TTPs               |
 | - Process tree       |
 | - Signatures         |
 +----------+-----------+
            |
            v
 +----------------------+
 | Consolidated Report  |
 +----------+-----------+
            |
            v
 +----------------------+
 | Tags / Comments /    |
 | Attributes           |
 +----------+-----------+
            |
            v
 +----------------------+
 | MWDB Reporter        |
 +----------+-----------+
```

------------------------------------------------------------------------

# 🔄 Modèle d'événements

    Sample
       │
       ▼
    MWDB
       │
       ▼
    Task Karton
       │
       ├── karton-capev2
       ├── karton-capa
       └── karton-strings
              │
              ▼
    Enrichissement
              │
              ▼
    MWDB

------------------------------------------------------------------------

# ⚙️ Composants

## Karton-CAPEv2

Responsable de :

-   sélection des fichiers analysables ;
-   choix automatique du guest Linux ou Windows ;
-   soumission à l'API CAPEv2 ;
-   suivi de l'analyse ;
-   récupération du rapport ;
-   extraction des IOCs ;
-   extraction des TTPs ;
-   extraction des signatures ;
-   génération du rapport consolidé ;
-   enrichissement de MWDB.

## Karton-CAPA

-   exécution de CAPA ;
-   récupération des capacités ;
-   mapping MITRE ATT&CK ;
-   enrichissement MWDB.

## Karton-Strings

-   extraction des chaînes ;
-   génération du rapport ;
-   enrichissement MWDB.

------------------------------------------------------------------------

# 🔁 Flux de traitement

## 1. Filtrage

-   type : sample
-   stage : recognized
-   taille : 100 B → 200 MB
-   extension supportée
-   heuristique exécutable

## 2. Analyse CAPE

POST `/apiv2/tasks/create/file/`

Options :

-   screenshots
-   Procmon
-   behavioral analysis
-   config extraction
-   payload extraction

## 3. Polling

GET `/apiv2/tasks/view/{task_id}/`

États :

-   reported
-   running
-   failed
-   timeout

## 4. Rapport

GET `/apiv2/tasks/get/report/{task_id}/`

------------------------------------------------------------------------

# 🧠 Intelligence extraite

## IOC

-   Domains
-   IPs
-   URLs
-   DNS
-   HTTP
-   Mutex
-   Registry
-   Files
-   Processes

Relations :

-   Domain ↔ IP
-   IP ↔ URL
-   Process ↔ Registry
-   Process ↔ File

## MITRE ATT&CK

-   Techniques
-   Tactiques

## Malware Behavior Catalog

-   MBC mappings

## Signatures CAPE

-   comportement
-   score
-   sévérité

## Payloads

-   dropped files
-   payloads
-   configurations
-   YARA
-   hashes

## Process Tree

-   vue hiérarchique
-   vue aplatie

------------------------------------------------------------------------

# 🧠 Modèle de données enrichi

Chaque analyse produit :

-   métadonnées
-   IOCs
-   TTPs
-   MBC
-   Signatures
-   Process Tree
-   Relations
-   Hashes
-   Configurations

------------------------------------------------------------------------

# 🧾 Rapport consolidé

``` json
{
  "analysis_metadata": {},
  "sample_information": {},
  "iocs": {},
  "ttps": {},
  "mbc": {},
  "process_tree": {},
  "payloads": {},
  "summary": {}
}
```

------------------------------------------------------------------------

# 🏷️ Tags MWDB

-   karton:capev2
-   karton:capev2:iocs
-   karton:capev2:payloads
-   karton:capev2:ttps
-   karton:capev2:signatures
-   karton:capev2:processtree
-   cape:id:{task_id}

------------------------------------------------------------------------

# 📊 Observabilité

-   logs des workers
-   suivi des tâches
-   corrélation par task_id
-   gestion des erreurs
-   reporting des statuts

------------------------------------------------------------------------

# 🔐 Sécurité

-   exécution en sandbox isolée ;
-   aucun exécutable lancé sur l'hôte de l'analyste, tout est fait via les guest CAPEv2 ;
-   timeout configurable.

------------------------------------------------------------------------

# ⚠️ Limitations

-   dépend de la disponibilité des guests CAPEv2 ;
-   certains packers limitent CAPA ;
-   certaines chaînes peuvent être bruitées ;
-   les analyses sandbox sont limitées par le timeout (30 minutes).

------------------------------------------------------------------------

# 🧪 Cas d'usage

-   SOC Automation
-   CTI
-   Malware Triage
-   Purple Team
-   Threat Hunting
-   IOC Enrichment
-   Importation OpenCTI pour l'enrichissement de la plateforme

------------------------------------------------------------------------

# 🚀 Roadmap

-   [ ] VirusTotal
-   [ ] YARA automatique
-   [ ] ClamAV
-   [ ] Suricata
-   [ ] Sigma
-   [ ] Sandbox Linux avancée
-   [ ] Export STIX 2.1
-   [ ] Dashboard Grafana pour le monitoring des service Karton

------------------------------------------------------------------------

# 🤝 Contribution

Les contributions sont les bienvenues via Pull Request.

------------------------------------------------------------------------

# 📄 Licence

À définir.