# 🚀 KerberosScanner


**WinToolsSuite – Security Tools for Network & Pentest**
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training

---

## 📋 Description

**KerberosScanner** surveille le journal d'événements de sécurité Windows en temps réel pour détecter et analyser les événements Kerberos (Event IDs 4768, 4769, 4771). L'outil agrège les requêtes par SPN (Service Principal Name) sur une fenêtre glissante configurable et détecte les pics anormaux pouvant indiquer des attaques type Kerberoasting ou autres anomalies Kerberos.

### Fonctionnalités principales

- **Surveillance temps réel** : subscription aux événements Security log via Windows Event Log API
- **Agrégation par SPN** : comptage et suivi des requêtes par service
- **Détection d'anomalies** : scoring basé sur volume de requêtes
- **Fenêtre glissante** : analyse sur période configurable (défaut 5 minutes)
- **Export CSV** : export des statistiques pour analyse ultérieure
- **Logging** : historique complet dans `%TEMP%\WinTools_KerberosScanner_log.txt`

- --


## 📌 Prérequis

- Windows 10 / Windows Server 2016+ (x64)
- Visual Studio 2017+ avec outils C++
- **Droits administrateur** : requis pour accès au journal Security

- --


## Compilation

Ouvrez **x64 Native Tools Command Prompt for VS** :

```bat
cd WinToolsSuite\KerberosScanner
go.bat
```

L'exécutable `KerberosScanner.exe` sera créé dans le même répertoire.

- --


# 🚀 Lister SPNs du domaine

# 🚀 Vérifier événements Kerberos

## 🚀 Utilisation

1. **Lancer l'outil** : exécuter `KerberosScanner.exe` **en tant qu'administrateur**
2. **Démarrer surveillance** : cliquer sur "Démarrer surveillance"
3. **Observer résultats** : le ListView affiche les SPNs avec statistiques en temps réel
4. **Exporter** : bouton "Exporter CSV" ou menu Fichier → Exporter CSV

### Interface

- **ListView** : colonnes SPN | Compteur | Dernière vue | Top IPs | Score
- **Boutons** :
  - Démarrer surveillance : lance la surveillance événements
  - Arrêter surveillance : stoppe la surveillance
  - Exporter CSV : sauvegarde résultats
  - Effacer : vide les statistiques actuelles

- --


## Événements surveillés

| Event ID | Description |
|----------|-------------|
| 4768 | TGT (Ticket Granting Ticket) demandé |
| 4769 | Service ticket demandé |
| 4771 | Échec pré-authentification Kerberos |

- --


## Détection d'anomalies

L'outil calcule un **score** pour chaque SPN :

- **Score 1** : activité normale (< 50 requêtes)
- **Score 2** : activité élevée (50-100 requêtes)
- **Score 3** : activité suspecte (> 100 requêtes)

Les scores élevés peuvent indiquer :
- Kerberoasting (extraction de tickets services pour cracking offline)
- Énumération SPN
- Activité automatisée anormale

- --


## Environnement LAB-CONTROLLED

### Configuration de test

1. **Active Directory de test** : déployer un DC Windows Server
2. **Comptes de service** : créer des comptes avec SPNs
3. **Génération trafic** : utiliser `setspn` pour lister SPNs, ou outils comme `Rubeus` en mode audit
4. **Surveillance** : lancer KerberosScanner sur le DC ou workstation jointe au domaine

### Étapes manuelles (VM isolée)

```powershell
setspn -Q */*

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768,4769,4771} -MaxEvents 10
```

**Note** : ne pas utiliser d'outils d'extraction de tickets en production sans autorisation.

- --


## Logs

Fichier : `%TEMP%\WinTools_KerberosScanner_log.txt`

Contenu :
- Horodatages démarrage/arrêt
- Erreurs de subscription
- Exports CSV

- --


## Limitations

- Requiert droits administrateur
- Extraction IP depuis événements : implémentation simplifiée (TODO amélioration parsing XML)
- Fenêtre glissante : actuellement fixée à 5 minutes (TODO configuration UI)

- --


## 🔒 Sécurité & Éthique

⚠️ **Audit uniquement** : cet outil est conçu pour la surveillance défensive et l'audit autorisé.

- Ne pas utiliser sur systèmes de production sans autorisation
- Respecter politiques de sécurité organisationnelles
- Les données peuvent contenir informations sensibles (noms utilisateurs, SPNs)

- --


## Support

**Ayi NEDJIMI Consultants**
Expert en Cybersécurité
https://www.ayinedjimi-consultants.fr

Pour formations ou missions d'audit Kerberos, contactez-nous.

- --


## 📄 Licence

MIT License - Voir fichier `LICENSE.txt` à la racine du dépôt.


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>