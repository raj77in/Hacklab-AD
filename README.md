````markdown
# Hacklab-AD

Vulnerable Active Directory Lab Setup for Windows Server 2025

**Hacklab-AD** is a PowerShell-based automation script designed to help you quickly spin up a fully functional and intentionally vulnerable Active Directory (AD) environment for security testing, red teaming, and training.

This lab is tailored for Windows Server 2025 and aims to simulate real-world misconfigurations and attack scenarios seen in enterprise AD environments.

## Features

* Configure IP, DNS, and hostname settings automatically
* Promote the server to a Domain Controller with a preset domain
* Inject a variety of AD vulnerabilities commonly abused in attacks
* Modular functions so you can pick and run what you want

## How to Use


After copying the script to your Windows Server 2025 machine as `setup.ps1`,
Open the script and modify the parameters at the top of script as per your
requirement.

Open PowerShell as administrator and run the following:

```powershell
.\setup.ps1
```

## Requirements

* Windows Server 2025 (Desktop or Core)
* PowerShell 5.1 or higher
* ActiveDirectory module installed
* Must be run as administrator

## Intended Use

This project is intended for offline use in labs, training environments, or CTF-style simulations. It's meant to help defenders and attackers alike understand and test AD attacks in a safe space. ONLY to be used for **educational purposes**.

