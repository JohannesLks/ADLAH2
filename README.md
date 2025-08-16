# ADLAH
Adaptive Deep Learning Anomaly Detection Honeynet (ADLAH) 

## TL;DR
1. customize `reinstall.sh`
2. `reinstall.sh`

## Ansible Deployment (Beta)

Struktur unter `ansible/`:

```
ansible/
	main.yml
	hosts.example.ini
	hosts.ini
	group_vars/
		all.yml
	roles/
		hive/         
		sensor/        
		cluster/
	requirements.yml
```

### Best Practices (Open Source & Secrets)

- Checke NIEMALS echte IPs von internen Netzen, private Keys oder Passwörter ein.
- Verwende `hosts.example.ini` als Vorlage und füge `ansible/hosts.ini` zur `.gitignore` hinzu.
- Sensible Variablen (Passwörter, API Keys) verschlüsselst du mit `ansible-vault` oder legst sie als Runtime-Variablen/CI-Secret bereit.
- Generierte Dateien wie `.env`, Zertifikate, `htpasswd`, sollten nicht in Git – füge sie zur `.gitignore`.
- Nutze Platzhalter (`ChangeMe`, Dummy-IPs 10.0.0.0/24) für Dokumentation.

### Secrets mit Ansible Vault

Beispiel: `ansible-vault create ansible/group_vars/hive/vault.yml`

Inhalt (verschlüsselt):
```
vault_kibana_password: SuperSecret123!
```

Dann in `roles/hive/vars/main.yml` referenzieren:
```
kibana_password: "{{ vault_kibana_password | default('ChangeMe123!') }}"
```

Playbook ausführen mit Passwort-Prompt oder Vault-File:
```
ansible-playbook -i ansible/hosts.ini ansible/main.yml --ask-vault-pass --tags hive
```

### Inventory & Bastion

ProxyJump Beispiel:
```
[bastion]
bastion1 ansible_host=x.x.x.x ansible_user=adlah

[hive]
hive1 ansible_host=10.0.0.10 ansible_user=adlah

[all:vars]
ansible_ssh_common_args='-o ProxyJump=bastion1'
```

### Collections installieren
```
ansible-galaxy collection install -r ansible/requirements.yml
```

### Testlauf (nur Ping)
```
ansible -i ansible/hosts.ini hive -m ping
```

### Deployment nur Hive
```
ansible-playbook -i ansible/hosts.ini ansible/main.yml --tags hive
```

### Nächste Schritte
- Cluster-Rolle ausbauen (K8s + MetalLB + Redis)
- CI Workflow (Lint + ansible-lint + Molecule Tests) hinzufügen
- Dokumentation für Rückbau / Updates


