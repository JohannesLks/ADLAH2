# Roles Directory

Each role in the Ansible project lives in its own subdirectory.

Example structure:

roles/
  example_role/
    tasks/main.yml
    handlers/main.yml
    files/
    templates/
    vars/main.yml
    defaults/main.yml
    meta/main.yml

Guidelines:
* Put only portable, reproducible artifacts here (no secrets, no generated certs).
* Use `defaults/` for overridable values, `vars/` for rarely overridden constants.
* Prefer templates over static files when they contain variable content.
