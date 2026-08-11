# To show the L2 — What this project is about (in plain terms)

## The problem we want to solve
Today you deploy the PSMs **by hand**, step by step. It takes a long time, there are
several reboots, and a small mistake (wrong zone, skipped step, replayed step)
can be costly. We want to **tool up your procedure**, not replace it with a black box.

## The idea: an "idempotent" script (like Ansible)
"Idempotent" simply means: **it can be rerun as many times as you want,
it only redoes what is missing**. For each phase, the script does two things:

1. **TEST**: "is this already done / already compliant?"
2. **SET**: if not → it applies it. If yes → it touches nothing.

At the end, it displays a summary like:
```
Role RD Session Host .............. OK        (already there)
RDS license ....................... CHANGED   (applied)
PSM installation .................. OK
Vault registration ................ CHANGED
Hardening ......................... OK
```
`OK` = nothing changed, `CHANGED` = applied, `FAILED` = failure (and it stops there).

## How we keep control (blunder-proofing)
- **"Plan" mode (`-WhatIf`)**: dry run, it **says what it would do** without changing anything.
- **Zone confirmation**: before acting, it displays the targeted datacenter and PVWA,
  and **asks for YES** — to avoid running against the wrong DC.
- **Confirmation before Vault registration** (the sensitive step).
- **Fail-fast**: at the first error, it **stops**; you fix, you rerun, it **resumes where it left off**.

## What the script does, in order (modeled on your procedure)
1. **Pre-flight**: checks admin rights, the zone, Vault/PVWA access.
2. **Prerequisites**: local RDS license (the RDS role itself is set up by the CyberArk auto-install).
3. **Additional software**: installs the clients/tools (driven by a config file + a folder of exe files).
4. **PSM installation**: launches the CyberArk automated installation (your command).
5. **Vault registration**: registration automation + the XML files, **after confirmation**.
6. **Hardening**: your customized PSMHardening + the in-house AppLocker policy.
7. **Validation**: checks that the PSM services are running.
8. **Reboots**: handled automatically, with **automatic resume** after restart.

## Where the passwords come from (security)
- **The admin performing the installation authenticates themselves to the PVWA** (they
  already have access to all CyberArk accounts). The script then retrieves, **on the fly via
  the PVWA REST API**, the password of the Vault install/admin account it needs —
  **never hard-coded, never in the logs** (masked automatically).
- **No CCP/AIM**: nothing to provision (no AppID, no application certificate). The
  admin's session is what authorizes the retrieval.
- The **PSMConnect/PSMAdminConnect** passwords are **not** entered: the PSM service
  retrieves them on its own at runtime (via the PSMConnect Safe), just like today.

## What we do NOT change
- The **way** CyberArk installs (we use **your** CyberArk commands/scripts).
- The **Load Balancer** (handled ahead of time, outside the script).
- The **antivirus/EDR** (handled by the OS admins).
- The **content** of your hardening and your AppLocker: we **embed your files** and
  apply them — you stay in control.

## What we need from you (the L2)
Above all: **the real files** and **how to detect that a step is already done**.
The precise list is in `Inspection-PSM-modele.md` (to run on the model PSM) and in
the checklist at the end of `Synthese-reponses.md`.
