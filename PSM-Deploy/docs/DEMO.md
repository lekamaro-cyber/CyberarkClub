# Running a demo (without media or real values)

You haven't put anything in the folder yet (no CyberArk media, no values):
that's **normal**, and you can still demonstrate **what has value** — the
idempotent engine and the guardrails — thanks to the **demo mode** (`demo/Demo-PSM.ps1`).

> ✅ No heavy prerequisites: **no need** for the CyberArk media, **nor** admin
> rights, **nor** network access. Just **Windows PowerShell 5.1** (present on every
> Windows) on any machine (your workstation, a VM…).

## What the demo proves
- **Real idempotence**: 1st run = everything `CHANGED`, 2nd run = everything `OK`
  (the engine re-reads a persistent state, it replays nothing).
- **"Plan" mode (`-WhatIf`)**: shows what *would* be done, **without changing anything**.
- **Zone confirmation**: the blunder-proofing before acting.
- **Secret masking**: a logged password appears as `********`.
- **Final summary** Ansible-style (OK / CHANGED / FAILED).
- **Reboot point**: where the real script would restart and resume.

## Suggested walkthrough for the meeting (3 minutes)

Open PowerShell in the `PSM-Deploy` folder, then:

### 1) "Plan" mode — nothing is touched
```powershell
.\demo\Demo-PSM.ps1 -Reset -NonInteractive -WhatIf
```
➡️ Everything comes out as `WHATIF`: "here is what I would do". No modification.

### 2) First real run — simulated installation
```powershell
.\demo\Demo-PSM.ps1 -Reset -NonInteractive
```
➡️ Everything comes out as `CHANGED`. Note the simulated **reboot** message.

### 3) Second run — THE idempotence demonstration
```powershell
.\demo\Demo-PSM.ps1 -NonInteractive
```
➡️ Everything comes out as `OK`: **nothing is redone**. This is the heart of the matter.

### 4) (optional) Interactive zone confirmation
```powershell
.\demo\Demo-PSM.ps1 -Reset        # without -NonInteractive: it asks you to type YES
```
➡️ Shows the "wrong zone = wrong Vault" guardrail.

## Also show the automated tests (optional)
If Pester is available:
```powershell
Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
```
➡️ Verifies the **idempotence contract** (2nd run = OK) and the structure.

## The message to give the L2
> "The real script (`Deploy-PSM.ps1`) works **exactly the same way**: same phases,
> same summary, same security. The only difference is that instead of *simulated*
> steps, it will run **your** CyberArk commands and **your** files. The demo
> shows the **mechanics**; the meeting is for gathering the **real content**
> (commands, XML, per-DC values)."

## Cleanup
The demo artifacts live in `demo/.demo-state` and `demo/.demo-logs`
(ignored by git). To start from scratch: `-Reset`, or delete those folders.
