
# Windows Forensic Artefact Parser Project : Configure DFIR-ORC

This guide provides step-by-step instructions on how to configure the DFIR-ORC collection tool for a streamlined and effective forensic investigation. It focuses on a configuration designed for speed and comprehensive artifact collection into a single archive

### 📌  Key Links

* **Documentation:** [Installation Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_install.md) | [Usage Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_use.md) | [Results Architecture](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/Explaining_the_results.md)
* **WAPP Repository:** [Available here](https://github.com/youhgo/WFAPP)
---

I've made a ready to go DFIR-ORC Binary available [DFIR-ORC](https://github.com/youhgo/WFAPP/tree/master/api/ressources) collector. 
 if you do not want to bother with thoses steps.

## What is ORC ?

DFIR-ORC (Outil de Recherche de Compromission), created by the ANSSI (French national authority for cyberdefence), is a powerful collection tool. It is designed to reliably parse and collect critical artifacts such as the MFT, registry hives, and event logs from a target machine.

While DFIR-ORC offers extensive configuration options, the default settings can be time-consuming, often taking an hour or more to complete. My custom configuration focuses on speed and efficiency, collecting all necessary artifacts for a complete investigation in approximately 5 minutes and creating a single, easy-to-manage archive.


## Prerequisite:

To configure DFIR-ORC, you will need a Windows machine and the following tools:

1. **DFIR-ORC Binaries**: Download the latest release from the [DFIR-ORC GitHub releases page](https://github.com/DFIR-ORC/dfir-orc/releases). Be sure to download both:

   * `DFIR-Orc_x64.exe`
   * `DFIR-Orc_x86.exe`

2. **Sysinternals Suite**: Download the following individual tools from the [Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/downloads/):
   * `handle.exe`
   * `Tcpvcon.exe`
   * `PsService.exe`
   * `Listdlls.exe`
   * `autorunsc.exe`

3. **DFIR-ORC Config Repository**: Download and extract the latest version of the [DFIR-ORC Config repo](https://github.com/DFIR-ORC/dfir-orc-config).

## Configuration Steps

Navigate to the `dfir-orc-config-master/` directory you just downloaded. It should contain the following structure:

```bash
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        28/03/2024     11:12                config
d-----        16/08/2024     11:35                output
d-----        06/06/2024     12:44                tools
------        28/03/2024     11:12             56 .gitattributes
------        28/03/2024     11:12             19 .gitignore
------        28/03/2024     11:12            695 Configure.cmd
------        28/03/2024     11:12           6665 configure.ps1
------        28/03/2024     11:12           8104 LICENSE-OUVERTE.md
------        28/03/2024     11:12           6796 open-licence.md
------        28/03/2024     11:12           3347 README.md
```

### Step 1: Place Tools in the `tools` Directory

Copy all the `Sysinternals` and `DFIR-ORC` binaries you downloaded into the `tools/` subdirectory.
After copying, the `tools/` directory should look like this:

```bash
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        06/02/2024     18:49         718272 autorunsc.exe
-a----        06/06/2024     09:46        7252480 DFIR-Orc_x64.exe
-a----        06/06/2024     09:49        5507584 DFIR-Orc_x86.exe
-a----        26/10/2022     18:50         761240 handle.exe
-a----        27/05/2016     12:30         424096 Listdlls.exe
-a----        30/03/2023     16:58         268168 PsService.exe
-a----        11/04/2023     18:10         202632 tcpvcon.exe
```

### Step 2: Configure Embedded Tools

Navigate to the `config/` directory and edit the `DFIR-ORC_embed.xml` file.
Remove the following lines to prevent the tool from embedding memory dump tools, which are not needed for our configuration.

```xml
<file name="dumpit" path=".\tools\DumpIt.exe" />
<file name="winpmem" path=".\tools\winpmem.exe" />
```

Those line indicate to ORC-CONFIG to embed the tools "DumpIt" and "Winpmem" into the ORC binary. Since we don't wanna do a ram memory dump, we don't need this tools.
If you still want to do a memory dump, keep those two lines.
you will need to download DumpIt.exe and winpmem.exe and place them in the `tools` directory.

> A pre-configured `DFIR-ORC_embed.xml` file is available [here](https://github.com/youhgo/DOPP/blob/master/ressources/DFIR-ORC_embed.xml).

### Step 3: General Configuration

We will be using my [configuration](https://github.com/youhgo/WFAPP/blob/master/api/ressources/DFIR-ORC_config.xml)
 which is optimized for speed and comprehensive artifact collection, creating a single archive for easy retrieval.

In the  `config/` directory, replace the default `DFIR-ORC_config.xml` file with the one provided.

Note :
You are free to configure DFIR-ORC to gather artefacts the way you want. ANSSI provide a [tutorial](https://dfir-orc.github.io/configuration.html)

Keep in mind that with the default config, ORC will be verry slow, the process can last sometime 2/3 hours and more.
Moreover the result are stored in multiples archives making the retrieval and parsing process more complex.


### Step 4: Run the Configuration Script

Return to the root `dfir-orc-config-master/` directory. Open PowerShell as an administrator and execute the configuration script.
```PowerShell
.\configure.ps1
```

Once the script completes, a fully configured and ready-to-use `DFIR-Orc.exe` binary will be available in the `output/` directory.
```bash
    Répertoire : C:\Users\HRO\Desktop\ORC\dfir-orc-config-master\output


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        16/08/2024     11:23        8225280 DFIR-Orc.exe
```
## Launching ORC

To begin the collection, simply execute the `DFIR-Orc.exe` binary with administrator privileges on the target machine.

Once the collection is finished, a single archive containing all the collected artifacts will be produced. You can then upload this archive to WAPP to begin your forensic investigation.


