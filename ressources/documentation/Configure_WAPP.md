# Windows Forensic Artifact Parser (WAPP) Project: In-depth Configuration

This guide provides step-by-step instructions on how to customize WAPP's configuration to meet your specific needs. It is highly recommended to follow this guide if you are not using the pre-configured DFIR-ORC setup.

Note: It is possible to send a custom configuration through the API with the archive you want to parse.

### 📌 Key Links

* **WAPP Repository:** <https://github.com/youhgo/WFAPP>

* **Documentation:** [Installation Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_install.md) | [Usage Guide](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_use.md) | [Results Architecture](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/Explaining_the_results.md)

## How WAPP Works

WAPP uses regular expressions (regex) to find and identify artifacts. It reads a configuration file and, for each artifact type, searches for files that match the specified regex. The tool then uses the correct parser to analyze the discovered artifacts.

**Note:** Everything in the uploaded archive will be ingested by `plaso`, even if WAPP doesn't have a specific parser for it. This ensures that all data is included in the final timeline.

## Artifact Naming Configuration

For WAPP to parse an artifact, you **must** provide a regex that matches its name in the configuration file. 

For it to work you must use this template, do NOT modify its structure.
It's not possible to add a new artefact to the config as there is no parser for it.

The default configuration file is located at [artefact_name_config.json](../WAPP_MODULE/config/artefact_name_config.json). 

This config is designed to work with DFIR-ORC and specialy with the DFIR-Orc.exe collector provided. See this [DFIR-ORC Configuration](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/configure_orc.md).

If you are using a different collection tool, such as KAPE, your artifacts might have different names.

### Example: Configuring Hives

The default hive configuration looks like this:
```json
{
    "hives": {
        "NTUSER": ["NTUSER.DAT$"],
        "AMCACHE": ["Amcache.hve$"],
        "SOFTWARE": ["SOFTWARE$"],
        "SYSTEM": ["SYSTEM$"],
        "SECURITY": ["SECURITY$"],
        "SAM": ["SAM$"]
    }
}
```

Let's say the `SOFTWARE` hive collected by your tool is named `"SOFTWARE_HIVE"`. To ensure WAPP can find and parse this file, you need to add a new regex to the `SOFTWARE` list in your configuration.

The updated configuration would then look like this:
```json
{
  "hives": {
        "...": [".."],
        "SOFTWARE": [
          "SOFTWARE$",
          "SOFTWARE_HIVE$"
        ],
        "...": [".."]
  }
}
```

By adjusting the regex patterns, you can make WAPP compatible with any forensic collection tool you use.