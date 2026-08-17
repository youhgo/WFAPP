import json

input_file = "all_view.ndjson"
output_file = "wazuh_converted_view.ndjson"

print(f"[*] Reading {input_file}...")

with open(input_file, "r", encoding="utf-8") as f_in, open(output_file, "w", encoding="utf-8") as f_out:
    count = 0
    for line in f_in:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)

            # --- COMPATIBILITY FIXES ---

            # 1. Remove 8.x Migration Versions (Wazuh doesn't know them)
            if "coreMigrationVersion" in data:
                del data["coreMigrationVersion"]
            if "typeMigrationVersion" in data:
                del data["typeMigrationVersion"]

            # 2. Fix Index Patterns referencing "timeFieldName"
            # Wazuh/OpenSearch sometimes prefers the raw string over nested structures for older compat
            if data.get("type") == "index-pattern":
                # Ensure timeFieldName is estimestamp
                if "timeFieldName" in data["attributes"]:
                    # Keep it as is, just ensuring it's cleaned
                    pass

            # 3. Clean "references"
            # Sometimes 8.x exports have references that 7.10/OpenSearch considers invalid if strictly checked.
            # We keep them for now, but if import fails, we might need to clear non-essential refs.

            # --- WRITE OUTPUT ---
            f_out.write(json.dumps(data) + "\n")
            count += 1

        except json.JSONDecodeError:
            print(f"[!] Skipped invalid JSON line")
            continue

print(f"[*] Success! {count} objects converted.")
print(f"[*] Created file: {output_file}")
print("[*] You can now import this file into Wazuh Dashboard.")