import re
import subprocess
import os


def is_apk_signed(apk_path):
    try:
        result = subprocess.run(
            ["jarsigner", "-verify", apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return "jar verified." in result.stdout
    except FileNotFoundError:
        print("jarsigner not found. Ensure JDK is installed and in PATH.")
        return False


def modify_smali_files_with_context(smali_dir, patterns_replacements, target_methods):
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.readlines()

                modified = False
                in_target_method = False
                new_content = []

                for line in content:
                    if any(method in line for method in target_methods):
                        in_target_method = True

                    if in_target_method:
                        for pattern, replacement in patterns_replacements:
                            if re.search(pattern, line):
                                line = re.sub(pattern, replacement, line)
                                modified = True

                    if line.strip() == ".end method":
                        in_target_method = False

                    new_content.append(line)

                if modified:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.writelines(new_content)
                    print(f"Modified: {file_path}")


if __name__ == "main":
    apk_path = "C:\\Users\\bnvsa\\Downloads\\app-debug_sealed.apk"
    smali_directory = "C:\\Users\\bnvsa\\app-debug_sealed"

    if is_apk_signed(apk_path):
        print("APK is signed. Proceeding with Smali modifications.")

        patterns_to_replace = [
            (
                r"invoke-virtual \{.*\}, Ljava/lang/String;->equals\(Ljava/lang/Object;\)Z",
                "const/4 v0, 0x1  # Force equals to return true",
            ),
            (
                r'const-string v0, "[a-fA-F0-9]+"',
                'const-string v0, "expected_hash"  # Hardcoded valid hash',
            ),
            (
                r"invoke-static \{.*\}, Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V",
                "# Removed loadLibrary call for security reasons",
            ),
        ]

        target_methods = [
            "Landroid/content/pm/PackageManager;->getPackageInfo",
            "Landroid/content/pm/PackageInfo;->signatures",
        ]

        modify_smali_files_with_context(
            smali_directory, patterns_to_replace, target_methods
        )
        print("Smali modifications completed.")
    else:
        print("APK is not signed. Exiting.")
