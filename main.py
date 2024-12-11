import os
import subprocess
import sys
import re
import xml.etree.ElementTree as ET

android_package_name = ""


def run_command(cmd):
    try:
        subprocess.run(cmd, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        sys.exit(1)


def run_apktool(command, *args):
    cmd = ["apktool", command] + list(args)
    run_command(" ".join(cmd))


def generate_signing_key(keystore_path, alias, password):
    print("Generating signing key...")
    if os.path.exists(keystore_path):
        print(f"Keystore already exists at {keystore_path}. Skipping key generation.")
        return

    cmd = (
        f"keytool -genkeypair -v -keystore {keystore_path} -keyalg RSA -keysize 2048 "
        f"-validity 10000 -alias {alias} -storepass {password} -keypass {password} "
        f'-dname "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown"'
    )
    run_command(cmd)


def sign_apk(apk_path, output_path, keystore_path, alias, password):
    print("Signing APK...")
    cmd = (
        f"apksigner sign --ks {keystore_path} --ks-key-alias {alias} "
        f"--ks-pass pass:{password} --key-pass pass:{password} --out {output_path} {apk_path}"
    )
    run_command(cmd)


def update_main_activity(main_activity_path):

    lines_to_insert = f"""
    
    invoke-static {{p0}}, L{android_package_name.replace(
        ".", "/"
    )}/usb_detection;->detectUSBDebugging(Landroid/content/Context;)V

    move-object v3, p0
    check-cast v3, Landroid/content/Context;
    invoke-static {{v3}}, L{android_package_name.replace(
        ".", "/"
    )}/cheat_tool_detection;->checkCheatTools(Landroid/content/Context;)Z
    move-result v4
    
    if-eqz v4, :show_safe
    
    const-string v5, "Cheat tool detected!"
    goto :show_toast
    
    :show_safe
    const-string v5, "No Cheat tool detected, App is safe to use!"
    
    :show_toast
    const/4 v4, 0x1
    invoke-static {{v3, v5, v4}}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    move-result-object v4
    invoke-virtual {{v4}}, Landroid/widget/Toast;->show()V


    invoke-static {{p0}}, L{android_package_name.replace(
        ".", "/"
    )}/emulator_detection;->isEmulator(Landroid/content/Context;)Z
    move-result v0

    if-eqz v0, :no_emulator  # If not an emulator, skip the Toast display

    invoke-static {{p0}}, L{android_package_name.replace(
        ".", "/"
    )}/emulator_detection;->showEmulatorToast(Landroid/content/Context;)V

    :no_emulator
    """

    try:
        with open(main_activity_path, "r") as main_activity_f:
            main_activity_content = main_activity_f.readlines()

        for i, line in enumerate(main_activity_content):
            if (
                f"invoke-virtual {{p0, v0}}, L{android_package_name.replace(
                    ".", "/"
                )}/MainActivity;->setContentView(I)V"
                in line
            ):
                insertion_index = i + 1
                break
        else:
            print(f"Target line not found in {main_activity_path}.")
            sys.exit(1)

        main_activity_content.insert(insertion_index, lines_to_insert)

        with open(main_activity_path, "w") as main_activity_f:
            main_activity_f.writelines(main_activity_content)

        with open(main_activity_path, "r") as main_activity_f:
            main_activity_content = main_activity_f.read()

        main_activity_content = re.sub(
            r"\.locals \d+",
            lambda x: f".locals {int(x.group(0).split()[-1]) + 5}",
            main_activity_content,
        )

        with open(main_activity_path, "w") as main_activity_f:
            main_activity_f.write(main_activity_content)

        print("Updated MainActivity.smali to include USB and Emulator detection.")

    except FileNotFoundError:
        print(f"File {main_activity_path} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


def create_detection_files(base_dir, smali_impl_dir):
    files_mapping = {
        "emulator_detection.smali": "emulator_detection.txt",
        "usb_detection.smali": "usb_detection.txt",
    }

    for smali_file, txt_file in files_mapping.items():
        txt_file_path = os.path.join(smali_impl_dir, txt_file)
        smali_file_path = os.path.join(base_dir, smali_file)

        if not os.path.exists(txt_file_path):
            print(f"Error: Source file '{txt_file_path}' not found.")
            continue

        with open(txt_file_path, "r") as txt_f:
            content = txt_f.read()

        class_declaration = f".class public final L{android_package_name.replace('.', '/')}/{smali_file[:-6]};\n"
        complete_content = class_declaration + content

        with open(smali_file_path, "w") as smali_f:
            smali_f.write(complete_content)

        print(f"Created file: {smali_file_path}")


def find_main_activity(temp_dir):
    global android_package_name
    manifest_path = None
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            if file == "AndroidManifest.xml":
                manifest_path = os.path.join(root, file)
                break
        if manifest_path:
            break

    if not manifest_path:
        return None

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        namespace = {"android": "http://schemas.android.com/apk/res/android"}
        for activity in root.findall(".//activity", namespace):
            intent_filters = activity.findall("intent-filter", namespace)
            for intent_filter in intent_filters:
                action = intent_filter.find(
                    "action[@android:name='android.intent.action.MAIN']", namespace
                )
                category = intent_filter.find(
                    "category[@android:name='android.intent.category.LAUNCHER']",
                    namespace,
                )
                if action is not None and category is not None:
                    activity_name = activity.attrib[f"{{{namespace['android']}}}name"]
                    if activity_name.startswith("."):
                        activity_name = root.attrib["package"] + activity_name
                    android_package_name = root.attrib["package"]
                    activity_file = activity_name.replace(".", "/") + ".smali"
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if activity_file in os.path.join(root, file).replace(
                                "\\", "/"
                            ):
                                return os.path.join(root, file)
    except Exception as e:
        print(f"Error: {e}")
        return None

    return None


def main(apk_path):
    if not os.path.isfile(apk_path):
        print(f"APK file does not exist: {apk_path}")
        sys.exit(1)

    temp_dir = os.path.join(os.getcwd(), "temp")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print(f"Using fixed directory for decompilation: {temp_dir}")

    print("Decompiling APK...")
    run_apktool("d", apk_path, "-o", temp_dir, "-f")

    main_activity_path = find_main_activity(temp_dir)

    if not main_activity_path:
        print("MainActivity.smali not found.")
        sys.exit(1)
    print(f"MainActivity.smali found at: {main_activity_path}")

    base_dir = os.path.dirname(main_activity_path)
    create_detection_files(base_dir, "./smali-impl")

    update_main_activity(main_activity_path)

    print("Rebuilding APK...")
    run_apktool("b", temp_dir, "-o", "unsigned_output.apk")

    keystore_path = os.path.join(os.getcwd(), "keystore.jks")
    alias = "alias"
    password = "password"

    generate_signing_key(keystore_path, alias, password)

    signed_apk_path = "signed_output.apk"
    sign_apk("unsigned_output.apk", signed_apk_path, keystore_path, alias, password)

    print(f"APK successfully signed and saved to {signed_apk_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    main(apk_path)
