import os
import subprocess
import sys
import re
import xml.etree.ElementTree as ET
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
from azure.storage.blob import BlobServiceClient


app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestBody(BaseModel):
    apk_url: str


android_package_name = ""

CONTAINER_NAME = "sih"

OUTPUT_BASE_DIR = "decompiled_apks"
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)


def upload_to_azure(file_path, blob_name):
    try:
        blob_service_client = BlobServiceClient.from_connection_string(
            "BlobEndpoint=https://sih2024.blob.core.windows.net/;QueueEndpoint=https://sih2024.queue.core.windows.net/;FileEndpoint=https://sih2024.file.core.windows.net/;TableEndpoint=https://sih2024.table.core.windows.net/;SharedAccessSignature=sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2026-12-12T14:20:49Z&st=2024-12-12T06:20:49Z&spr=https,http&sig=O1IGlTlJF4YPLVMU%2BuT%2B421XtBr1lT8zzgUfad%2BAvQc%3D"
        )
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME, blob=blob_name
        )

        with open(file_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)

        url = blob_client.url
        print(f"File uploaded to Azure Blob Storage: {url}")
        return url
    except Exception as e:
        print(f"Error uploading file to Azure Blob Storage: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to upload APK to Azure Blob Storage"
        )


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


import os


def update_main_activity(main_activity_path):

    lines_to_insert_android_armour = f"""
.method public static runSecurityChecks(Landroid/content/Context;)V
.locals 6  # Define sufficient registers for the method

    # USB Debugging Detection
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/usb_detection;->detectUSBDebugging(Landroid/content/Context;)V

    # Cheat Tool Detection
    move-object v0, p0
    check-cast v0, Landroid/content/Context;
    invoke-static {{v0}}, L{android_package_name.replace(".", "/")}/cheat_tool_detection;->checkCheatTools(Landroid/content/Context;)Z
    move-result v1

    if-eqz v1, :show_safe_cheat
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/cheat_tool_detection;->showCheatToolDetectedToast(Landroid/content/Context;)V

    :show_safe_cheat
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/cheat_tool_detection;->showCheatToolNotDetectedToast(Landroid/content/Context;)V

    # Root Detection
    invoke-static {{}}, L{android_package_name.replace(".", "/")}/rooting_detection;->isDeviceRooted()Z
    move-result v1

    if-eqz v1, :show_safe_root
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/rooting_detection;->showRootingDetectedToast(Landroid/content/Context;)V

    :show_safe_root
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/rooting_detection;->showRootingNotDetectedToast(Landroid/content/Context;)V

    # Emulator Detection
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/emulator_detection;->isEmulator(Landroid/content/Context;)Z
    move-result v1

    if-eqz v1, :no_emulator  # Skip if not an emulator
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/emulator_detection;->showEmulatorDetectedToast(Landroid/content/Context;)V

    :no_emulator
    invoke-static {{p0}}, L{android_package_name.replace(".", "/")}/emulator_detection;->showEmulatorNotDetectedToast(Landroid/content/Context;)V
    return-void
.end method
    """

    start_index = main_activity_path.find("com")
    end_index = main_activity_path.rfind(".smali")
    extracted_path = main_activity_path[start_index:end_index]

    print("extracted_path", extracted_path)

    lines_to_insert = f"""
    invoke-static {{p0}}, L{extracted_path.replace(".", "/")};->runSecurityChecks(Landroid/content/Context;)V
    """

    print("lines_to_insert", lines_to_insert)

    try:
        with open(main_activity_path, "r") as main_activity_f:
            main_activity_content = main_activity_f.readlines()

        insertion_index = None
        insertion_index_armour = len(main_activity_content)

        main_activity_content.insert(
            insertion_index_armour, lines_to_insert_android_armour
        )

        for i, line in enumerate(main_activity_content):

            print("android_package_name", android_package_name)

            if (
                f"invoke-virtual {{p0, v0}}, L{extracted_path.replace(".", "/")};->setContentView(I)V"
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
        "cheat_tool_detection.smali": "cheat_tool_detection.txt",
        "rooting_detection.smali": "rooting_detection.txt",
        "android_armour.smali": "android_armour.txt",
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


def main(apk_url):

    print(f"Decompiling APK from URL: {apk_url}")

    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

    response = requests.get(apk_url, stream=True)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to download APK")

    apk_name = os.path.basename(apk_url)
    apk_path = os.path.join(OUTPUT_BASE_DIR, apk_name)

    with open(apk_path, "wb") as apk_file:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                apk_file.write(chunk)

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
    upload_url = upload_to_azure(signed_apk_path, "signed_output.apk")

    print(f"APK successfully signed and saved to {signed_apk_path}")

    print("Cleaning up...")
    # os.remove(apk_path)
    # os.remove("unsigned_output.apk")
    # os.rename(temp_dir, os.path.join(OUTPUT_BASE_DIR, "decompiled_apks"))

    return upload_url


@app.get("/")
async def read_root():
    return {"message": "Hello World"}


@app.post("/apk-decompile")
async def decompile_apk(request: RequestBody):

    apk_url = request.apk_url

    print(f"Decompiling APK from URL: {apk_url}")

    signed_apk_url = main(apk_url)

    return {
        "message": "APK decompiled and uploaded successfully.",
        "url": signed_apk_url,
    }
