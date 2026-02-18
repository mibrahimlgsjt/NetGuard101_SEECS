import os
import zipfile
import shutil

def prepare_zip():
    zip_name = "netguard_android_build.zip"
    # Essential files and directories
    include_files = [
        "main.py",
        "android_utils.py",
        "mock_data.py",
        "buildozer_colab.spec"
    ]
    include_dirs = [
        "app",     # Assets, models
        "idps"     # Cloud manager, logic
    ]

    print(f"Creating clean Android source: {zip_name}...")
    
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add files
        for file in include_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"  + {file}")
            else:
                print(f"  ! Warning: {file} not found")

        # Add directories recursively
        for root_dir in include_dirs:
            if os.path.exists(root_dir):
                for root, dirs, files in os.walk(root_dir):
                    # Skip pycache and hidden
                    if "__pycache__" in root or "/." in root:
                        continue
                    for file in files:
                        if not file.endswith(('.pyc', '.log', '.txt')):
                            file_path = os.path.join(root, file)
                            zipf.write(file_path)
                print(f"  + {root_dir}/ (recursive)")

    print(f"\nSUCCESS: Created {zip_name}")
    print("You can now upload this file to Google Colab for building.")

if __name__ == "__main__":
    prepare_zip()
