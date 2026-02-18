import zipfile
import os

def create_pydroid_zip():
    zip_name = 'netguard_pydroid.zip'
    # Files needed for Pydroid 3
    files_to_include = ['main.py', 'mock_data.py']
    dirs_to_include = ['app']
    
    print(f"📦 Creating {zip_name} for Pydroid 3...")
    
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add files
        for file in files_to_include:
            if os.path.exists(file):
                zipf.write(file)
                print(f"  + {file}")
        
        # Add directories
        for root_dir in dirs_to_include:
            if os.path.exists(root_dir):
                for root, dirs, files in os.walk(root_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path)
                print(f"  + {root_dir}/ folder")

    print(f"\n✅ DONE! Transfer '{zip_name}' to your phone.")

if __name__ == "__main__":
    create_pydroid_zip()
