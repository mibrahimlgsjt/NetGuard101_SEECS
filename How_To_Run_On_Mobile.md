# How to Run NetGuard on Android (Windows User Guide)

Building the Android app requires a Linux environment. Since you are on Windows, we use **Google Colab** to build it in the cloud.

---

## 🚀 Build Method: Google Colab (Recommended)
This method builds the app on Google's powerful servers and gives you an `.apk` file to download.

### Steps:

1.  **Open Google Colab:** Go to [colab.research.google.com](https://colab.research.google.com/).
2.  **Upload the Notebook:**
    *   Click **File > Upload notebook**.
    *   Select `Build_NetGuard_APK.ipynb` (located in your project's `viva_docs` folder).
3.  **Upload Project:**
    *   Create a ZIP file of your `NetGuard proj` folder.
    *   In Colab, click the **Folder icon** (sidebar) and upload your ZIP file.
4.  **Run Automation:**
    *   Click **Runtime > Run All**.
    *   Use the new "Fix File Structure" step if prompted.
5.  **Download & Install:**
    *   Once the build completes (approx. 15-20 mins for first run), the `.apk` file will download automatically.
    *   Transfer it to your phone and install!

---

## Troubleshooting

### "APK won't install"
Ensure **"Install from Unknown Sources"** is enabled on your phone settings for your file manager or browser.
