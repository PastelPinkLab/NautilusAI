<h1 align="center">

Nautilus_AI

---

<img src="images/banner.png" alt="image" width="1200">

</h1> 

Nautilus with AI is a small, lightweight and free fork of Nautilus that using PowerShell that allows you to quickly debloat your Windows ISO but still be able to use AI functionalities. Instead of manually applying tweaks on a live system, this tool automates the creation of a fully debloated, pure and telemetry-free Windows 11 ISO (`.iso`). 

Building within pure performance for both low-end and high-end PCs, makes the process quick!

> Nautilus is also heavily based on Tiny11Builder in Tweaks, APPXs removal, etc...

## ⚠️ Disclaimer

> [!Warning]
> Great care went into making sure this script does not unintentionally break any OS functionality, but use at your own risk! This script modifies core system images offline. Always test your generated ISO on a Virtual Machine before deploying it on your main hardware.

> This script will work only on Windows 11, if you're looking for Windows 10 builder, you can take it a look on [Elflower](https://github.com/PastelPinkLab/Elflower).

## What things will be removed (Scanned in Windows 11 26H2)

#### APPXs
- Clipchamp.Clipchamp
- Microsoft.ApplicationCompatibilityEnhancements
- Microsoft.BingNews
- Microsoft.BingSearch
- Microsoft.BingWeather
- Microsoft.GamingApp
- Microsoft.GetHelp
- Microsoft.MicrosoftOfficeHub
- Microsoft.MicrosoftSolitaireCollection
- Microsoft.MicrosoftStickyNotes
- Microsoft.OutlookForWindows
- Microsoft.Paint
- Microsoft.PowerAutomateDesktop
- Microsoft.ScreenSketch
- Microsoft.Todos
- Microsoft.Windows.DevHome
- Microsoft.WindowsAlarms
- Microsoft.WindowsCalculator
- Microsoft.WindowsFeedbackHub
- Microsoft.WindowsSoundRecorder
- Microsoft.WindowsStore
- Microsoft.WindowsTerminal
- Microsoft.Xbox.TCUI
- Microsoft.XboxGamingOverlay
- Microsoft.XboxIdentityProvider
- Microsoft.XboxSpeechToTextOverlay
- Microsoft.YourPhone
- Microsoft.ZuneMusic
- MicrosoftCorporationII.QuickAssist
- MicrosoftWindows.Client.WebExperience
- MicrosoftWindows.CrossDevice
- MSTeams

#### Optional Features (Unlocked DMA Region Policy)
- Printing-Foundation-InternetPrinting-Client
- Printing-XPSServices-Features
- Printing-PrintToPDFServices-Features
- WorkFolders-Client
- MediaPlayback
- SMB1Protocol
- SMB1Protocol-Client
- SMB1Protocol-Server
- SMB1Protocol-Deprecation
- MSRDC-Infrastructure
- WindowsMediaPlayer

#### Capabilities (FOD)
- App.StepsRecorder
- Browser.InternetExplorer
- Language.Handwriting
- Language.OCR
- Language.Speech
- Language.TextToSpeech
- MathRecognizer
- Media.WindowsMediaPlayer
- Microsoft.Wallpapers.Extended
- Microsoft.Windows.PowerShell.ISE
- OneCoreUAP.OneSync
- Print.Management.Console
- VBSCRIPT

#### CBS Package
- Microsoft-Windows-CEIPEnable-Adm-Package
- Microsoft-Windows-FlipGridPWA-Package
- Microsoft-Windows-Internet-Browser-Package
- Microsoft-Windows-OneDrive-Setup-Package
- Microsoft-Windows-OneDrive-Setup-WOW64-Package
- Microsoft-Windows-OutlookPWA-Package
- Microsoft-Windows-Printing-XpsDocumentWriter-Opt-Package
- Microsoft-Windows-Printing-XPSServices-Package
- Microsoft-Windows-RemoteAssistance-Package-Client
- LanguageFeatures-TextToSpeech
- UserExperience-Recall-Package

#### And more...
- Edge (Edge, EdgeUpdate, EdgeCore)
- Microsoft-Edge-Webview
- OneDrive

## Tweaks
- Telemetry, sponsors apps
- GameDXR and Xbox
- Enable Local Accounts
- Disable Bing
- Disable ContentDelivery
- Disable Bitlocker
- Bypass TPM 2.0 and unsupported CPU
- Disable HR and Hibernation
- ResetBase

## So... how to use the builder?

### Requirements
- A pure Windows 11 ISO downloaded from Microsoft.
- At least 20GB of free space on your `C:\` drive for the workspace.
- **Administrator Privileges** (The script will automatically check for this).

### Running the Script

1. Download the latest version of the script (`NautilusCopilot.ps1`).
2. Open PowerShell as Administrator.
3. Temporarily allow script execution by running:
   ```PowerShell
   Set-ExecutionPolicy Unrestricted -Scope Process -Force
4. Follow the instructions
5. Sit back and let the tool do it

## License
Nautilus is licensed under the GPLv3 license. See the LICENSE file for more information.

## Credits
- [NTDEV](https://github.com/ntdevlabs) for creating and hosting Tiny11Builder
- [Luu Phuong](https://github.com/lyghtlychee) for providing some neccessary infos
- [Raphire](https://github.com/Raphire) for Win11Debloat
- ...

## Support me
- Non-available, unfortunately

