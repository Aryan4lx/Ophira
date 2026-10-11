Description: "Ophira registry deep-dive batch - persistence, execution and lateral-movement keys across SYSTEM/SOFTWARE/NTUSER/UsrClass hives"
Author: "Ophira IR toolkit"
Version: 2
Id: 3f7a2c94-6b1d-4e08-9c5a-82d14f0b7e33
Keys:
# RECmd 2.x .reb format (the old 1.x flat .bn format is rejected by 2.0 - every parse
# failed with a YAML syntax error until this rewrite). Non-matching keys are skipped
# per-hive, so one batch serves all hives. Run via -Mode Parse against a case's
# raw\registry hives -> csv\registry_recmd.csv

# ---- autoruns / persistence (SOFTWARE + NTUSER) ----
    -
        Description: Autorun Run key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
    -
        Description: Autorun RunOnce key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
    -
        Description: Autorun Run key (Wow6432Node)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
    -
        Description: Autorun RunOnce key (Wow6432Node)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
    -
        Description: Policies Explorer Run key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
    -
        Description: RunOnceEx key
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: true
    -
        Description: Autorun Run key (user)
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
    -
        Description: Autorun RunOnce key (user)
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false

# ---- classic persistence / hijack spots ----
    -
        Description: Winlogon (user)
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        Recursive: false
    -
        Description: AppCompatFlags (user)
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
        Recursive: true
    -
        Description: Winlogon (shell/userinit)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        Recursive: false
    -
        Description: Image File Execution Options (debugger hijacks)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        Recursive: true
    -
        Description: Windows load/hosting values
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Windows
        Recursive: false
    -
        Description: AppCompatFlags (system)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
        Recursive: true
    -
        Description: Active Setup Installed Components
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Active Setup\Installed Components
        Recursive: true
    -
        Description: Explorer Shell Folders
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        Recursive: false
    -
        Description: Explorer User Shell Folders
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
        Recursive: false

# ---- services + drivers + system (SYSTEM) ----
    -
        Description: Services (all - ServiceDll hijack audit)
        HiveType: SYSTEM
        Category: Services
        KeyPath: ControlSet*\Services
        Recursive: true
    -
        Description: Session Manager (BootExecute/PendingFileRenames)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Session Manager
        Recursive: false
    -
        Description: Session Manager Executive
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Session Manager\Executive
        Recursive: false
    -
        Description: SafeBoot (safe-mode persistence)
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\SafeBoot
        Recursive: true
    -
        Description: USBSTOR (USB device history)
        HiveType: SYSTEM
        Category: USB devices
        KeyPath: ControlSet*\Enum\USBSTOR
        Recursive: true
    -
        Description: TimeZoneInformation
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\TimeZoneInformation
        Recursive: false
    -
        Description: ComputerName
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\ComputerName
        Recursive: true
    -
        Description: CurrentControlSet Select
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        Recursive: false

# ---- network / lateral (SYSTEM + NTUSER) ----
    -
        Description: Tcpip Parameters
        HiveType: SYSTEM
        Category: Network
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        Recursive: false
    -
        Description: Lsa (restriction / protection)
        HiveType: SYSTEM
        Category: Network
        KeyPath: ControlSet*\Control\Lsa
        Recursive: false
    -
        Description: Terminal Server Client Default (recent RDP targets)
        HiveType: NTUSER
        Category: Lateral movement
        KeyPath: Software\Microsoft\Terminal Server Client\Default
        Recursive: false
    -
        Description: Terminal Server Client Servers (RDP history)
        HiveType: NTUSER
        Category: Lateral movement
        KeyPath: Software\Microsoft\Terminal Server Client\Servers
        Recursive: true

# ---- execution evidence (NTUSER + UsrClass) ----
    -
        Description: Explorer TypedPaths
        HiveType: NTUSER
        Category: Execution evidence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        Recursive: false
    -
        Description: Explorer RunMRU
        HiveType: NTUSER
        Category: Execution evidence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        Recursive: false
    -
        Description: LastVisitedPidlMRU
        HiveType: NTUSER
        Category: Execution evidence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: true
    -
        Description: RecentApps
        HiveType: NTUSER
        Category: Execution evidence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
        Recursive: true
    -
        Description: Word Reading Locations
        HiveType: NTUSER
        Category: Execution evidence
        KeyPath: Software\Microsoft\Office\16.0\Word\Reading Locations
        Recursive: true
    -
        Description: Shell MuiCache (executed binaries)
        HiveType: UsrClass
        Category: Execution evidence
        KeyPath: Local Settings\Software\Microsoft\Windows\Shell\MuiCache
        Recursive: false
    -
        Description: TrayNotify
        HiveType: UsrClass
        Category: Execution evidence
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify
        Recursive: false
    -
        Description: Explorer Shell Folders (UsrClass)
        HiveType: UsrClass
        Category: Execution evidence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        Recursive: false
