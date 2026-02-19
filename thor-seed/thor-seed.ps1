$ThorDirectory = "C:\thor-seed"
$OutputPath = "C:\thor-seed\reports"
$NoLog = $False
$Hostname = [System.Net.Dns]::GetHostName()
$ThorArch = "64"
if ([System.Environment]::Is64BitOperatingSystem -eq $False)
{
    $ThorArch = ""
}

# Predefined YAML Config
$UsePresetConfig = $True
# Lines with '#' are commented and inactive. We decided to give you
# some examples for your convenience. You can see all possible command
# line parameters running `thor64.exe --help` or on this web page:
# https://github.com/NextronSystems/nextron-helper-scripts/tree/master/thor-help
# Only the long forms of the parameters are accepted in the YAML config.

# PRESET CONFIGS

# FULL with Lookback
# Preset template for a complete scan with a lookback of 14 days
# Hint: lookback in conjunction with the global-lookback parameter applies the "lookback" value to all possible modules (e.g. Filescan, etc.). This reduces scan time significantly.
# Run time: 30 to 60 minutes
# Specifics:
#   - runs all default modules
#   - only scans elements that have been changed or created within the last 14 days
#   - applies Sigma rules
# cloudconf: [!]PresetConfig_FullLookback [Full Scan with Lookback] Performs a full disk scan with all modules but only checks elements changed or created within the last 14 days - best for SOC response to suspicious events (20 to 40 min)
$PresetConfig_FullLookback = @"
rebase-dir: $($ThorDirectory)  # Path to store all output files (default: script location)
nosoft: true           # Don't throttle the scan, even on single core systems
global-lookback: true  # Apply lookback to all possible modules
lookback: 14           # Log and Eventlog look back time in days
# cpulimit: 70         # Limit the CPU usage of the scan
sigma: true            # Activate Sigma scanning on Eventlogs
nofserrors: true       # Don't print an error for non-existing directories selected in quick scan
nocsv: true            # Don't create CSV output file with all suspicious files
noscanid: true         # Don't print a scan ID at the end of each line (only useful in SIEM import use cases)
nothordb: true         # Don't create a local SQLite database for differential analysis of multiple scans
"@

# QUICK
# Preset template for a quick scan
# Run time: 10 to 30 minutes
# Specifics:
#   - runs all default modules except Eventlog and a full file system scan
#   - in quick mode only a highly relevant subset of folders gets scanned
#   - skips Registry checks (keys with potential for persistence still get checked in Autoruns module)
# cloudconf: PresetConfig_Quick [Quick Scan] Performs a quick scan on processes, caches, persistence elements and selected highly relevant directories (10 to 20 min)
$PresetConfig_Quick = @"
rebase-dir: $($ThorDirectory)  # Path to store all output files (default: script location)
nosoft: true       # Don't throttle the scan, even on single core systems
quick: true        # Quick scan mode
nofserrors: true   # Don't print an error for non-existing directories selected in quick scan
nocsv: true        # Don't create CSV output file with all suspicious files
noscanid: true     # Don't print a scan ID at the end of each line (only useful in SIEM import use cases)
nothordb: true     # Don't create a local SQLite database for differential analysis of multiple scans
"@

# FULL
# Preset template for a complete scan
# Hint: lookback per default only applies to the Eventlog module, meaning no Eventlog entries older than 14 days get scanned, but all other modules scan the full system (e.g. Filescan, etc.). This will reduce scan time a little bit, especially on systems with many Eventlog entries.
# Run time: 40 minutes to 6 hours
# Specifics:
#   - runs all default modules
#   - only scans the last 14 days of the Eventlog
#   - applies Sigma rules
# cloudconf: PresetConfig_Full [Full Scan] Performs a full disk scan with all modules (40 min to 6 hours)
$PresetConfig_Full = @"
rebase-dir: $($ThorDirectory)  # Path to store all output files (default: script location)
nosoft: true       # Don't throttle the scan, even on single core systems
lookback: 14       # Log and Eventlog look back time in days
# cpulimit: 70     # Limit the CPU usage of the scan
sigma: true        # Activate Sigma scanning on Eventlogs
nofserrors: true   # Don't print an error for non-existing directories selected in quick scan
nocsv: true        # Don't create CSV output file with all suspicious files
noscanid: true     # Don't print a scan ID at the end of each line (only useful in SIEM import use cases)
nothordb: true     # Don't create a local SQLite database for differential analysis of multiple scans
"@

# SELECT YOU CONFIG
# Select your preset config
# Choose between: $PresetConfig_Full, $PresetConfig_Quick, $PresetConfig_FullLookback
$PresetConfig = $PresetConfig_FullLookback

# False Positive Filters
$UseFalsePositiveFilters = $True
# The following new line separated false positive filters get
# applied to all log lines as regex values.
$PresetFalsePositiveFilters = @"
Could not get files of directory
Signature file is older than 60 days
\\Our-Custom-Software\\v1.[0-9]+\\
"@

# Fixing Certain Platform Environments --------------------------------
$AutoDetectPlatform = ""
if ($ThorDirectory -eq "")
{
    $ThorDirectory = $PSScriptRoot
}


# Global Variables ----------------------------------------------------
$global:NoLog = $NoLog

# #####################################################################
# Functions -----------------------------------------------------------
# #####################################################################


function Write-Log
{
    param (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = "Log entry")]
        [ValidateNotNullOrEmpty()]
        [String]$Entry,
        [Parameter(Position = 1, HelpMessage = "Log file to write into")]
        [ValidateNotNullOrEmpty()]
        [Alias('SS')]
        [IO.FileInfo]$LogFile = "thor-seed.log",
        [Parameter(Position = 3, HelpMessage = "Level")]
        [ValidateNotNullOrEmpty()]
        [String]$Level = "Info"
    )

    # Indicator
    $Indicator = "[+] "
    if ($Level -eq "Warning")
    {
        $Indicator = "[!] "
    }
    elseif ($Level -eq "Error")
    {
        $Indicator = "[E] "
    }
    elseif ($Level -eq "Progress")
    {
        $Indicator = "[.] "
    }
    elseif ($Level -eq "Note")
    {
        $Indicator = "[i] "
    }
    elseif ($Level -eq "Help")
    {
        $Indicator = ""
    }

    # Output Pipe
    if ($Level -eq "Warning")
    {
        Write-Warning -Message "$($Indicator) $($Entry)"
    }
    elseif ($Level -eq "Error")
    {
        Write-Host "$($Indicator)$($Entry)" -ForegroundColor Red
    }
    else
    {
        Write-Host "$($Indicator)$($Entry)"
    }

    # Log File
    if ($global:NoLog -eq $False)
    {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') $($env:COMPUTERNAME): $Entry" | Out-File -FilePath $LogFile -Append
    }
}

# #####################################################################
# Main Program --------------------------------------------------------
# #####################################################################

Write-Host "==========================================================="
Write-Host "   ________ ______  ___    ____           __    ___        "
Write-Host "  /_  __/ // / __ \/ _ \  / __/__ ___ ___/ /   /   \       "
Write-Host "   / / / _  / /_/ / , _/ _\ \/ -_) -_) _  /   /_\ /_\      "
Write-Host "  /_/ /_//_/\____/_/|_| /___/\__/\__/\_,_/    \ / \ /      "
Write-Host "                                               \   /       "
Write-Host "  Nextron Systems, by Florian Roth              \_/        "
Write-Host "                                                           "
Write-Host "==========================================================="

# Measure time
$DateStamp = Get-Date -f yyyy-MM-dd
$StartTime = $(Get-Date)

Write-Log "Started thor-seed with PowerShell v$($PSVersionTable.PSVersion)"

# ---------------------------------------------------------------------
# THOR still running --------------------------------------------------
# ---------------------------------------------------------------------
$ThorProcess = Get-Process -Name "thor64" -ErrorAction SilentlyContinue
if ($ThorProcess)
{
    Write-Log "A THOR process is still running." -Level "Error"
}

# ---------------------------------------------------------------------
# Run THOR ------------------------------------------------------------
# ---------------------------------------------------------------------
try
{
    # Finding THOR binaries in extracted package
    Write-Log "Trying to find THOR binary in location $($ThorDirectory)" -Level "Progress"
    $ThorLocations = Get-ChildItem -Path $ThorDirectory -Recurse -Filter thor*.exe
    # Error - not a single THOR binary found
    if ($ThorLocations.count -lt 1)
    {
        Write-Log "THOR binaries not found in directory $($ThorDirectory)" -Level "Error"
        if ($CustomUrl)
        {
            Write-Log 'When using a custom ZIP package, make sure that the THOR binaries are in the root of the archive and not any sub-folder. (e.g. ./thor64.exe and ./signatures)' -Level "Warning"
            break
        }
        else
        {
            Write-Log "This seems to be a bug. You could check the temporary THOR package yourself in location $($ThorDirectory)." -Level "Warning"
            break
        }
    }

    # Selecting the first location with THOR binaries
    $LiteAddon = ""
    foreach ($ThorLoc in $ThorLocations)
    {
        # Skip THOR Util findings
        if ($ThorLoc.Name -like "*-util*")
        {
            continue
        }
        # Save the directory name of the found THOR binary
        $ThorBinDirectory = $ThorLoc.DirectoryName
        # Is it a Lite version
        if ($ThorLoc.Name -like "*-lite*")
        {
            Write-Log "THOR Lite detected"
            $LiteAddon = "-lite"
        }
        Write-Log "Using THOR binaries in location $($ThorBinDirectory)."
        break
    }
    $ThorBinaryName = "thor$($ThorArch)$($LiteAddon).exe"
    $ThorBinary = Join-Path $ThorBinDirectory $ThorBinaryName

    # Use Preset Config (instead of external .yml file)
    $Config = ""
    if ($UsePresetConfig)
    {
        Write-Log 'Using preset config defined in script header due to $UsePresetConfig = $True'
        $TempConfig = Join-Path $ThorBinDirectory "config.yml"
        Write-Log "Writing temporary config to $($TempConfig)" -Level "Progress"
        Out-File -FilePath $TempConfig -InputObject $PresetConfig -Encoding ASCII
        $Config = $TempConfig
    }

    # Use Preset False Positive Filters
    if ($UseFalsePositiveFilters)
    {
        Write-Log 'Using preset false positive filters due to $UseFalsePositiveFilters = $True'
        $ThorConfigDir = Join-Path $ThorBinDirectory "config"
        $TempFPFilter = Join-Path $ThorConfigDir "false_positive_filters.cfg"
        Write-Log "Writing temporary false positive filter file to $($TempFPFilter)" -Level "Progress"
        Out-File -FilePath $TempFPFilter -InputObject $PresetFalsePositiveFilters -Encoding ASCII
    }

    # Scan parameters
    [string[]]$ScanParameters = @()
    if ($Config)
    {
        $ScanParameters += "-t $($Config)"
    }

    # Run THOR
    Write-Log "Starting THOR scan ..." -Level "Progress"
    Write-Log "Command Line: $($ThorBinary) $($ScanParameters)"
    Write-Log "Writing output files to $($OutputPath)"
    if (-not (Test-Path -Path $OutputPath))
    {
        Write-Log "Output path does not exists yet. Trying to create it ..." -Level "Progress"
        try
        {
            New-Item -ItemType Directory -Force -Path $OutputPath
            Write-Log "Output path $($OutputPath) successfully created."
        }
        catch
        {
            Write-Log "Output path set by $OutputPath variable doesn't exist and couldn't be created. You'll have to rely on the SYSLOG export or command line output only." -Level "Error"
        }
    }
    if ($ScanParameters.Count -gt 0)
    {
        # With Arguments
        $p = Start-Process $ThorBinary -ArgumentList $ScanParameters -NoNewWindow -PassThru
    }
    else
    {
        # Without Arguments
        $p = Start-Process $ThorBinary -NoNewWindow -PassThru
    }
    # Cache handle, required to access ExitCode, see https://stackoverflow.com/questions/10262231/obtaining-exitcode-using-start-process-and-waitforexit-instead-of-wait
    $handle = $p.Handle
    # Wait using WaitForExit, which handles CTRL+C delayed
    $p.WaitForExit()

    # ERROR -----------------------------------------------------------
    if ($p.ExitCode -ne 0)
    {
        Write-Log "THOR scan terminated with error code $($p.ExitCode)" -Level "Error"
    }
    else
    {
        # SUCCESS -----------------------------------------------------
        Write-Log "Successfully finished THOR scan"
        # Output File Info
        $OutputFiles = Get-ChildItem -Path "$($OutputPath)\*" -Include "$($Hostname)_thor_$($DateStamp)*"
        if ($OutputFiles.Length -gt 0)
        {
            foreach ($OutFile in $OutputFiles)
            {
                Write-Log "Generated output file: $($OutFile.FullName)"
            }
        }
        # Give help depending on the auto-detected platform
        if ($AutoDetectPlatform -eq "MDATP" -and $OutputFiles.Length -gt 0)
        {
            Write-Log "Hint (ATP): You can use the following commands to retrieve the scan logs"
            foreach ($OutFile in $OutputFiles)
            {
                Write-Log "  getfile `"$($OutFile.FullName)`""
            }
            #Write-Log "Hint (ATP): You can remove them from the end system by using"
            #foreach ( $OutFile in $OutputFiles ) {
            #    Write-Log "  remediate file `"$($OutFile.FullName)`""
            #}
        }
    }
}
catch
{
    Write-Log "Unknown error during THOR scan $_" -Level "Error"
}

# ---------------------------------------------------------------------
# End -----------------------------------------------------------------
# ---------------------------------------------------------------------
$ElapsedTime = $(get-date) - $StartTime
$TotalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
Write-Log "Scan took $($TotalTime) to complete" -Level "Information"
