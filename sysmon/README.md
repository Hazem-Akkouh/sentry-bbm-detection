# /sysmon : Detail Guide

## The working config

`sysmonconfig-sentry.xml` is the SwiftOnSecurity baseline with four targeted additions applied. Install with:

```powershell
sysmon64.exe -accepteula -i sysmonconfig-sentry.xml
```

## The four fixes, and why each was needed

### 1. ImageLoad (Event ID 7) : was silently disabled

The baseline ships with an empty `<ImageLoad onmatch="include"></ImageLoad>` block. The config's own comment says it plainly: *"Using 'include' with no rules means nothing in this section will be logged."* Needed for Rule 1 (confirming liboradb.dll is loaded in a target process). Fixed by scoping a real rule:

```xml
<ImageLoad onmatch="include">
    <ImageLoaded condition="end with">liboradb.dll</ImageLoaded>
</ImageLoad>
```

### 2. ProcessAccess (Event ID 10) : same trap, plus a real mistake to avoid

Same empty-include problem as above. **A wrong first fix attempt is worth documenting as a warning**: filtering `GrantedAccess condition="contains any" value="0x0020;0x0008;..."`, assuming individual permission flags would appear as substrings in the logged value. **This does not work** : Sysmon logs the bitwise-OR'd combined result (e.g. `0x1028`), which does not textually contain `0x0020` or `0x0008`. The correct fix uses exact-match against the real observed combined values:

```xml
<ProcessAccess onmatch="include">
    <GrantedAccess condition="is">0x1028</GrantedAccess>
    <GrantedAccess condition="is">0x0028</GrantedAccess>
    <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
    <GrantedAccess condition="is">0x1F1FFF</GrantedAccess>
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
</ProcessAccess>
```

### 3. FileCreate : extended for SWIFT-specific artifacts

The baseline's FileCreate include list only covers `.exe`/`.dll`/script extensions. Added:

```xml
<TargetFilename condition="end with">.dat</TargetFilename>
<TargetFilename condition="end with">.prc</TargetFilename>
<TargetFilename condition="end with">.fal</TargetFilename>
<TargetFilename condition="end with">.txt</TargetFilename>
<TargetFilename condition="begin with">C:\Allians\</TargetFilename>
```

The last line is a path-based catch-all : necessary because Rule 6's secure-delete emulator renames files to random strings with **no extension at all**, which the extension-based filters above would never match.

### 4. FileDelete (Event ID 23) : was entirely absent, and crashes Sysmon 15.21 if given a `name` attribute

The baseline has no `FileDelete` rule group at all (only a comment describing the event type). Needed for Rule 6's delete-side detection. **Important, real bug found during this build**: adding a `name` attribute to the `<FileDelete>` element crashes Sysmon 15.21 with `STATUS_STACK_BUFFER_OVERRUN` (exit code -1073740791) on every config reload. Isolated via a clean rebuild from an unmodified baseline, reapplying fixes 1-3 (all survived), then adding FileDelete with vs. without the `name` attribute. **Working version, no `name` attribute:**

```xml
<FileDelete onmatch="include">
    <TargetFilename condition="begin with">C:\Allians\</TargetFilename>
</FileDelete>
```

This crash pattern is not novel : Microsoft Q&A threads document the same FileDelete crash class going back to Sysmon v12.03 on Windows 2008 R2, reportedly fixed in v13.02. Its reappearance in v15.21 suggests a regression or a related, distinct edge case. **Note on terminology**: `STATUS_STACK_BUFFER_OVERRUN` is a legacy-named Windows status code that no longer specifically implies an exploitable buffer overflow : Microsoft's own engineers have publicly clarified it was broadened to mean "program self-triggered abnormal termination" (a `/GS` fast-fail) generally. This should be reported and treated as a stability/crash finding, not an unverified security vulnerability claim.

## Verifying your config actually reloaded

Sysmon's config-reload output can be misleading during heavy iteration. Always confirm the hash changed:

```powershell
$before = (& .\sysmon64.exe -c | Select-String "Config hash")
.\sysmon64.exe -c sysmonconfig-sentry.xml
$after = (& .\sysmon64.exe -c | Select-String "Config hash")
# $before and $after should differ if the reload actually took effect
```

If piping Sysmon's own output to PowerShell string-matching cmdlets returns nothing even for text you can visually confirm is present, redirect to a file and read it directly instead : Sysmon's console output can misbehave with some PowerShell text-processing pipelines.
