param(
    [string]$Target = "C:\Users\26346\Downloads\AxonSkin v4.1.exe"
)
$ErrorActionPreference = "Stop"
$OutDir = "C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\recon"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rep = New-Object System.Collections.ArrayList

function W([string]$s) { Write-Output $s; [void]$rep.Add($s) }

if (-not (Test-Path -LiteralPath $Target)) { W "NOT FOUND: $Target"; exit 1 }
$fi = Get-Item -LiteralPath $Target
$fileSize = $fi.Length
W "=== FILE ==="
W "Path: $($fi.FullName)"
W "Size: $fileSize bytes ($([math]::Round($fileSize/1MB,2)) MB)"
W "Modified: $($fi.LastWriteTime)"

$fs = [System.IO.File]::Open($fi.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
$br = New-Object System.IO.BinaryReader($fs)

function ReadBytes($off, $len) {
    $fs.Seek($off, [System.IO.SeekOrigin]::Begin) | Out-Null
    return $br.ReadBytes($len)
}
function HexAscii($b) {
    $h = ($b | ForEach-Object { $_.ToString('x2') }) -join ' '
    $a = -join ($b | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
    return "$h  |$a|"
}

# ---- DOS header ----
$dos = ReadBytes 0 64
if ($dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) { W "Not an MZ binary!"; $fs.Close(); exit 1 }
$e_lfanew = [BitConverter]::ToInt32($dos, 0x3C)
W "e_lfanew: 0x$($e_lfanew.ToString('x'))"

# ---- PE signature ----
$pemagic = ReadBytes $e_lfanew 4
$peStr = -join ($pemagic | ForEach-Object { [char]$_ })
W "PE signature: '$peStr' (expected 'PE' + 2 NUL bytes)"

# ---- COFF header ----
$coff = ReadBytes ($e_lfanew + 4) 20
$machine = [BitConverter]::ToUInt16($coff, 0)
$numSections = [BitConverter]::ToUInt16($coff, 2)
$timeDate = [BitConverter]::ToUInt32($coff, 4)
$sizeOptHdr = [BitConverter]::ToUInt16($coff, 16)
$chars = [BitConverter]::ToUInt16($coff, 18)
$machStr = switch ($machine) { 0x14c {"x86"} 0x8664 {"x64 (AMD64)"} 0xaa64 {"ARM64"} 0x1c0 {"ARM"} 0x1c4 {"ARMv7-NT"} default {"0x$($machine.ToString('x'))"} }
W "Machine: $machStr"
W "NumberOfSections: $numSections"
try { W "TimeDateStamp: $timeDate -> $([DateTimeOffset]::FromUnixTimeSeconds($timeDate).UtcDateTime.ToString('o'))" } catch { W "TimeDateStamp: $timeDate" }
W "SizeOfOptionalHeader: $sizeOptHdr (0x$($sizeOptHdr.ToString('x')))"
W "Characteristics: 0x$($chars.ToString('x'))"

# ---- Optional header ----
$optBase = $e_lfanew + 4 + 20
$opt = ReadBytes $optBase $sizeOptHdr
$magic = [BitConverter]::ToUInt16($opt, 0)
$is64 = $false
$peKind = if ($magic -eq 0x10b) { "PE32 (32-bit)" } elseif ($magic -eq 0x20b) { $is64=$true; "PE32+ (64-bit)" } else { "unknown 0x$($magic.ToString('x'))" }
W "OptionalHeader Magic: $peKind"
$entryPoint = [BitConverter]::ToUInt32($opt, 16)
W "AddressOfEntryPoint: 0x$($entryPoint.ToString('x'))"
W "BaseOfCode: 0x$([BitConverter]::ToUInt32($opt,20).ToString('x'))"
$subsystem = [BitConverter]::ToUInt16($opt, 68)
$subStr = switch ($subsystem) { 1 {"Native"} 2 {"GUI"} 3 {"Console"} 9 {"WinCE"} default {"$subsystem"} }
W "Subsystem: $subStr ($subStr)"
$dllChars = [BitConverter]::ToUInt16($opt, 70)
W "DllCharacteristics: 0x$($dllChars.ToString('x'))"

# data directories base
$ddBase = if ($is64) { 112 } else { 96 }
$nrvas = [BitConverter]::ToUInt32($opt, $ddBase - 4)
W "NumberOfRvaAndSizes: $nrvas"

# ---- Section table ----
$secBase = $optBase + $sizeOptHdr
W ""
W "=== SECTIONS ==="
$sections = New-Object System.Collections.ArrayList
$endOfRaw = 0
for ($i = 0; $i -lt $numSections; $i++) {
    $s = ReadBytes ($secBase + $i*40) 40
    $nameBytes = $s[0..7]
    $name = -join ($nameBytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '' } })
    $name = $name.TrimEnd([char]0)
    $vsize = [BitConverter]::ToUInt32($s, 8)
    $vaddr = [BitConverter]::ToUInt32($s, 12)
    $rawsize = [BitConverter]::ToUInt32($s, 16)
    $rawptr  = [BitConverter]::ToUInt32($s, 20)
    $schars  = [BitConverter]::ToUInt32($s, 36)
    [void]$sections.Add([pscustomobject]@{ Name=$name; VSize=$vsize; VA=$vaddr; RawSize=$rawsize; RawPtr=$rawptr; Chars=$schars })
    if (($rawptr + $rawsize) -gt $endOfRaw) { $endOfRaw = $rawptr + $rawsize }
    $flags = @()
    if ($schars -band 0x20) { $flags += "CODE" }
    if ($schars -band 0x40) { $flags += "INIT_DATA" }
    if ($schars -band 0x80) { $flags += "UNINIT_DATA" }
    if ($schars -band 0x20000000) { $flags += "EXEC" }
    if ($schars -band 0x40000000) { $flags += "READ" }
    if ($schars -band 0x80000000) { $flags += "WRITE" }
    W ("{0,-10} VA=0x{1:x8} VS=0x{2:x8} RawPtr=0x{3:x8} RawSize=0x{4:x8} Chars=0x{5:x8} [{6}]" -f $name,$vaddr,$vsize,$rawptr,$rawsize,$schars,($flags -join ','))
}

# ---- Overlay ----
W ""
W "=== OVERLAY ==="
W "EndOfRawData: $endOfRaw (0x$($endOfRaw.ToString('x')))"
$overlay = $fileSize - $endOfRaw
W "Overlay size: $overlay bytes ($([math]::Round($overlay/1MB,2)) MB)"
if ($overlay -gt 0) {
    $ovHead = ReadBytes $endOfRaw ([math]::Min(512, $overlay))
    W "Overlay first 512 bytes:"
    for ($row=0; $row -lt $ovHead.Length; $row+=16) {
        $len = [math]::Min(16, $ovHead.Length - $row)
        W HexAscii $ovHead[$row..($row+$len-1)]
    }
    # signature detection
    $sig = ""
    if ($ovHead.Length -ge 4) {
        $s4 = $ovHead[0..3]
        if ($s4[0] -eq 0x37 -and $s4[1] -eq 0x7A -and $s4[2] -eq 0xBC -and $s4[3] -eq 0xAF) { $sig = "7-Zip archive" }
        elseif ($s4[0] -eq 0x52 -and $s4[1] -eq 0x61 -and $s4[2] -eq 0x72 -and $s4[3] -eq 0x21) { $sig = "RAR archive" }
        elseif ($s4[0] -eq 0x50 -and $s4[1] -eq 0x4B -and ($s4[2] -eq 0x03 -or $s4[2] -eq 0x05 -or $s4[2] -eq 0x07)) { $sig = "ZIP archive" }
        elseif ($s4[0] -eq 0xD0 -and $s4[1] -eq 0xCF -and $s4[2] -eq 0x11 -and $s4[3] -eq 0xE0) { $sig = "CFB/MSS (MSI/CAB-like)" }
    }
    # string-based signatures within first 4KB
    $big = ReadBytes $endOfRaw ([math]::Min(8192, $overlay))
    $txt = -join ($big | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { ' ' } })
    if ($txt -match "Nullsoft|NSIS") { $sig = "Nullsoft NSIS installer" }
    if ($txt -match "Inno Setup|iNnO|InstallShield") { $sig = "Inno/InstallShield installer" }
    if ($txt -match "7z") { if (-not $sig) { $sig = "possible 7z" } }
    if ($txt -match "Wise") { $sig = "Wise installer" }
    W "Detected overlay signature: $(if ($sig) { $sig } else { 'none (raw payload)' })"
}

# ---- Imports ----
function RvaToFileOffset($rva) {
    foreach ($s in $sections) {
        $act = [math]::Max($s.VSize, $s.RawSize)
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $act)) { return [int]($s.RawPtr + ($rva - $s.VA)) }
    }
    return -1
}
W ""
W "=== IMPORTS ==="
$importRva = [BitConverter]::ToUInt32($opt, $ddBase + 8)
$importSize = [BitConverter]::ToUInt32($opt, $ddBase + 12)
W "Import directory RVA=0x$($importRva.ToString('x')) Size=$importSize"
$impOff = RvaToFileOffset $importRva
if ($impOff -ge 0) {
    $ptrSize = if ($is64) { 8 } else { 4 }
    $thunkMask = if ($is64) { 0x8000000000000000 } else { 0x80000000 }
    $ordMask   = if ($is64) { 0xFFFF } else { 0xFFFF }
    $dllCount = 0
    $funcCount = 0
    $importSummary = New-Object System.Collections.ArrayList
    $off = $impOff
    while ($true) {
        $desc = ReadBytes $off 20
        if ($desc[0] -eq 0 -and $desc[1] -eq 0 -and $desc[4] -eq 0 -and $desc[5] -eq 0 -and $desc[8] -eq 0 -and $desc[9] -eq 0 -and $desc[12] -eq 0 -and $desc[13] -eq 0 -and $desc[16] -eq 0 -and $desc[17] -eq 0) { break }
        $oftRva  = [BitConverter]::ToUInt32($desc, 0)
        $nameRva = [BitConverter]::ToUInt32($desc, 12)
        $iatRva  = [BitConverter]::ToUInt32($desc, 16)
        $nameOff = RvaToFileOffset $nameRva
        $dllName = ""
        if ($nameOff -ge 0) {
            $nb = ReadBytes $nameOff 128
            for ($k=0; $k -lt $nb.Length; $k++) { if ($nb[$k] -eq 0) { break }; $dllName += [char]$nb[$k] }
        }
        $thunkRva = if ($oftRva -ne 0) { $oftRva } else { $iatRva }
        $thunkOff = RvaToFileOffset $thunkRva
        $funcs = New-Object System.Collections.ArrayList
        if ($thunkOff -ge 0) {
            $t = $thunkOff
            while ($true) {
                if ($is64) { $tk = ReadBytes $t 8; $val = [BitConverter]::ToUInt64($tk, 0) } else { $tk = ReadBytes $t 4; $val = [BitConverter]::ToUInt32($tk, 0) }
                if ($val -eq 0) { break }
                if ($val -band $thunkMask) {
                    [void]$funcs.Add("#$($val -band $ordMask)")
                } else {
                    $hnOff = RvaToFileOffset ([uint32]$val)
                    if ($hnOff -ge 0) {
                        $hb = ReadBytes ($hnOff + 2) 128
                        $fn = ""
                        for ($k=0; $k -lt $hb.Length; $k++) { if ($hb[$k] -eq 0) { break }; $fn += [char]$hb[$k] }
                        [void]$funcs.Add($fn)
                    }
                }
                $funcCount++
                $t += $ptrSize
                if ($funcs.Count -ge 120) { break }
            }
        }
        $dllCount++
        W ("DLL[{0}] {1}  funcs={2}  sample: {3}" -f $dllCount, $dllName, $funcs.Count, (($funcs | Select-Object -First 12) -join ', '))
        [void]$importSummary.Add([pscustomobject]@{ DLL=$dllName; Count=$funcs.Count; Sample=(($funcs | Select-Object -First 6) -join ',') })
        $off += 20
        if ($dllCount -ge 300) { W "...truncated at 300 DLLs"; break }
    }
    W "Total imported DLLs: $dllCount ; total imported symbols: $funcCount"
    $importSummary | Export-Csv -Path "$OutDir\imports.csv" -NoTypeInformation -Encoding UTF8
}

# ---- Version info / resources quick check ----
W ""
W "=== DATA DIR SUMMARY ==="
$dirNames = @("Export","Import","Resource","Exception","Certificate","BaseReloc","Debug","Architect","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","CLR","Reserved")
for ($d=0; $d -lt [math]::Min($nrvas,16); $d++) {
    $r = [BitConverter]::ToUInt32($opt, $ddBase + $d*8)
    $sz = [BitConverter]::ToUInt32($opt, $ddBase + $d*8 + 4)
    if ($r -ne 0 -or $sz -ne 0) {
        W ("  [{0}] {1,-14} RVA=0x{2:x8} Size={3}" -f $d, $dirNames[$d], $r, $sz)
    }
}

$fs.Close()
$rep -join "`r`n" | Out-File -FilePath "$OutDir\pe_triage.txt" -Encoding UTF8
Write-Output ""
Write-Output "Report saved -> $OutDir\pe_triage.txt"
