param(
    [string]$Target = "C:\Users\26346\Downloads\AxonSkin v4.1.exe"
)
$ErrorActionPreference = "Stop"
$OutDir = "C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\recon"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rep = New-Object System.Collections.ArrayList
function W([string]$s){ Write-Output $s; [void]$rep.Add($s) }

$fi = Get-Item -LiteralPath $Target
$fs=[System.IO.File]::Open($fi.FullName,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$br=New-Object System.IO.BinaryReader($fs)

# re-derive key offsets quickly
$dos=[byte[]](0)*64; $fs.Seek(0,0)|Out-Null; $dos=$br.ReadBytes(64)
$e_lfanew=[BitConverter]::ToInt32($dos,0x3C)
$fs.Seek($e_lfanew+6,0)|Out-Null; $numSec=[BitConverter]::ToUInt16($br.ReadBytes(2),0)
$fs.Seek($e_lfanew+20,0)|Out-Null; $szOpt=[BitConverter]::ToUInt16($br.ReadBytes(2),0)
$secBase=$e_lfanew+24+$szOpt
$sec=New-Object System.Collections.ArrayList
for($i=0;$i -lt $numSec;$i++){
  $fs.Seek($secBase+$i*40,0)|Out-Null
  $b=$br.ReadBytes(40)
  $name=-join($b[0..7]|%{if($_ -ge 32 -and $_ -le 126){[char]$_}else{''}})
  [void]$sec.Add([pscustomobject]@{
    Name=$name.TrimEnd([char]0)
    VSize=[BitConverter]::ToUInt32($b,8)
    VA=[BitConverter]::ToUInt32($b,12)
    RawSize=[BitConverter]::ToUInt32($b,16)
    RawPtr=[BitConverter]::ToUInt32($b,20)
  })
}

# 1) Version Info via Win32 VerQuery
W "=== VERSION INFO ==="
$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fi.FullName)
W "FileDescription: $($vi.FileDescription)"
W "ProductName:     $($vi.ProductName)"
W "CompanyName:     $($vi.CompanyName)"
W "OriginalName:    $($vi.OriginalFilename)"
W "InternalName:    $($vi.InternalName)"
W "FileVersion:     $($vi.FileVersion)"
W "ProductVersion:  $($vi.ProductVersion)"
W "LegalCopyright:  $($vi.LegalCopyright)"
W "LegalTrademarks: $($vi.LegalTrademarks)"
W "Comments:        $($vi.Comments)"
W "IsDebug:         $($vi.IsDebug)  IsPatched: $($vi.IsPatched)  IsPreRelease: $($vi.IsPreRelease)"

# 2) Packer / tool signatures by scanning section heads + known byte patterns
W ""
W "=== SECTION HEAD SIGNATURES ==="
foreach($s in $sec){
  if($s.RawSize -gt 0){
    $len=[math]::Min(256,$s.RawSize)
    $fs.Seek($s.RawPtr,0)|Out-Null
    $b=$br.ReadBytes($len)
    $asc=-join($b|%{if($_ -ge 32 -and $_ -le 126){[char]$_}else{'.'}})
    W ("{0,-10} first {1} bytes:" -f $s.Name,$len)
    W ("  {0}" -f $asc.Substring(0,[math]::Min(96,$asc.Length)))
  } else {
    W ("{0,-10} RawSize=0 (no disk data)" -f $s.Name)
  }
}

# 3) Known packer/protector signature scan across whole file (cheap: search first 2MB of each data section)
W ""
W "=== PACKER SIGNATURE SCAN ==="
$sigs = @{
  "Themida/WinLicense" = @("Themida","WinLicense","OREANS","SecureEngine")
  "VMProtect"          = @("VMProtect","VMProtectSDK","VMP_")
  "Enigma"             = @("Enigma","EnigmaProtector")
  "ASProtect"          = @("ASProtect","ASPr")
  "MPRESS"             = @("MPRESS","MPR")
  "UPX"                = @("UPX0","UPX1","UPX!")
  "PECompact"          = @("PECompact","PEC2")
  "Armadillo"          = @("Armadillo","SilentRun")
  "Obsidium"           = @("Obsidium")
  "StarForce"          = @("StarForce")
  "Custom/.a1/.rr4"    = @(".a1",".rr4",".k3",".pkg")
}
$found = @{}
foreach($s in $sec){
  if($s.RawSize -le 0){continue}
  $scan = [math]::Min(2097152,$s.RawSize)  # 2MB per section
  $fs.Seek($s.RawPtr,0)|Out-Null
  $b=$br.ReadBytes($scan)
  $txt=[System.Text.Encoding]::ASCII.GetString($b)
  foreach($k in $sigs.Keys){
    foreach($sig in $sigs[$k]){
      if($txt.Contains($sig)){
        if(-not $found.ContainsKey($k)){ $found[$k]=@() }
        $found[$k]+= "$($s.Name):$sig"
      }
    }
  }
}
if($found.Count -gt 0){
  foreach($k in $found.Keys){ W ("FOUND [{0}]: {1}" -f $k,($found[$k] -join ', ')) }
} else { W "No known packer string signature hit in scanned region." }

# 4) Entry point bytes
W ""
W "=== ENTRY POINT BYTES ==="
$epRva=0x13fee150
$rr4=$sec | Where-Object { $_.Name -eq ".rr4" }
if($rr4){
  $epOff=$rr4.RawPtr + ($epRva - $rr4.VA)
  $fs.Seek($epOff,0)|Out-Null
  $b=$br.ReadBytes(64)
  $hex=($b|%{$_.ToString('x2')}) -join ' '
  $asc=-join($b|%{if($_ -ge 32 -and $_ -le 126){[char]$_}else{'.'}})
  W "EP file offset 0x$($epOff.ToString('x'))"
  W "  $hex"
  W "  |$asc|"
}

# 5) Resource directory quick walk (type names)
W ""
W "=== RESOURCE TYPES ==="
$rsrc=$sec | Where-Object { $_.Name -eq ".rsrc" }
if($rsrc){
  $rbase=$rsrc.RawPtr
  $fs.Seek($rbase,0)|Out-Null
  $root=$br.ReadBytes(16)
  $nEntries=[BitConverter]::ToUInt16($root,12)+[BitConverter]::ToUInt16($root,14)
  $namedIds=@()
  for($i=0;$i -lt $nEntries;$i++){
    $fs.Seek($rbase+16+$i*8,0)|Out-Null
    $e=$br.ReadBytes(8)
    $idOrNameOff=[BitConverter]::ToUInt32($e,0)
    $dataOff=[BitConverter]::ToUInt32($e,4)
    $isName=($idOrNameOff -band 0x80000000) -ne 0
    $id=$idOrNameOff -band 0x7FFFFFFF
    $typeName=switch($id){1{"CURSOR"}2{"BITMAP"}3{"ICON"}4{"MENU"}5{"DIALOG"}6{"STRING"}7{"FONTDIR"}8{"FONT"}9{"ACCELERATOR"}10{"RCDATA"}11{"MESSAGETABLE"}12{"GROUP_CURSOR"}14{"GROUP_ICON"}16{"VERSION"}23{"MANIFEST"}24{"HTML"}default{"TYPE_$id"}}
    $namedIds+= [pscustomobject]@{ IsName=$isName; Id=$id; Name=$typeName; SubOff=$dataOff }
    W ("  {0,-6} id/nameOff=0x{1:x8} -> {2}" -f $typeName,$idOrNameOff,$dataOff)
  }
}

# 6) Extract readable ASCII + UTF-16 strings from on-disk sections (.a1, .rr4, .rsrc)
W ""
W "=== STRING EXTRACTION ==="
foreach($s in @($sec | Where-Object { $_.RawSize -gt 0 })){
  $chunkSize=16777216
  $total=[math]::Min($s.RawSize,134217728)  # cap 128MB per section for time
  $cnt=0
  $ascStrs=New-Object System.Collections.ArrayList
  $uniStrs=New-Object System.Collections.ArrayList
  for($off=0;$off -lt $total;$off+=$chunkSize){
    $len=[math]::Min($chunkSize,$total-$off)
    $fs.Seek($s.RawPtr+$off,0)|Out-Null
    $b=$br.ReadBytes($len)
    # ASCII >=6
    $cur=""
    foreach($bt in $b){
      if($bt -ge 32 -and $bt -le 126){ $cur+=[char]$bt } else { if($cur.Length -ge 6){[void]$ascStrs.Add($cur)}; $cur="" }
    }
    if($cur.Length -ge 6){[void]$ascStrs.Add($cur)}
    # UTF-16LE printable (look for pairs)
    $i=0
    $u=""
    while($i+1 -lt $b.Length){
      $lo=$b[$i]; $hi=$b[$i+1]
      if($hi -eq 0 -and $lo -ge 32 -and $lo -le 126){ $u+=[char]$lo } else { if($u.Length -ge 5){[void]$uniStrs.Add($u)}; $u="" }
      $i+=2
    }
    if($u.Length -ge 5){[void]$uniStrs.Add($u)}
  }
  $ascStrs | Select-Object -Unique | Out-File -FilePath "$OutDir\strings_$($s.Name)_ascii.txt" -Encoding UTF8
  $uniStrs | Select-Object -Unique | Out-File -FilePath "$OutDir\strings_$($s.Name)_utf16.txt" -Encoding UTF8
  W ("  {0}: ascii={1} uni={2} (saved)" -f $s.Name,$ascStrs.Count,$uniStrs.Count)
}

$fs.Close()
$rep -join "`r`n" | Out-File -FilePath "$OutDir\extract.txt" -Encoding UTF8
Write-Output ""
Write-Output "Report saved -> $OutDir\extract.txt"
