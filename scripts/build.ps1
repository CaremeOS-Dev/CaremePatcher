<#
  build.ps1 -- build xtc-patch.exe natively on Windows with MinGW (static).

    .\scripts\build.ps1                       # auto-detect Dev-Cpp MinGW
    .\scripts\build.ps1 -Gcc C:\msys64\ucrt64\bin\gcc.exe -Out out\xtc-patch.exe

  Requires a KernelPatch checkout:
    * XTC_KP_DIR            environment variable, or
    * ..\KernelPatch        (sibling of this repo), or
    * third_party\KernelPatch

  The kptools sources are compiled in-process (-Dmain=kptools_main) and the
  kpimg blob from kpimg\kpimg-canonical.bin is appended with a 16-byte trailer.
#>
[CmdletBinding()]
param(
    [string]$Gcc,
    [string]$Kpimg,
    [string]$Out = "out\xtc-patch.exe",
    [switch]$NoEmbed
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$src = Join-Path $root "src"
$zop = Join-Path $root "third_party\zopfli"

# --- locate KernelPatch -------------------------------------------------
$kpDir = $env:XTC_KP_DIR
if (-not $kpDir) {
    foreach ($c in @((Join-Path $root "..\KernelPatch"), (Join-Path $root "third_party\KernelPatch"))) {
        if (Test-Path (Join-Path $c "tools\kptools.c")) { $kpDir = $c; break }
    }
}
if (-not $kpDir -or -not (Test-Path (Join-Path $kpDir "tools\kptools.c"))) {
    throw "KernelPatch checkout not found; set XTC_KP_DIR"
}
$kp = Join-Path $kpDir "tools"

if (-not $Gcc) {
    $cand = @(
        "D:\Program Files (x86)\Dev-Cpp\MinGW64\bin\gcc.exe",
        "D:\Program Files (x86)\Dev-Cpp\MinGW32\bin\gcc.exe",
        "C:\msys64\ucrt64\bin\gcc.exe",
        "C:\msys64\mingw64\bin\gcc.exe"
    ) | Where-Object { Test-Path $_ }
    if (-not $cand) { throw "gcc not found; pass -Gcc <path>" }
    $Gcc = $cand[0]
}
$env:PATH = "$(Split-Path -Parent $Gcc);$env:PATH"

if (-not $Kpimg) { $Kpimg = Join-Path $root "kpimg\kpimg-canonical.bin" }
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $root $Out)) -Force | Out-Null }
$outPath = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path $root $Out }

$inc = @("-I$src", "-I$kp", "-I$zop", "-I$($kp)\lib\sha",
         "-I$($kp)\lib\bz2", "-I$($kp)\lib\lz4", "-I$($kp)\lib\xz")

$sources = @()
foreach ($line in Get-Content (Join-Path $root "scripts\kptools_sources.txt")) {
    $t = $line.Trim()
    if ($t -and -not $t.StartsWith("#")) { $sources += (Join-Path $kp $t) }
}
$sources += (Get-ChildItem "$zop\*.c" | Where-Object { $_.Name -ne "zgzip.c" } | ForEach-Object { $_.FullName })

$obj = Join-Path $root "out\kptools_main.o"
New-Item -ItemType Directory -Path (Split-Path -Parent $obj) -Force | Out-Null

Write-Host "[1/3] compiling kptools (main -> kptools_main)"
& $Gcc -O2 -w -c @inc "-Dmain=kptools_main" (Join-Path $kp "kptools.c") -o $obj
if ($LASTEXITCODE -ne 0) { throw "kptools.c compile failed" }

Write-Host "[2/3] linking $outPath"
& $Gcc -O2 -w -o $outPath @inc (Join-Path $src "xtc-patch.c") (Join-Path $src "xtc_zopfli_parallel.c") `
    $sources $obj -lz -lm -static
if ($LASTEXITCODE -ne 0) { throw "link failed" }

if (-not $NoEmbed) {
    Write-Host "[3/3] appending kpimg blob"
    $blob = [System.IO.File]::ReadAllBytes($Kpimg)
    $blobMd5 = (Get-FileHash $Kpimg -Algorithm MD5).Hash
    if ((Split-Path -Leaf $Kpimg) -eq "kpimg-canonical.bin" -and
        $blobMd5 -ne "8CA5DCBBBEADB649115BBF792CAF258C") {
        throw "kpimg-canonical.bin md5 $blobMd5 is not the verified 8CA5DCBB build"
    }
    $trailer = New-Object byte[] 16
    [System.Text.Encoding]::ASCII.GetBytes("XTCPKP01").CopyTo($trailer, 0)
    [BitConverter]::GetBytes([uint32]$blob.Length).CopyTo($trailer, 8)
    $fs = [System.IO.File]::Open($outPath, [System.IO.FileMode]::Append)
    try {
        $fs.Write($blob, 0, $blob.Length)
        $fs.Write($trailer, 0, $trailer.Length)
    } finally { $fs.Dispose() }
    Write-Host ("      embedded {0} bytes  md5 {1}" -f $blob.Length, $blobMd5)
} else {
    Write-Host "[3/3] skipped (-NoEmbed)"
}

$fi = Get-Item $outPath
Write-Host ("  {0}`n  size {1} bytes   md5 {2}" -f $fi.FullName, $fi.Length,
    (Get-FileHash $outPath -Algorithm MD5).Hash)
