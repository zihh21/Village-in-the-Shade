# FishingAutoCatch v1.0.2 实机内存探针（OpenProcess + ReadProcessMemory）
# 用法: pwsh -File scripts/probe_v102.ps1
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class MemProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@

$pidV = 24924
$mb = 0x7FF66AA00000
$stub = 0x1CD76900000
$PROCESS_VM_READ = 0x0010
$h = [MemProbe]::OpenProcess($PROCESS_VM_READ -bor 0x0400 -bor 0x0020, $false, $pidV)
if ($h -eq [IntPtr]::Zero) { Write-Host "OpenProcess 失败 err=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit 1 }

function Read-Hex($addr, $len) {
    $buf = New-Object byte[] $len
    $n = [IntPtr]::Zero
    if (-not [MemProbe]::ReadProcessMemory($h, [IntPtr]$addr, $buf, $len, [ref]$n)) { return "读取失败 err=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    return (($buf | ForEach-Object { $_.ToString("X2") }) -join " ")
}

Write-Host "HookA detour :" (Read-Hex ($mb + 0x38A860) 14)
Write-Host "HookB        :" (Read-Hex ($mb + 0x38B2FD) 6)
Write-Host "HookC detour :" (Read-Hex ($mb + 0x216C9C) 14)
Write-Host "HookD detour :" (Read-Hex ($mb + 0x216B46) 14)
Write-Host "StubA head   :" (Read-Hex $stub 24)
Write-Host "StubC head   :" (Read-Hex ($stub + 176) 30)
Write-Host "StubD head   :" (Read-Hex ($stub + 368) 24)
Write-Host "Stub flags   :" (Read-Hex ($stub + 560) 22)
[MemProbe]::CloseHandle($h) | Out-Null