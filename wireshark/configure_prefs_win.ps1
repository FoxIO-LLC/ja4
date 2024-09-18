# Define the file path
$filePath = "$env:APPDATA\Wireshark\preferences"

# Backup the original file
$backupFilePath = "$filePath.bak"
Copy-Item $filePath $backupFilePath -Force

# Read the file content
$content = Get-Content $filePath

# Define the start and end of the block to replace
$startBlock = '# Packet list column format'
$endBlock = 'Info", "%i"'

# Flag to track whether we are inside the block to replace
$insideBlock = $false

# Store the new content
$newContent = @()

foreach ($line in $content) {
    # If we find the start of the block, mark the flag
    if ($line -eq $startBlock) {
        $insideBlock = $true
        # Add the new block content
        $newContent += @(
            '# Packet list column format',
            '# Each pair of strings consists of a column title and its format',
            'gui.column.format: ',
            '    "No.", "%m",',
            '    "Time", "%t",',
            '    "Source", "%s",',
            '    "Destination", "%d",',
            '    "Protocol", "%p",',
            '    "Length", "%L",',
            '    "Info", "%i",',
            '    "JA4T", "%Cus:ja4.ja4t:0:R",',
            '    "JA4TS", "%Cus:ja4.ja4ts:0:R",',
            '    "JA4", "%Cus:tls.handshake.ja4:0:R",',
            '    "JA4S", "%Cus:ja4.ja4s:0:R",',
            '    "JA4H", "%Cus:ja4.ja4h:0:R",',
            '    "JA4L", "%Cus:ja4.ja4l:0:R",',
            '    "JA4LS", "%Cus:ja4.ja4ls:0:R",',
            '    "JA4X", "%Cus:ja4.ja4x:0:R",',
            '    "JA4SSH", "%Cus:ja4.ja4ssh:0:R"'
        )
        continue
    }

    # If we are at the end of the block, reset the flag and skip the old block
    if ($insideBlock -and $line -eq $endBlock) {
        $insideBlock = $false
        continue
    }

    # If we're not inside the block, keep the original content
    if (-not $insideBlock) {
        $newContent += $line
    }
}

# Write the new content back to the file
$newContent | Set-Content -Path $filePath

Write-Host "Text replacement completed successfully."
