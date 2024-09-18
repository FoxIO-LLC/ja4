#!/bin/bash

# Define the file path
filePath="$HOME/.config/wireshark/preferences"

# Define the old and new text blocks
oldText=$(cat <<'EOF'
# Packet list column format
# Each pair of strings consists of a column title and its format
gui.column.format: 
	"No.", "%m",
	"Time", "%t",
	"Source", "%s",
	"Destination", "%d",
	"Protocol", "%p",
	"Length", "%L",
	"Info", "%i"
EOF
)

newText=$(cat <<'EOF'
# Packet list column format
# Each pair of strings consists of a column title and its format
gui.column.format: 
	"No.", "%m",
	"Time", "%t",
	"Source", "%s",
	"Destination", "%d",
	"Protocol", "%p",
	"Length", "%L",
	"Info", "%i",
	"JA4T", "%Cus:ja4.ja4t:0:R",
	"JA4TS", "%Cus:ja4.ja4ts:0:R",
	"JA4", "%Cus:tls.handshake.ja4:0:R",
	"JA4S", "%Cus:ja4.ja4s:0:R",
	"JA4H", "%Cus:ja4.ja4h:0:R",
	"JA4L", "%Cus:ja4.ja4l:0:R",
	"JA4LS", "%Cus:ja4.ja4ls:0:R",
	"JA4X", "%Cus:ja4.ja4x:0:R",
	"JA4SSH", "%Cus:ja4.ja4ssh:0:R"
EOF
)

# Backup the original preferences file
cp "$filePath" "$filePath.bak"

# Replace the old text block with the new text block in the preferences file
if grep -qF "$oldText" "$filePath"; then
    sed -i '' "s|$oldText|$newText|" "$filePath"
    echo "Preferences updated successfully."
else
    echo "Old text block not found in preferences."
fi
