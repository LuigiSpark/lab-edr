#!/bin/bash
# Watch /tmp/malware and transfer any new file to Windows on close_write.
# Usage (in tmux on Kali): ~/lab/watch_and_transfer.sh

WATCH_DIR="/tmp/malware"

mkdir -p "$WATCH_DIR" "$WATCH_DIR/done" "$WATCH_DIR/failed"
echo "[watcher] Watching $WATCH_DIR..."

# %w%f: inotifywait outputs directory (%w) + filename (%f) as a full path
inotifywait -m -e close_write --format '%w%f' "$WATCH_DIR" |
while read -r filepath; do
    echo "[watcher] New file: $(basename "$filepath")"
    /usr/local/bin/send-malware.sh "$filepath" \
        && mv "$filepath" "$WATCH_DIR/done/" \
        || mv "$filepath" "$WATCH_DIR/failed/"
done
