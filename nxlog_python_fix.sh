#!/bin/bash

# This fix was taken from the following Gitlab issue
# https://gitlab.com/nxlog-public/nxlog-ce/-/issues/?sort=created_date&state=all&search=python&first_page_size=20&show=eyJpaWQiOiIzOCIsImZ1bGxfcGF0aCI6Im54bG9nLXB1YmxpYy9ueGxvZy1jZSIsImlkIjoxNTIxOTQ0OTV9

SOURCE_FILE="nxlog-ce-build/src/modules/extension/python/libnxpython.c"

# Get Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

echo "[INFO] Detected Python version: $PYTHON_MAJOR.$PYTHON_MINOR"

# Check if Python is >= 3.11
if [[ "$PYTHON_MAJOR" -gt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -ge 11 ]]; }; then
    if grep -q "PyFrame_GetCode" "$SOURCE_FILE"; then
        echo "[INFO] Patch already present. No action needed."
    else
        echo "[INFO] Python >= 3.11 detected. Patching $SOURCE_FILE..."
        cp "$SOURCE_FILE" "${SOURCE_FILE}.bak"

        sed -i \
            -e 's/frame->f_code/PyFrame_GetCode(frame)/g' \
            -e 's/frame->f_back/PyFrame_GetBack(frame)/g' \
            -e 's/frame->f_lasti/PyFrame_GetLasti(frame)/g' \
            "$SOURCE_FILE"

        echo "[INFO] Patch applied successfully."
    fi
else
    echo "[INFO] Python version < 3.11. Skipping patch."
fi
