#!/bin/bash
# Version Bump Script
# Usage: ./scripts/bump-version.sh [major|minor|patch]

set -e

CARGO_TOML="Cargo.toml"

# Get current version from workspace
CURRENT_VERSION=$(grep -A5 '\[workspace.package\]' "$CARGO_TOML" | grep 'version' | head -1 | sed 's/.*= "\(.*\)"/\1/')

if [ -z "$CURRENT_VERSION" ]; then
    echo "Error: Could not find version in $CARGO_TOML"
    exit 1
fi

echo "Current version: $CURRENT_VERSION"

# Parse version parts
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Determine bump type
BUMP_TYPE="${1:-patch}"

case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "Usage: $0 [major|minor|patch]"
        exit 1
        ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
echo "New version: $NEW_VERSION"

# Update version in root Cargo.toml
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
else
    # Linux
    sed -i "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
fi

echo "Updated $CARGO_TOML"

# Verify change
NEW_CHECK=$(grep -A5 '\[workspace.package\]' "$CARGO_TOML" | grep 'version' | head -1)
echo "Verification: $NEW_CHECK"

# Optional: Create git tag
read -p "Create git tag v$NEW_VERSION? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git add "$CARGO_TOML"
    git commit -m "chore: bump version to $NEW_VERSION"
    git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
    echo "Created tag v$NEW_VERSION"
    echo "Run 'git push && git push --tags' to publish"
fi
