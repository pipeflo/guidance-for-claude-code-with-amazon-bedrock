#!/bin/bash
# Claude Code Authentication Installer (generic)

set -e

echo "======================================"
echo "Claude Code Authentication Installer"
echo "======================================"
echo

# Check prerequisites
echo "Checking prerequisites..."
HAS_ERRORS=false

if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is not installed"
    echo "       Please install from https://aws.amazon.com/cli/"
    HAS_ERRORS=true
fi

if [ ! -f "config.json" ]; then
    echo "ERROR: config.json not found in current directory"
    echo "       Make sure you are running this from the extracted package folder"
    HAS_ERRORS=true
fi

PYTHON=""
if command -v python3 &> /dev/null; then
    PYTHON="python3"
elif command -v python &> /dev/null; then
    PYTHON="python"
else
    echo "ERROR: Python is not installed (python3 or python)"
    echo "       Python is needed to parse configuration files"
    HAS_ERRORS=true
fi

if [ "$HAS_ERRORS" = "true" ]; then
    exit 1
fi

if [ ! -f "claude-settings/settings.json" ]; then
    echo "WARNING: claude-settings/settings.json not found"
    echo "         Claude Code IDE settings will not be configured automatically"
    echo ""
fi

echo "OK Prerequisites validated"

# Detect platform and architecture
echo
echo "Detecting platform and architecture..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    ARCH=$(uname -m)
    if [[ "$ARCH" == "arm64" ]]; then
        echo "Detected macOS ARM64 (Apple Silicon)"
        BINARY_SUFFIX="macos-arm64"
    else
        echo "Detected macOS Intel"
        BINARY_SUFFIX="macos-intel"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    ARCH=$(uname -m)
    if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
        echo "Detected Linux ARM64"
        BINARY_SUFFIX="linux-arm64"
    else
        echo "Detected Linux x64"
        BINARY_SUFFIX="linux-x64"
    fi
else
    echo "Unsupported platform: $OSTYPE"
    echo "   This installer supports macOS and Linux only."
    exit 1
fi

CREDENTIAL_BINARY="credential-process-$BINARY_SUFFIX"
OTEL_BINARY="otel-helper-$BINARY_SUFFIX"

if [ ! -f "$CREDENTIAL_BINARY" ]; then
    echo "Binary not found for your platform: $CREDENTIAL_BINARY"
    echo "   Please ensure you have the correct package for your architecture."
    exit 1
fi

# Create directory
echo
echo "Installing authentication tools..."
mkdir -p ~/claude-code-with-bedrock

cp "$CREDENTIAL_BINARY" ~/claude-code-with-bedrock/credential-process
cp config.json ~/claude-code-with-bedrock/
chmod +x ~/claude-code-with-bedrock/credential-process

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo
    echo "macOS Keychain Access:"
    echo "   On first use, macOS will ask for permission to access the keychain."
    echo "   This is normal and required for secure credential storage."
    echo "   Click 'Always Allow' when prompted."
fi

# Copy Claude Code settings if present
if [ -d "claude-settings" ]; then
    echo
    echo "Installing Claude Code settings..."
    mkdir -p ~/.claude

    if [ -f "claude-settings/settings.json" ]; then
        if [ -f ~/.claude/settings.json ]; then
            echo "Existing Claude Code settings found"
            BACKUP_NAME="settings.json.backup-$(date +%Y%m%d-%H%M%S)"
            cp ~/.claude/settings.json ~/.claude/$BACKUP_NAME
            echo "  Backed up to: ~/.claude/$BACKUP_NAME"
            read -p "Overwrite with new settings? (Y/n): " -n 1 -r
            echo
            if [[ -z "$REPLY" ]]; then
                REPLY="y"
            fi
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Skipping Claude Code settings..."
                SKIP_SETTINGS=true
            fi
        fi

        if [ "$SKIP_SETTINGS" != "true" ]; then
            sed -e "s|__OTEL_HELPER_PATH__|$HOME/claude-code-with-bedrock/otel-helper|g" \
                -e "s|__CREDENTIAL_PROCESS_PATH__|$HOME/claude-code-with-bedrock/credential-process|g" \
                "claude-settings/settings.json" > ~/.claude/settings.json

            if grep -q '__CREDENTIAL_PROCESS_PATH__\|__OTEL_HELPER_PATH__' ~/.claude/settings.json 2>/dev/null; then
                echo "WARNING: Some path placeholders were not replaced in settings.json"
                echo "         You may need to edit the file manually: ~/.claude/settings.json"
            else
                echo "OK Claude Code settings configured: ~/.claude/settings.json"
            fi
        fi
    fi
fi

# Copy OTEL helper executable if present
if [ -f "$OTEL_BINARY" ]; then
    echo
    echo "Installing OTEL helper..."
    cp "$OTEL_BINARY" ~/claude-code-with-bedrock/otel-helper
    chmod +x ~/claude-code-with-bedrock/otel-helper
    echo "OTEL helper installed"
fi

# Update AWS config
echo
echo "Configuring AWS profiles..."
mkdir -p ~/.aws

PROFILES=$($PYTHON -c "import json; profiles = list(json.load(open('config.json')).keys()); print(' '.join(profiles))")

if [ -z "$PROFILES" ]; then
    echo "No profiles found in config.json"
    exit 1
fi

echo "Found profiles: $PROFILES"
echo

# Read default region from config.json (first profile's aws_region)
DEFAULT_REGION=$($PYTHON -c "
import json
c = json.load(open('config.json'))
p = list(c.keys())[0]
print(c[p].get('aws_region', 'us-east-1'))
")

for PROFILE_NAME in $PROFILES; do
    echo "Configuring AWS profile: $PROFILE_NAME"

    sed -i.bak "/\[profile $PROFILE_NAME\]/,/^$/d" ~/.aws/config 2>/dev/null || true

    PROFILE_REGION=$($PYTHON -c "
import json
print(json.load(open('config.json')).get('$PROFILE_NAME', {}).get('aws_region', '$DEFAULT_REGION'))
")

    cat >> ~/.aws/config << EOF
[profile $PROFILE_NAME]
credential_process = $HOME/claude-code-with-bedrock/credential-process --profile $PROFILE_NAME
region = $PROFILE_REGION
EOF
    echo "  Created AWS profile '$PROFILE_NAME'"
done

# Optional: install shell-function wrapper for GDPR per-zone isolation.
# Only runs when the bundle was packaged with enforce_project_isolation=true
# (so the config.json has the zone_inference_profiles mapping). On other
# installs this block is a no-op and nothing touches the user's rc files.
FIRST_PROFILE=$(echo $PROFILES | awk '{print $1}')
ISOLATION_ON=$($PYTHON -c "
import json
c = json.load(open('config.json')).get('$FIRST_PROFILE', {})
print('yes' if c.get('enforce_project_isolation') else 'no')
")
if [ "$ISOLATION_ON" = "yes" ]; then
    echo
    echo "Installing Claude Code wrapper for per-zone inference profile isolation..."
    WRAPPER_FILE="$HOME/claude-code-with-bedrock/claude-wrapper.sh"

    # Build a portable shell source that:
    #   * unsets any stale ANTHROPIC_MODEL* from prior ccwb installs
    #   * extracts the Zone tag via `credential-process --get-tag Zone`
    #   * picks the right application-inference-profile ARN via a case
    #     statement generated from config.json.zone_inference_profiles
    #   * exec's claude with ANTHROPIC_MODEL set for just this invocation
    $PYTHON - <<PYEOF > "$WRAPPER_FILE"
import json
cfg = json.load(open('config.json'))
prof_name = list(cfg.keys())[0]
prof = cfg[prof_name]
short = prof.get('model_short_name', 'opus-4-6')
zmap = prof.get('zone_inference_profiles', {}) or {}
print('# Generated by ccwb install.sh. Do not edit by hand.')
print('# Regenerated on every re-install. Safe to source multiple times.')
print('')
print('unset ANTHROPIC_MODEL ANTHROPIC_SMALL_FAST_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL')
print('')
print('claude() {')
# IMPORTANT: do NOT combine `local` with command-substitution assignment.
# `local x="$(cmd)"` returns local's exit code (always 0), hiding cmd's
# real exit status. Declare locals first, then assign separately, and
# always quote the variable in the test (otherwise an empty expansion
# produces `[ -ne 0 ]` which bash rejects with "unary operator expected").
print('  local zone arn')
print('  zone="$("$HOME/claude-code-with-bedrock/credential-process" --profile ' + prof_name + ' --get-tag Zone 2>/dev/null)"')
print('  if [ -z "$zone" ]; then')
print('    echo "Claude Code: no Zone assignment found on your Okta token." >&2')
print('    echo "Ask your administrator to add you to a ' + prof_name + '-<zone>-<project> group," >&2')
print('    echo "or run \\\`aws sts get-caller-identity\\\` to trigger a fresh login." >&2')
print('    return 1')
print('  fi')
print('  case "$zone" in')
for zone, models in sorted(zmap.items()):
    arn = models.get(short)
    if arn:
        print(f'    {zone}) arn={json.dumps(arn)} ;;')
print('    *)')
print('      echo "Claude Code: zone \\"$zone\\" has no inference profile mapping." >&2')
print('      echo "Ask your administrator to run \\\`ccwb inference-profile create --zone $zone --model ' + short + '\\\`." >&2')
print('      return 1')
print('      ;;')
print('  esac')
print('  ANTHROPIC_MODEL="$arn" command claude "$@"')
print('}')
PYEOF

    for rc in ~/.zshrc ~/.bashrc; do
        [ -f "$rc" ] || continue
        if ! grep -q "ccwb claude wrapper" "$rc" 2>/dev/null; then
            cat >> "$rc" <<RCEOF

# >>> ccwb claude wrapper >>>
# GDPR per-zone inference-profile isolation. Managed by ccwb install.sh;
# remove this block by re-running install.sh (it regenerates the sourced
# file) or run \`ccwb cleanup\` to uninstall the whole ccwb setup.
[ -f "$WRAPPER_FILE" ] && . "$WRAPPER_FILE"
# <<< ccwb claude wrapper <<<
RCEOF
            echo "  Added ccwb claude wrapper block to $rc"
        else
            echo "  ccwb claude wrapper block already present in $rc (wrapper file refreshed)"
        fi
    done

    echo "  Wrapper written to $WRAPPER_FILE"
    echo "  Restart your shell or run: source ~/.zshrc  (or ~/.bashrc)"
fi

# Post-install validation
echo
echo "Validating installation..."
if [ -f ~/claude-code-with-bedrock/credential-process ]; then
    echo "  OK credential-process: ~/claude-code-with-bedrock/credential-process"
else
    echo "  FAIL credential-process not found at: ~/claude-code-with-bedrock/credential-process"
fi
if [ -f ~/.claude/settings.json ]; then
    echo "  OK settings.json: ~/.claude/settings.json"
else
    echo "  WARN settings.json not found at: ~/.claude/settings.json"
fi

echo
echo "======================================"
echo "Installation complete!"
echo "======================================"
echo
echo "Available profiles:"
for PROFILE_NAME in $PROFILES; do
    echo "  - $PROFILE_NAME"
done
echo
echo "To use Claude Code authentication:"
echo "  export AWS_PROFILE=<profile-name>"
echo "  aws sts get-caller-identity"
echo
FIRST_PROFILE=$(echo $PROFILES | awk '{print $1}')
echo "Example:"
echo "  export AWS_PROFILE=$FIRST_PROFILE"
echo "  aws sts get-caller-identity"
echo
echo "Note: Authentication will automatically open your browser when needed."
echo
