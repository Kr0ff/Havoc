#!/bin/bash

# Script: check_missing_semicolons.sh
# Purpose: Check for missing semicolons in C, C++, and Go files
# Usage: ./check_missing_semicolons.sh [file_or_directory]

set -euo pipefail

TARGET="${1:-.}"
ERRORS_FOUND=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Language detection based on file extension
detect_language() {
    local file="$1"
    case "$file" in
        *.go) echo "go" ;;
        *.c|*.h) echo "c" ;;
        *.cpp|*.cc|*.cxx|*.hpp|*.h++) echo "cpp" ;;
        *) return 1 ;;
    esac
}

# Check if line is part of a statement that needs semicolon
needs_semicolon() {
    local line="$1"
    
    # Remove leading whitespace for analysis
    local trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    # Skip empty lines
    [[ -z "$trimmed" ]] && return 1
    
    # Skip pure comment lines
    [[ "$trimmed" =~ ^// ]] && return 1
    [[ "$trimmed" =~ ^# ]] && return 1
    [[ "$trimmed" =~ ^/\* ]] && return 1
    [[ "$trimmed" =~ ^\* ]] && return 1
    [[ "$trimmed" =~ ^\*/ ]] && return 1
    
    # Already has semicolon
    [[ "$trimmed" =~ \;[[:space:]]*$ ]] && return 1
    
    # Preprocessor directives
    [[ "$trimmed" =~ ^#(include|define|if|ifdef|ifndef|endif|pragma|undef|else|elif|error|warning) ]] && return 1
    
    # Label declarations (ends with colon)
    [[ "$trimmed" =~ :[[:space:]]*$ ]] && return 1
    
    # Control structure keywords that start a block (if, while, for, do, switch, else, etc.)
    [[ "$trimmed" =~ ^if[[:space:]]*\( ]] && return 1
    [[ "$trimmed" =~ ^else([[:space:]]*if[[:space:]]*\(|[[:space:]]*$|\{) ]] && return 1
    [[ "$trimmed" =~ ^while[[:space:]]*\( ]] && return 1
    [[ "$trimmed" =~ ^do[[:space:]]*(\{|$) ]] && return 1
    [[ "$trimmed" =~ ^for[[:space:]]*\( ]] && return 1
    [[ "$trimmed" =~ ^switch[[:space:]]*\( ]] && return 1
    [[ "$trimmed" =~ ^case[[:space:]]+ ]] && return 1
    [[ "$trimmed" =~ ^default[[:space:]]*: ]] && return 1
    
    # Function/method declarations (contain ( and ) with { or no terminator)
    # Pattern: identifier(params) { or identifier(params) const {
    if [[ "$trimmed" =~ ^[a-zA-Z_][a-zA-Z0-9_:~]*[[:space:]]*\(.*\)[[:space:]]*(const)?[[:space:]]*\{[[:space:]]*$ ]]; then
        return 1
    fi
    
    # Lines ending with opening braces or parentheses
    [[ "$trimmed" =~ \{[[:space:]]*$ ]] && return 1
    [[ "$trimmed" =~ \([[:space:]]*$ ]] && return 1
    [[ "$trimmed" =~ \[[[:space:]]*$ ]] && return 1
    
    # Closing braces followed by control keywords
    [[ "$trimmed" =~ ^\}([[:space:]]|$|while|else|catch) ]] && return 1
    
    # Lines ending with comma or continuation
    [[ "$trimmed" =~ ,[[:space:]]*$ ]] && return 1
    [[ "$trimmed" =~ \\[[:space:]]*$ ]] && return 1
    
    # Operators at end of line
    [[ "$trimmed" =~ (\+|-|\*|/|=|&|\||!|<|>)[[:space:]]*$ ]] && return 1
    
    # Function declarations without body on same line (just the signature)
    # Pattern: return_type name(params) - no { and no ;
    if [[ "$trimmed" =~ ^(void|int|char|bool|long|short|unsigned|signed|float|double|struct|union|enum|const|static|virtual|inline|extern)[[:space:]]+ ]] && \
       [[ ! "$trimmed" =~ \{ ]] && \
       [[ ! "$trimmed" =~ = ]] && \
       [[ "$trimmed" =~ \) ]]; then
        # This looks like a function declaration without body
        return 1
    fi
    
    # Namespace/struct/class/enum/union declarations
    [[ "$trimmed" =~ ^(namespace|class|struct|union|enum|interface)[[:space:]]+ ]] && return 1
    
    # Macro definitions
    [[ "$trimmed" =~ ^#define[[:space:]]+ ]] && return 1
    
    # Type definitions and forward declarations without assignment
    if [[ "$trimmed" =~ ^(typedef|extern)[[:space:]]+ ]] && [[ ! "$trimmed" =~ = ]]; then
        return 1
    fi
    
    # At this point, if the line looks like actual code (not a control structure or declaration),
    # it should end with a semicolon
    # Valid statement indicators: assignment, function call, or statement keywords
    if [[ "$trimmed" =~ (=|;|\(.*\)|return|break|continue|goto|throw) ]]; then
        # This looks like it should have a semicolon
        return 0
    fi
    
    # If it's just a macro call like PUTS("...") or similar, it needs a semicolon
    if [[ "$trimmed" =~ ^[A-Z_]+[[:space:]]*\( ]] || \
       [[ "$trimmed" =~ ^[a-z_][a-z_0-9]*[[:space:]]*\(.*\)[[:space:]]*$ ]]; then
        return 0
    fi
    
    # Variable declarations or assignments
    if [[ "$trimmed" =~ ^(int|char|void|bool|float|double|long|short|unsigned|signed|const|static|auto|struct|union|enum)[[:space:]]+ ]]; then
        return 0
    fi
    
    # If no clear pattern matched, assume it doesn't need a semicolon (to reduce false positives)
    return 1
}

# Process a file
process_file() {
    local file="$1"
    local lang
    
    # Detect language
    lang=$(detect_language "$file") || return 0
    
    local line_num=0
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))
        
        if needs_semicolon "$line"; then
            echo -e "${RED}✗ Missing semicolon:${NC} $file:$line_num"
            echo "  $line"
            ((ERRORS_FOUND++))
        fi
    done < "$file"
}

# Main execution
if [[ -f "$TARGET" ]]; then
    # Single file
    process_file "$TARGET"
elif [[ -d "$TARGET" ]]; then
    # Directory (recursive)
    while IFS= read -r file; do
        process_file "$file"
    done < <(find "$TARGET" -type f \( -name "*.go" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" -o -name "*.hpp" -o -name "*.h++" \))
else
    echo "Error: '$TARGET' is not a valid file or directory" >&2
    exit 1
fi

# Summary
echo ""
if [[ $ERRORS_FOUND -eq 0 ]]; then
    echo -e "${GREEN}✓ No missing semicolons found!${NC}"
    exit 0
else
    echo -e "${RED}✗ Found $ERRORS_FOUND line(s) with missing semicolons${NC}"
    exit 1
fi
