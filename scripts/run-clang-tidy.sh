#!/bin/bash

CLICKHOUSE_INCLUDE="-I$(pwd)/utils/clickhouse-cpp"

detect_clang_tidy() {
    if command -v "clang-tidy" &> /dev/null; then
        echo "clang-tidy"
        return 0
    fi
    
    for cmd in $(compgen -c | grep -E "^clang-tidy-[0-9]+$" | sort -r); do
        echo "$cmd"
        return 0
    done
    
    echo ""
    return 1
}

main() {
    CLANG_TIDY=$(detect_clang_tidy)
    
    if [ -z "$CLANG_TIDY" ]; then
        echo "Error: clang-tidy not found. Please install clang-tidy."
        exit 1
    fi
    
    echo "Using $CLANG_TIDY"
    
    if [ -n "$1" ]; then
        CPP_FILES="$1"
    else
        CPP_FILES=$(find utils -name "*.cc" -o -name "*.cpp" -o -name "*.hh" -o -name "*.hpp" -o -name "*.h" \
    |   grep -v "clickhouse-cpp" \
    |   xargs grep -L "clickhouse/")
    fi
    
    for file in $CPP_FILES; do
        echo "Checking $file..."
        $CLANG_TIDY "$file" --config-file=./.clang-tidy -- \
            -std=c++20  -stdlib=libc++
    done
}

main "$@"
