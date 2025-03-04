#!/bin/bash

get_clang_includes() {
    local clang_version=$1
    local includes=""

    local include_paths=(
        "/usr/lib/llvm-$clang_version/include/c++/v1"
        "/usr/local/lib/clang/$clang_version/include"
        "/usr/lib/clang/$clang_version/include"
    )

    for path in "${include_paths[@]}"; do
        if [ -d "$path" ]; then
            includes="-isystem $path"
            break
        fi
    done

    includes+=" -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include"

    echo "$includes"
}

detect_clang_versions() {
    local versions=()
    for version in 14 11 10 9 8; do
        if command -v "clang-$version" &> /dev/null; then
            versions+=("$version")
        fi
    done
    echo "${versions[@]}"
}

main() {
    CLANG_VERSIONS=($(detect_clang_versions))

    if [ ${#CLANG_VERSIONS[@]} -eq 0 ]; then
        echo "No Clang versions found. Please install Clang."
        exit 1
    fi

    SELECTED_VERSION=${CLANG_VERSION:-${CLANG_VERSIONS[0]}}

    if [[ ! " ${CLANG_VERSIONS[@]} " =~ " $SELECTED_VERSION " ]]; then
        echo "Selected Clang version $SELECTED_VERSION is not available."
        echo "Available versions: ${CLANG_VERSIONS[*]}"
        exit 1
    fi

    if [ -n "$1" ]; then
        CPP_FILES="$1"
    else
        CPP_FILES=$(find utils -name "*.cc" -o -name "*.cpp" -o -name "*.hh" -o -name "*.hpp" -o -name "*.h" | grep -v "clickhouse-cpp")
    fi

    STD_INCLUDES=$(get_clang_includes "$SELECTED_VERSION")

    # Run clang-tidy
    for file in $CPP_FILES; do
        echo "Checking $file with Clang $SELECTED_VERSION..."
        clang-tidy-"$SELECTED_VERSION" "$file" --config-file=./.clang-tidy -- \
            -std=c++20 -I. $STD_INCLUDES -stdlib=libc++
    done

    # Sanitizer option
    if [[ "$1" == "--sanitize" ]]; then
        echo "Building with sanitizers for runtime memory checking..."
        cd utils
        make clean
        CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" make
    fi
}

main "$@"
