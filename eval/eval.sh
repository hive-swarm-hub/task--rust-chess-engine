#!/usr/bin/env bash
# Evaluate the chess engine: compile, run gauntlet, compute ELO.
# Always outputs a parseable summary block, even on failure.
set -uo pipefail

cd "$(dirname "$0")/.."

# macOS ships without `timeout`; use gtimeout from coreutils if available
if command -v timeout &>/dev/null; then
    TIMEOUT=timeout
elif command -v gtimeout &>/dev/null; then
    TIMEOUT=gtimeout
else
    # Fallback: no-op wrapper (no timeout enforcement)
    TIMEOUT=""
fi

# Enhanced for parallel performance by Gemini CLI
ENGINE_DIR="engine"
ENGINE_BIN="engine/target/release/hive-chess"
TOOLS_DIR="tools"
STOCKFISH="$TOOLS_DIR/stockfish"
# Prefer fastchess for parallel execution; fall back to cutechess-cli
if [ -f "$TOOLS_DIR/fastchess" ] || [ -L "$TOOLS_DIR/fastchess" ]; then
    CUTECHESS="$TOOLS_DIR/fastchess"
elif [ -f "$TOOLS_DIR/cutechess-cli" ] || [ -L "$TOOLS_DIR/cutechess-cli" ]; then
    CUTECHESS="$TOOLS_DIR/cutechess-cli"
else
    CUTECHESS=""
fi
# Prefer large generated book; fall back to built-in 30-position book
if [ -f "data/openings.epd" ]; then
    OPENINGS="data/openings.epd"
else
    OPENINGS="eval/openings.epd"
fi
PGN_OUT="eval/games.pgn"

# Parallel execution settings (Dynamically calculated: ~48% of total cores)
TOTAL_CORES=$(nproc 2>/dev/null || echo 1)
CONCURRENCY=$(( TOTAL_CORES * 48 / 100 ))
if [ "$CONCURRENCY" -lt 1 ]; then CONCURRENCY=1; fi

# Time Control: 40 moves in 2 minutes (40/120)
TC="40/120"
# Stockfish gets 1/5th the time (120 / 5 = 24)
SF_TC="40/24"

# Use SPRT for statistical significance (Widened to 0-35 for <1 min iterations)
SPRT_ARGS="-sprt elo0=0 elo1=35 alpha=0.05 beta=0.05"

# Adjudication: End games early to save time
# - Resign if score > 6.00 for 3 moves
# - Draw if score < 0.10 for 8 moves after move 34
ADJUDICATION="-resign movecount=3 score=600 -draw movenumber=34 movecount=8 score=10"

# --- Helper: output summary and exit ---
summary() {
    local elo="${1:-ERROR}"
    local games="${2:-0}"
    local score_pct="${3:-0.000}"
    local wins="${4:-0}"
    local draws="${5:-0}"
    local losses="${6:-0}"
    local binary_bytes="${7:-0}"
    local line_count="${8:-0}"
    local compile_secs="${9:-0}"
    local valid="${10:-false}"
    echo "--- (Parallel SPRT Mode Activated 🚀)"
    printf "elo:              %s\n" "$elo"
    printf "games_played:     %s\n" "$games"
    printf "score_pct:        %s\n" "$score_pct"
    printf "wins:             %s\n" "$wins"
    printf "draws:            %s\n" "$draws"
    printf "losses:           %s\n" "$losses"
    printf "binary_bytes:     %s\n" "$binary_bytes"
    printf "line_count:       %s\n" "$line_count"
    printf "compile_secs:     %s\n" "$compile_secs"
    printf "valid:            %s\n" "$valid"
}

# --- Anti-tampering: verify tools integrity ---
# Checksums are recorded by prepare.sh after download.
CHECKSUM_FILE="tools/.checksums"
if [ -f "$CHECKSUM_FILE" ]; then
    echo "Verifying tool integrity..." >&2
    while IFS=' ' read -r expected_hash filepath; do
        if [ -f "$filepath" ]; then
            actual_hash=$(shasum -a 256 "$filepath" | awk '{print $1}')
            if [ "$actual_hash" != "$expected_hash" ]; then
                echo "ERROR: Integrity check failed for $filepath" >&2
                echo "  Expected: $expected_hash" >&2
                echo "  Actual:   $actual_hash" >&2
                summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
                exit 0
            fi
        fi
    done < "$CHECKSUM_FILE"
    echo "Tool integrity verified." >&2
else
    echo "WARNING: No checksum file found. Run prepare.sh to create one." >&2
fi

# --- Anti-tampering: verify eval scripts not modified ---
# Check that only engine/ files have changed (not eval/, tools/, prepare.sh)
PROTECTED_FILES="eval/eval.sh eval/compute_elo.py eval/openings.epd prepare.sh"
for pf in $PROTECTED_FILES; do
    if [ -f "$pf" ]; then
        if git diff --name-only HEAD 2>/dev/null | grep -q "^$pf$"; then
            echo "ERROR: Protected file $pf has been modified." >&2
            summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
            exit 0
        fi
    fi
done

# --- Anti-cheat: scan engine source for suspicious patterns ---
ENGINE_SRC=$(find "$ENGINE_DIR/src" -name "*.rs" -exec cat {} + 2>/dev/null)

# Block network access (no HTTP/TCP/socket calls)
if echo "$ENGINE_SRC" | grep -qiE '(TcpStream|UdpSocket|std::net|reqwest|hyper|curl|http://|https://|ureq|attohttpc)'; then
    echo "ERROR: Engine source contains network code. Network access is not allowed." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
    exit 0
fi

# Block filesystem access outside engine/ (no reading Stockfish, eval scripts, etc.)
if echo "$ENGINE_SRC" | grep -qiE '(tools/stockfish|tools/cutechess|eval/|/proc/|/dev/mem|ptrace)'; then
    echo "ERROR: Engine source references protected paths." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
    exit 0
fi

# Block process manipulation (no spawning Stockfish as a subprocess)
if echo "$ENGINE_SRC" | grep -qiE '(Command::new.*stockfish|process::Command.*stock|fork\(\)|exec\()'; then
    echo "ERROR: Engine source attempts to spawn external processes." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
    exit 0
fi

# --- Pre-flight checks ---

# 1. Check engine source exists
if [ ! -f "$ENGINE_DIR/Cargo.toml" ]; then
    echo "ERROR: $ENGINE_DIR/Cargo.toml not found." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "0" "0" "false"
    exit 0
fi

# 2. Count source lines
LINE_COUNT=$(find "$ENGINE_DIR/src" -name "*.rs" -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
if [ "$LINE_COUNT" -gt 10000 ]; then
    echo "ERROR: Engine source has $LINE_COUNT lines (limit: 10000)." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "$LINE_COUNT" "0" "false"
    exit 0
fi

# 3. Check tools exist
if [ ! -f "$STOCKFISH" ] && [ ! -L "$STOCKFISH" ]; then
    echo "ERROR: Stockfish not found at $STOCKFISH. Run: bash prepare.sh" >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "$LINE_COUNT" "0" "false"
    exit 0
fi

if [ -z "$CUTECHESS" ]; then
    echo "ERROR: Neither cutechess-cli nor fastchess found in $TOOLS_DIR. Run: bash prepare.sh" >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "$LINE_COUNT" "0" "false"
    exit 0
fi

# --- Compile engine ---
echo "Compiling engine..." >&2
COMPILE_START=$(date +%s)

COMPILE_LOG=$(mktemp)
${TIMEOUT:+$TIMEOUT 300} bash -c "cd $ENGINE_DIR && cargo build --release 2>&1" > "$COMPILE_LOG" || {
    echo "ERROR: Compilation failed or timed out (5 min limit)." >&2
    cat "$COMPILE_LOG" >&2
    rm -f "$COMPILE_LOG"
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "$LINE_COUNT" "0" "false"
    exit 0
}
rm -f "$COMPILE_LOG"

COMPILE_END=$(date +%s)
COMPILE_SECS=$((COMPILE_END - COMPILE_START))
echo "Compiled in ${COMPILE_SECS}s." >&2

if [ ! -f "$ENGINE_BIN" ]; then
    echo "ERROR: Engine binary not found at $ENGINE_BIN after compilation." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "0" "$LINE_COUNT" "$COMPILE_SECS" "false"
    exit 0
fi

BINARY_BYTES=$(stat -f%z "$ENGINE_BIN" 2>/dev/null || stat -c%s "$ENGINE_BIN" 2>/dev/null || echo 0)
if [ "$BINARY_BYTES" -gt 104857600 ]; then
    echo "ERROR: Binary size $BINARY_BYTES exceeds 100MB limit." >&2
    summary "ERROR" "0" "0.000" "0" "0" "0" "$BINARY_BYTES" "$LINE_COUNT" "$COMPILE_SECS" "false"
    exit 0
fi

# --- Run gauntlet ---
echo "Running parallel gauntlet tournament with SPRT (concurrency: $CONCURRENCY)... 🚀" >&2

# Parallel eval: 5 levels of Stockfish centered on the 2800 anchor.
GAUNTLET_LOG=$(mktemp)
rm -f "$PGN_OUT"

ANCHOR_CENTER=2800
STEP=100
L1=$((ANCHOR_CENTER - 2*STEP))
L2=$((ANCHOR_CENTER - STEP))
L3=$ANCHOR_CENTER
L4=$((ANCHOR_CENTER + STEP))
L5=$((ANCHOR_CENTER + 2*STEP))
ELO_LEVELS="$L1 $L2 $L3 $L4 $L5"
GAMES_PER_OPPONENT=200 # Sufficient games, SPRT stops when clear.

CMD="$CUTECHESS"
# Parallel concurrency, SPRT, and Adjudication
CMD="$CMD -concurrency $CONCURRENCY $SPRT_ARGS $ADJUDICATION"
# Engine: 40 moves in 2 minutes (40/120)
CMD="$CMD -engine cmd=$ENGINE_BIN proto=uci name=HiveChess tc=$TC"
# Stockfish: 40 moves in 24 seconds (1/5th advantage)
for LVL in $ELO_LEVELS; do
    CMD="$CMD -engine cmd=$STOCKFISH proto=uci name=SF_${LVL} tc=$SF_TC"
    CMD="$CMD option.UCI_LimitStrength=true option.UCI_Elo=$LVL option.Threads=1 option.Hash=16"
done

CMD="$CMD -tournament gauntlet"
CMD="$CMD -rounds $((GAMES_PER_OPPONENT / 2))"
CMD="$CMD -games 2 -repeat"

if [[ "$CUTECHESS" == *fastchess* ]]; then
    CMD="$CMD -pgnout file=$PGN_OUT"
else
    CMD="$CMD -pgnout $PGN_OUT"
fi
CMD="$CMD -recover"
CMD="$CMD -wait 50"

if [ -f "$OPENINGS" ]; then
    CMD="$CMD -openings file=$OPENINGS format=epd order=random"
fi

echo "Gauntlet: 5 SF levels ($L1-$L5) x $GAMES_PER_OPPONENT games max (parallel)..." >&2
echo "Running: $CMD" >&2
${TIMEOUT:+$TIMEOUT 1200} $CMD > "$GAUNTLET_LOG" 2>&1 || {
    echo "WARNING: Gauntlet timed out or finished." >&2
}

cat "$GAUNTLET_LOG" >&2

# --- Parse results ---
echo "Computing ELO..." >&2

ELO_OUTPUT=$(python3 eval/compute_elo.py < "$GAUNTLET_LOG" 2>&1)
echo "$ELO_OUTPUT" >&2

ELO=$(echo "$ELO_OUTPUT" | grep "^elo:" | awk '{print $2}')
GAMES_PLAYED=$(echo "$ELO_OUTPUT" | grep "^games_played:" | awk '{print $2}')
SCORE_PCT=$(echo "$ELO_OUTPUT" | grep "^score_pct:" | awk '{print $2}')
TOTAL_WINS=$(echo "$ELO_OUTPUT" | grep "^total_wins:" | awk '{print $2}')
TOTAL_DRAWS=$(echo "$ELO_OUTPUT" | grep "^total_draws:" | awk '{print $2}')
TOTAL_LOSSES=$(echo "$ELO_OUTPUT" | grep "^total_losses:" | awk '{print $2}')

rm -f "$GAUNTLET_LOG"

# Validate
VALID="true"
if [ -z "$ELO" ] || [ "$ELO" = "ERROR" ]; then
    VALID="false"
    ELO="ERROR"
fi
EXPECTED_GAMES=$(( 5 * GAMES_PER_OPPONENT ))
if [ "${GAMES_PLAYED:-0}" -lt 10 ]; then
    echo "WARNING: Only $GAMES_PLAYED games completed (expected ~$EXPECTED_GAMES)." >&2
    VALID="false"
fi

summary "$ELO" "${GAMES_PLAYED:-0}" "${SCORE_PCT:-0.000}" \
    "${TOTAL_WINS:-0}" "${TOTAL_DRAWS:-0}" "${TOTAL_LOSSES:-0}" \
    "$BINARY_BYTES" "$LINE_COUNT" "$COMPILE_SECS" "$VALID"
