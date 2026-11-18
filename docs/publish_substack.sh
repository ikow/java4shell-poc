#!/usr/bin/env bash
# Publish Java4Shell article to Substack
# Usage: ./publish_substack.sh <substack.sid cookie value>
#
# To get the cookie:
#   1. Open qideng.substack.com in Chrome
#   2. DevTools (F12) → Application → Cookies → substack.com
#   3. Copy the "substack.sid" value (starts with "s:")
#   4. Run: ./publish_substack.sh "s:XXXX.YYYY"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HTML_FILE="${SCRIPT_DIR}/substack_article_v2.html"
COVER_IMAGE="${SCRIPT_DIR}/cover.png"
PUBLICATION="qideng"  # qideng.substack.com

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <substack.sid cookie value>"
    echo ""
    echo "Get the cookie from Chrome DevTools:"
    echo "  1. Open https://qideng.substack.com"
    echo "  2. F12 → Application → Cookies → substack.com"
    echo "  3. Copy 'substack.sid' value"
    exit 1
fi

SID="$1"
# URL-encode the cookie value for curl
SID_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SID', safe=''))")

BASE="https://${PUBLICATION}.substack.com"
COOKIE="substack.sid=${SID_ENCODED}"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

echo -e "${CYAN}Java4Shell Substack Publisher${NC}"
echo ""

# Step 1: Verify session
echo -e "${CYAN}[1/5] Verifying session...${NC}"
USER_INFO=$(curl -s -H "Cookie: ${COOKIE}" -H "User-Agent: ${UA}" \
  "${BASE}/api/v1/user/self" 2>&1)

if echo "$USER_INFO" | grep -q "Not authorized"; then
    echo -e "${RED}Session expired. Get a fresh cookie from Chrome DevTools.${NC}"
    exit 1
fi

USER_NAME=$(echo "$USER_INFO" | python3 -c "import json,sys; print(json.load(sys.stdin).get('name','unknown'))" 2>/dev/null || echo "unknown")
echo -e "${GREEN}  Logged in as: ${USER_NAME}${NC}"

# Step 2: Get publication ID
echo -e "${CYAN}[2/5] Getting publication info...${NC}"
PUB_INFO=$(curl -s -H "Cookie: ${COOKIE}" -H "User-Agent: ${UA}" \
  "${BASE}/api/v1/publication/for-subdomain/${PUBLICATION}" 2>&1)

PUB_ID=$(echo "$PUB_INFO" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [[ -z "$PUB_ID" ]]; then
    echo -e "${RED}  Could not find publication ID${NC}"
    exit 1
fi
echo -e "${GREEN}  Publication ID: ${PUB_ID}${NC}"

# Step 3: Upload cover image
echo -e "${CYAN}[3/5] Uploading cover image...${NC}"
if [[ -f "$COVER_IMAGE" ]]; then
    UPLOAD_RESP=$(curl -s -X POST \
      -H "Cookie: ${COOKIE}" \
      -H "User-Agent: ${UA}" \
      -F "image=@${COVER_IMAGE}" \
      "${BASE}/api/v1/image" 2>&1)

    COVER_URL=$(echo "$UPLOAD_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('url',''))" 2>/dev/null || echo "")
    if [[ -n "$COVER_URL" ]]; then
        echo -e "${GREEN}  Cover uploaded: ${COVER_URL}${NC}"
    else
        echo -e "${RED}  Cover upload failed: ${UPLOAD_RESP}${NC}"
        COVER_URL=""
    fi
else
    echo "  No cover image found at ${COVER_IMAGE}"
    COVER_URL=""
fi

# Step 4: Extract HTML body content
echo -e "${CYAN}[4/5] Preparing article content...${NC}"
BODY_HTML=$(python3 -c "
import re
with open('${HTML_FILE}') as f:
    content = f.read()
# Extract body content
match = re.search(r'<body>(.*)</body>', content, re.DOTALL)
if match:
    body = match.group(1).strip()
    # Remove HTML comments
    body = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL).strip()
    print(body)
")

TITLE="Java4Shell: From AVX-512 Integer Underflow to Pre-Auth Heap Corruption in Keycloak, Jenkins, and Elasticsearch"
SUBTITLE="CVE-2026-114938 — We built the full exploit chain: JIT compilation, heap grooming, JavaBleed disclosure, and tested it against three production applications in default configs. Here's exactly how it works."

echo "  Title: ${TITLE:0:80}..."
echo "  Body size: $(echo "$BODY_HTML" | wc -c | tr -d ' ') bytes"

# Step 5: Create draft post
echo -e "${CYAN}[5/5] Creating draft post...${NC}"

# Build the JSON payload
PAYLOAD=$(python3 -c "
import json

body_html = '''$(echo "$BODY_HTML" | sed "s/'/\\\\'/g")'''

payload = {
    'type': 'newsletter',
    'draft_title': '''${TITLE}''',
    'draft_subtitle': '''${SUBTITLE}''',
    'draft_body': body_html,
    'audience': 'everyone',
}

cover_url = '${COVER_URL}'
if cover_url:
    payload['cover_image'] = cover_url

print(json.dumps(payload))
")

DRAFT_RESP=$(curl -s -X POST \
  -H "Cookie: ${COOKIE}" \
  -H "User-Agent: ${UA}" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "${BASE}/api/v1/drafts" 2>&1)

DRAFT_ID=$(echo "$DRAFT_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id', d.get('draft_id','')))" 2>/dev/null || echo "")

if [[ -n "$DRAFT_ID" ]]; then
    echo -e "${GREEN}  Draft created: ID=${DRAFT_ID}${NC}"
    echo ""
    echo -e "${GREEN}Article draft ready!${NC}"
    echo -e "  Edit: ${BASE}/publish/post/${DRAFT_ID}"
    echo ""
    echo "Next steps:"
    echo "  1. Open the edit link above"
    echo "  2. Add the free paywall where you want it"
    echo "  3. Preview → Publish"
else
    echo -e "${RED}  Draft creation failed${NC}"
    echo "  Response: ${DRAFT_RESP:0:500}"
    echo ""
    echo "Fallback: manual import"
    echo "  1. Open ${BASE}/publish/post"
    echo "  2. Click ⋮ → Import or switch to HTML mode"
    echo "  3. Paste contents of: ${HTML_FILE}"
fi
