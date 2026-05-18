#!/bin/bash
set -euo pipefail

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI Risk Platform — Build & Deploy
# 위치: ~/ai-risk-platform/deploy.sh
# 사용: ./deploy.sh [태그]
#   예: ./deploy.sh          → git SHA 기반 자동 태그
#       ./deploy.sh 0.4.0    → 수동 태그 지정
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ECR_REPO="106760547719.dkr.ecr.ap-northeast-2.amazonaws.com/ai-risk-platform"
REGION="ap-northeast-2"
NAMESPACE="ai-risk-platform"
DEPLOYMENT="ai-risk-platform"
CONTAINER="server"

# 태그 결정: 인자 있으면 사용, 없으면 git SHA 앞 7자리
if [ -n "${1:-}" ]; then
  TAG="$1"
else
  TAG="$(git rev-parse --short HEAD)"
fi
IMAGE="${ECR_REPO}:${TAG}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 AI Risk Platform Deploy"
echo "   Image: ${IMAGE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. git pull (최신 코드 확인)
echo ""
echo "📥 [1/5] git pull..."
git pull origin main --ff-only 2>/dev/null || echo "Already up to date (or not on main)"

# 2. ECR 로그인
echo ""
echo "🔐 [2/5] ECR login..."
aws ecr get-login-password --region ${REGION} | \
  docker login --username AWS --password-stdin ${ECR_REPO%/*}

# 3. Docker build (amd64)
echo ""
echo "🔨 [3/5] Docker build (linux/amd64)..."
docker build --platform linux/amd64 -t "${IMAGE}" .

# 4. ECR push
echo ""
echo "📤 [4/5] ECR push..."
docker push "${IMAGE}"

# 5. EKS rollout
echo ""
echo "🔄 [5/5] EKS rollout..."
kubectl set image deployment/${DEPLOYMENT} -n ${NAMESPACE} \
  ${CONTAINER}="${IMAGE}"

echo ""
echo "⏳ Waiting for rollout..."
kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE} --timeout=120s

# 결과 확인
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Deploy complete!"
echo ""
kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT}
echo ""
echo "🔍 로그 확인: kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT} --tail 5"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
