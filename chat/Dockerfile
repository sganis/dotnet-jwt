# chat/Dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# OpenShift runs containers with an arbitrary UID from the namespace range.
# Grant group-0 ownership + group-writable so any UID can write to /app.
RUN chgrp -R 0 /app && chmod -R g=u /app

# Non-root UID — OpenShift may override this with its own arbitrary UID.
USER 1001

EXPOSE 8080

# Env vars expected at runtime (set via OpenShift Deployment/ConfigMap/Secret):
#   JWT_ISSUER, JWT_AUDIENCE, JWT_JWKS_URL
#   LLM_BACKEND_URL
#   ACCESS_GROUPS, TIER_PRO_GROUPS, TIER_MAX_GROUPS, DEFAULT_TIER
#   REDIS_URL, RL_ENABLED
#   RL_RPM_BASIC, RL_RPM_PRO, RL_RPM_MAX
#   RL_CONC_BASIC, RL_CONC_PRO, RL_CONC_MAX

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
