FROM redis:7-alpine
# OpenShift runs containers with arbitrary UID but always GID 0.
# /data must be group-writable so any assigned UID can write.
RUN chown -R 999:0 /data && chmod -R g+rwX /data
USER 999
EXPOSE 6379
# No persistence — rate-limit counters reset on restart (acceptable per spec)
CMD ["redis-server", "--save", "", "--appendonly", "no"]
