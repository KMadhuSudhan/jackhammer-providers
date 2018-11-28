#pulling jdk image
FROM openjdk:8

#provider
ENV TOOL_NAME "BundleAudit"

#retirejs scripts, logs and provider directories
RUN /bin/bash -c "mkdir -p /home/src/bundle_audit/"
RUN /bin/bash -c "mkdir -p /home/src/bundle_audit/logs"
RUN /bin/bash -c "mkdir -p /home/src/bundle_audit/scripts"
RUN /bin/bash -c "mkdir -p /home/src/bundle_audit/provider"

#script envs
ENV WORKSPACE /home/src/bundle_audit
ENV BUNDLE_AUDIT_PRE_DEPLOY_SCRIPT_PATH $WORKSPACE/scripts/BundleAuditPreDeploy.sh
ENV BUNDLE_AUDIT_DEPLOY_SCRIPT_PATH $WORKSPACE/scripts/BundleAuditDeploy.sh

#logs envs
ENV BUNDLE_AUDIT_PRE_DEPLOY_ERROR_LOG_PATH $WORKSPACE/logs/bundle_audit_pre_install_error.log
ENV BUNDLE_AUDIT_PRE_DEPLOY_OUTPUT_LOG_PATH $WORKSPACE/logs/bundle_audit_pre_install_output.log
ENV BUNDLE_AUDIT_DEPLOY_ERROR_LOG_PATH $WORKSPACE/logs/bundle_audit_install_error.log
ENV BUNDLE_AUDIT_DEPLOY_OUTPUT_LOG_PATH $WORKSPACE/logs/bundle_audit_install_output.log
ENV SCAN_ERROR_LOG_PATH $WORKSPACE/logs/scan_error.log

#installation scripts
COPY scripts/BundleAuditPreDeploy.sh $WORKSPACE/scripts/
COPY scripts/BundleAuditDeploy.sh $WORKSPACE/scripts/

#sdk files
#COPY JchSDK.jar $WORKSPACE
COPY config.yml $WORKSPACE

#working dir
WORKDIR $WORKSPACE

#coping provider 
COPY target/bundle-audit-provider.jar $WORKSPACE/provider/

#exposing port 
EXPOSE 9998

#running sdk for bundle-audit
CMD java -Xms500m -Xmx2920m -jar $WORKSPACE/provider/bundle-audit-provider.jar server $WORKSPACE/config.yml