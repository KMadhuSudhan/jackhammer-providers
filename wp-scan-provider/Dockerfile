#pulling jdk image
FROM ubuntu:18.04

RUN rm -rf /var/lib/apt/lists/* && apt-get clean && apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && apt-get install -y git \
    && apt-get install -y iproute2 \
    && apt-get install -y inetutils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk


#provider
ENV TOOL_NAME "WpScan"

#wp_scan scripts, logs and provider directories
RUN /bin/bash -c "mkdir -p /home/src/WpScan/"
RUN /bin/bash -c "mkdir -p /home/src/WpScan/logs"
RUN /bin/bash -c "mkdir -p /home/src/WpScan/scripts"
RUN /bin/bash -c "mkdir -p /home/src/WpScan/provider"
RUN /bin/bash -c "mkdir -p /home/src/WpScan/scanner"

#script envs
ENV PATH /root/.rbenv/bin:/root/.rbenv/shims:$PATH
ENV WORKSPACE /home/src/WpScan
ENV WP_SCAN_PRE_DEPLOY_SCRIPT_PATH $WORKSPACE/scripts/WpScanPreDeploy.sh
ENV WP_SCAN_DEPLOY_SCRIPT_PATH $WORKSPACE/scripts/WpScanDeploy.sh

#logs envs
ENV WP_SCAN_PRE_DEPLOY_ERROR_LOG_PATH $WORKSPACE/logs/wp_scan_pre_install_error.log
ENV WP_SCAN_PRE_DEPLOY_OUTPUT_LOG_PATH $WORKSPACE/logs/wp_scan_pre_install_output.log
ENV WP_SCAN_DEPLOY_ERROR_LOG_PATH $WORKSPACE/logs/wp_scan_install_error.log
ENV WP_SCAN_DEPLOY_OUTPUT_LOG_PATH $WORKSPACE/logs/wp_scan_install_output.log

ENV WP_SCAN_INSTALLATION_PATH $WORKSPACE/scanner/wp_scan.rb
ENV WP_SCAN_UPDATION_PATH $WORKSPACE/scanner/wpscan.rb
ENV SCAN_ERROR_LOG_PATH $WORKSPACE/logs/scan_error.log
ENV SCAN_OUT_PUT_LOG_PATH $WORKSPACE/logs/scan_output.log

#installation scripts
COPY scripts/WpScanPreDeploy.sh $WORKSPACE/scripts/
COPY scripts/WpScanDeploy.sh $WORKSPACE/scripts/
#host setup
COPY scripts/docker-host.sh $WORKSPACE/scripts/
#sdk files
#COPY JchSDK.jar $WORKSPACE
COPY config.yml $WORKSPACE

#working dir
WORKDIR $WORKSPACE

#coping provider 
COPY target/wpscan-provider.jar $WORKSPACE/provider/

#coping scanner
COPY wpscan/ $WORKSPACE/scanner/

#running sdk for wp_scan
CMD java -Xms500m -Xmx2920m -jar $WORKSPACE/provider/wpscan-provider.jar server $WORKSPACE/config.yml
