package com.olacabs.jch.services.bundleaudit.controllers;

import java.io.File;
import java.io.IOException;

import com.olacabs.jch.sdk.spi.DeploySpi;
import com.olacabs.jch.services.bundleaudit.common.Constants;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DeployController implements DeploySpi {

    public ProcessBuilder buildCommand() {
        ProcessBuilder builder = new ProcessBuilder(Constants.NOHUP,Constants.SH,System.getenv(Constants.BUNDLE_AUDIT_DEPLOY_SCRIPT_PATH));
        builder.redirectError(new File(System.getenv(Constants.BUNDLE_AUDIT_DEPLOY_ERROR_LOG_PATH)));
        builder.redirectOutput(new File(System.getenv(Constants.BUNDLE_AUDIT_DEPLOY_OUTPUT_LOG_PATH)));
        return builder;
    }

	public int executeCommand(ProcessBuilder processBuilder) {
        Process process;
        int exit;
        try {
            process = processBuilder.start();
            exit =  process.waitFor();
        } catch (IOException e) {
            exit = -1;
            log.error("IOException while installing bundle audit", e);
        } catch (InterruptedException ie) {
            exit = -1;
            log.error("InterruptedException while installing bundle audit",ie);
        }
        return exit;
	}

    public ProcessBuilder buildCommand(String command) {
        // TODO Auto-generated method stub
        return null;
    }

	public ProcessBuilder buildCommand(File scriptFile) {
		// TODO Auto-generated method stub
		return null;
	}

    public String getToolName() {
        return Constants.PROVIDER_NAME;
    }
 
}
