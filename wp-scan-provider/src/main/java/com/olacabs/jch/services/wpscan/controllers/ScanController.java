package com.olacabs.jch.services.wpscan.controllers;

import java.io.File;
import java.io.IOException;
import java.util.*;

import com.olacabs.jch.sdk.models.ScanRequest;
import com.olacabs.jch.sdk.models.ScanResponse;
import com.olacabs.jch.sdk.spi.ScanSpi;
import com.olacabs.jch.services.wpscan.common.ExceptionMessages;
import com.olacabs.jch.services.wpscan.common.Constants;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ScanController implements ScanSpi {

    public ProcessBuilder buildScanCommand(ScanRequest scanRequest) {
        ProcessBuilder builder = new ProcessBuilder();
        Map<String, String> envs = builder.environment();

        //update builder
        ProcessBuilder updateBuilder = new ProcessBuilder();

        File tempFile = null;
        try {
            tempFile = File.createTempFile(Constants.TEMP_FILE_PREFIX, Constants.TEMP_FILE_SUFFIX);
            updateBuilder.command(Constants.RUBY_CMD, envs.get(Constants.WP_SCAN_UPDATION_PATH), Constants.WP_SCAN_UPDATE_ARG);
            Process process;
            process = updateBuilder.start();
            process.waitFor();
        } catch (IOException e) {
            log.error("Temp file could not created/IOException while updating wp scan");
        } catch (InterruptedException ie) {
            log.error("InterruptedException while updating wp scan", ie);
        }

        scanRequest.setResultFile(tempFile);
        builder.command(Constants.RUBY_CMD, envs.get(Constants.WP_SCAN_INSTALLATION_PATH), scanRequest.getTarget().replace("\"", ""), tempFile.getAbsolutePath());
        builder.redirectOutput(new File(envs.get(Constants.SCAN_OUT_PUT_LOG_PATH)));
        builder.redirectError(new File(envs.get(Constants.SCAN_ERROR_LOG_PATH)));
        return builder;
    }

    public ScanResponse executeScanCommand(ProcessBuilder builder) {
        ScanResponse scanResponse = new ScanResponse();
        scanResponse.setStartTime(System.currentTimeMillis());
        try {
            Process process;
            process = builder.start();
            process.waitFor();
        } catch (IOException io) {
            scanResponse.setStatus(Constants.FAILED_STATUS);
            scanResponse.setFailedReasons(ExceptionMessages.IO_EXCEPTION);
            log.error("IOException while running wp scan", io);
        } catch (InterruptedException ie) {
            scanResponse.setStatus(Constants.FAILED_STATUS);
            scanResponse.setFailedReasons(ExceptionMessages.INTERRUPTED_EXCEPTION);
            log.error("InterruptedException while running wp scan", ie);
        }
        return scanResponse;
    }

    public String getToolName() {
        return Constants.PROVIDER_NAME;
    }


    public ProcessBuilder buildCommand() {
        // TODO Auto-generated method stub
        return null;
    }


    public ProcessBuilder buildCommand(File scriptFile) {
        // TODO Auto-generated method stub
        return null;
    }
}
