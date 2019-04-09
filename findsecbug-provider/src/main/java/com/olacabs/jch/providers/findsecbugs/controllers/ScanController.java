package com.olacabs.jch.providers.findsecbugs.controllers;

import java.io.File;
import java.io.IOException;

import com.olacabs.jch.providers.findsecbugs.common.ExceptionMessages;
import com.olacabs.jch.sdk.models.ScanRequest;
import com.olacabs.jch.sdk.models.ScanResponse;
import com.olacabs.jch.sdk.spi.ScanSpi;
import com.olacabs.jch.providers.findsecbugs.common.Constants;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;


@Slf4j
public class ScanController implements ScanSpi {

    public ProcessBuilder buildScanCommand(ScanRequest scanRequest) {

        Process process;
        //scan compiler builder
        ProcessBuilder compileBuilder = new ProcessBuilder();
        //scan process builder
        ProcessBuilder builder = new ProcessBuilder();

        //compile command,logs and running directory
        compileBuilder.command(Constants.BASH_PATH, Constants.MAVEN_CMD, Constants.MAVEN_COMPILE, Constants.MAVEN_COMPILE_ARG);

//        compileBuilder.command(Constants.BASH_PATH, Constants.MAVEN_CMD, Constants.MAVEN_CLEAN_ARG, Constants.MAVEN_INSTALL_ARG);
        compileBuilder.redirectOutput(new File(System.getenv(Constants.MAVEN_COMPILE_OUT_PUT_PATH)));
        compileBuilder.redirectError(new File(System.getenv(Constants.MAVEN_COMPILE_ERROR_PATH)));
        compileBuilder.directory(new File(scanRequest.getTarget()));

        //scan error log and running directory
//        builder.redirectError(new File(System.getenv(Constants.SCAN_ERROR_LOG_PATH)));
        builder.directory(new File(System.getenv(Constants.FIND_SEC_BUGS_INSTALLED_PATH)));

        try {
            //run compile
            String maxHeapSize = System.getenv(Constants.MAX_HEAP_SIZE);
            log.info("mvn compile starting........");
            process = compileBuilder.start();
//            System.out.println(compileBuilder.redirectError());
//            System.out.println(compileBuilder.redirectOutput());
            process.waitFor();
            log.info("mvn compile completed........");
            //build scan cmd
            File tempFile = File.createTempFile(Constants.TEMP_FILE_PREFIX, Constants.TEMP_FILE_SUFFIX);
            builder.command(Constants.BASH_PATH, Constants.CLI_SCRIPT_CMD, Constants.MAX_HEAP, maxHeapSize, Constants.EFFORT_MAX_ARG, Constants.QUIET_ARG,
                    Constants.XML_WITH_MESSAGES_ARG, Constants.OUTPUT_ARG, tempFile.getAbsolutePath(), Constants.BUG_CATEGORIES_ARG,
                    Constants.BUG_CATEGORIES_ARG_VAL, Constants.TEXT_UI, scanRequest.getTarget());
            //set scan result file
            scanRequest.setResultFile(tempFile);
        } catch (IOException io) {
            log.error("IOException while building find sec bugs scan command", io);
        } catch (Exception e) {
            log.error("Exception while building scan command", e);
        } catch (Throwable th) {
            log.error("Throwable exception while building scan command", th);
        }
        return builder;
    }


    public ScanResponse executeScanCommand(ProcessBuilder builder) {
        ScanResponse scanResponse = new ScanResponse();
        scanResponse.setStartTime(System.currentTimeMillis());
        Process process;
        try {
            log.info("Scanning started........");
            process = builder.start();
            System.out.println(builder.redirectError());
            System.out.println(builder.redirectOutput());
            log.info("waiting for scan to finish........");
            process.waitFor();
            log.info("scan completed........");
            File m2Repository = new File(System.getenv(Constants.HOME) + Constants.REPOSITORY_DIR);
            if (m2Repository.exists()) FileUtils.deleteDirectory(m2Repository);
        } catch (IOException io) {
            scanResponse.setStatus(Constants.FAILED_STATUS);
            scanResponse.setFailedReasons(ExceptionMessages.IO_EXCEPTION);
            log.error("IOException while running FindSecBugs", io);
        } catch (InterruptedException ie) {
            scanResponse.setStatus(Constants.FAILED_STATUS);
            scanResponse.setFailedReasons(ExceptionMessages.INTERRUPTED_EXCEPTION);
            log.error("InterruptedException while running FindSecBugs", ie);
        } catch (Throwable th) {
            scanResponse.setStatus(Constants.FAILED_STATUS);
            scanResponse.setFailedReasons(ExceptionMessages.INTERRUPTED_EXCEPTION);
            log.error("Error while running scan", th);
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


