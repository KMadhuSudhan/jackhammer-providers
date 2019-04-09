package com.olacabs.jch.providers.findsecbugs.common;

public class Constants {
    public static final String PROVIDER_NAME = "FindSecBugs";
    public static final String NOHUP = "nohup";
    public static final String SH="sh";
    public static final String TEMP_FILE_PREFIX = "findsecbug";
    public static final String TEMP_FILE_SUFFIX = ".xml";
    public static final String COMPLETED_STATUS = "Completed";
    public static final String FAILED_STATUS = "Failed";
    public static final String CRITICAL = "Critical";
    public static final String HIGH = "High";
    public static final String MEDIUM = "Medium";
    public static final String LOW = "Low";
    public static final String INFO = "Info";
    public static final String BASH_PATH = "/bin/bash";
    public static final String CLI_SCRIPT_CMD = "./spotbugs";
    public static final String EFFORT_MAX_ARG = "-effort:max";
    public static final String QUIET_ARG = "-quiet";
    public static final String XML_WITH_MESSAGES_ARG = "-xml:withMessages";
    public static final String OUTPUT_ARG = "-output";
    public static final String TEXT_UI = "-textui";
    public static final String MAVEN_CMD = "mvn";
    public static final String MAVEN_COMPILE = "compile";
    public static final String MAVEN_COMPILE_ARG = "-fn";
    public static final String MAVEN_CLEAN_ARG = "clean";
    public static final String MAVEN_INSTALL_ARG = "install";
    public static final String BUG_INSTANCE ="BugInstance";
    public static final String HOME = "HOME";
    public static final String REPOSITORY_DIR = "/.m2/repository";
    public static final String BUG_CATEGORIES_ARG = "-bugCategories";
    public static final String BUG_CATEGORIES_ARG_VAL = "SECURITY";

    //pre deploy
    public static final String FIND_SEC_BUGS_PRE_DEPLOY_SCRIPT_PATH = "FIND_SEC_BUGS_PRE_DEPLOY_SCRIPT_PATH";
    public static final String FIND_SEC_BUGS_PRE_DEPLOY_ERROR_LOG_PATH = "FIND_SEC_BUGS_PRE_DEPLOY_ERROR_LOG_PATH";
    public static final String FIND_SEC_BUGS_PRE_DEPLOY_OUTPUT_LOG_PATH = "FIND_SEC_BUGS_PRE_DEPLOY_OUTPUT_LOG_PATH";

    // deploy
    public static final String FIND_SEC_BUGS_DEPLOY_SCRIPT_PATH = "FIND_SEC_BUGS_DEPLOY_SCRIPT_PATH";
    public static final String FIND_SEC_BUGS_DEPLOY_ERROR_LOG_PATH = "FIND_SEC_BUGS_DEPLOY_ERROR_LOG_PATH";
    public static final String FIND_SEC_BUGS_DEPLOY_OUTPUT_LOG_PATH = "FIND_SEC_BUGS_DEPLOY_OUTPUT_LOG_PATH";

    // post deploy
    public static final String FIND_SEC_BUGS_POST_DEPLOY_SCRIPT_PATH = "FIND_SEC_BUGS_POST_DEPLOY_SCRIPT_PATH";
    public static final String FIND_SEC_BUGS_POST_DEPLOY_ERROR_LOG_PATH = "FIND_SEC_BUGS_POST_DEPLOY_ERROR_LOG_PATH";
    public static final String FIND_SEC_BUGS_POST_DEPLOY_OUTPUT_LOG_PATH = "FIND_SEC_BUGS_POST_DEPLOY_OUTPUT_LOG_PATH";

    //code compile logs
    public static final String MAVEN_COMPILE_OUT_PUT_PATH = "MAVEN_COMPILE_OUT_PUT_PATH";
    public static final String MAVEN_COMPILE_ERROR_PATH = "MAVEN_COMPILE_ERROR_PATH";

    //scan
    public static final String FIND_SEC_BUGS_INSTALLED_PATH = "FIND_SEC_BUGS_INSTALLED_PATH";
    public static final String SCAN_ERROR_LOG_PATH = "SCAN_ERROR_LOG_PATH";

    //xml attributes
    public static final String SHORT_MESSAGE = "ShortMessage";
    public static final String LONG_MESSAGE = "LongMessage";
    public static final String TYPE = "type";
    public static final String METHOD_ATTR = "Method";
    public static final String NAME_ATTR = "Name";
    public static final String CLASS_NAME = "classname";
    public static final String SOURCE_LINE = "SourceLine";
    public static final String SOURCE_PATH = "sourcepath";
    public static final String PRIMARY = "primary";
    public static final String START = "start";
    public static final String PRIORITY = "priority";
    public static final String EXTERNAL_LINK = "https://find-sec-bugs.github.io/bugs.htm##";
    public static final String CLASS = "Class: ";
    public static final String METHOD = "Method :";
    public static final String LOCATION_SEPARATOR = ",";
    public static final String MAX_HEAP = "-maxHeap";
    public static final String MAX_HEAP_SIZE = "MAX_HEAP_SIZE";
}
