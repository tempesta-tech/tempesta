pipeline {
    environment {
        TESTS_PATH = "/home/tempesta/tempesta-test"
        RUN_BUILD = "true"
    }

    agent {
       label "tempesta-test"
    }

    stages {
        stage('Set buildName'){
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    script {
                        currentBuild.displayName = "${GIT_COMMIT[0..7]} $PARAMS"
                        catchError {
                            currentBuild.displayName = "PR-${ghprbPullId}"
                        }
                    }
                }
            }
        }
    
        stage('Pre build'){
            steps {
                script {
                    try {
                        dir("/root/tempesta"){
                            NEW_HASH=sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                        }
                        echo "NEW HASH: $NEW_HASH"
                        OLD_HASH=sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                        echo "OLD HASH: $OLD_HASH"
                        if (OLD_HASH == NEW_HASH){
                            echo "HASH EQUALS - no new build"
                            env.RUN_BUILD = "false"
                        }
                        echo "Check tempesta start/stop"
                        def TEMPESTA_STATUS = sh(returnStatus: true, script: "/root/tempesta/scripts/tempesta.sh --start")
                        sh "/root/tempesta/scripts/tempesta.sh --stop"
                        if (TEMPESTA_STATUS == 1){
                            echo "TEMPESTA CANT RUN - SET RUN_BUILD"
                            env.RUN_BUILD = "true"
                        }
                        if (env.RUN_BUILD == "true"){
                            echo "Clean tempesta src"
                            sh 'rm -rf /root/tempesta'
                            sh 'cp -r . /root/tempesta'
                        }
                    } catch (Exception e) {
                        env.RUN_BUILD = "true"
                        echo "ERROR $e"
                    } finally {
                        if (env.RUN_BUILD == "true"){
                            sh 'rm -rf /root/tempesta'
                            sh 'cp -r . /root/tempesta'
                            env.RUN_BUILD = "true"
                        }
                    }
                }
            }
        }
                        

        stage('Build tempesta-fw') {
            when {
                expression { env.RUN_BUILD == 'true' }
            }
            steps {
                dir("/root/tempesta"){
                    sh 'make'
                }
            }
        }

        stage('Checkout tempesta-tests') {
            steps {
                sh "rm -rf ${TESTS_PATH}"
                sh "git clone --branch $TEST_BRANCH https://github.com/tempesta-tech/tempesta-test.git ${TESTS_PATH}"
            }
        }

        stage('Run tests') {
            options {
                timeout(time: 180, unit: 'MINUTES')   // timeout on this stage
            }
            steps {
                dir("${TESTS_PATH}"){
                    sh "./run_tests.py $PARAMS"
                }
            }
        }


        stage('Clean WS'){
            steps {
                    cleanWs()
                }
        }
    }
}
