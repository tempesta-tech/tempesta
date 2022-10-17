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
                        currentBuild.displayName = "PR-${ghprbPullId}"
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
                            echo "HASH EQUALS - no build required"
                            env.RUN_BUILD = "false"
                            echo "Check tempesta start/stop"
                            def TEMPESTA_STATUS = sh(returnStatus: true, script: "/root/tempesta/scripts/tempesta.sh --start")
                            sh "/root/tempesta/scripts/tempesta.sh --stop"
                            echo "$TEMPESTA_STATUS"
                            if (TEMPESTA_STATUS != "0"){
                                echo "TEMPESTA CANT RUN - new build required"
                                sh 'rm -rf /root/tempesta; cp -r . /root/tempesta'
                                env.RUN_BUILD = "true"
                            }
                        } else {
                            sh 'rm -rf /root/tempesta; cp -r . /root/tempesta'
                            env.RUN_BUILD = "true"
                        }
                    } catch (Exception e) {
                        echo "ERROR $e"
                        sh 'rm -rf /root/tempesta; cp -r . /root/tempesta'
                        env.RUN_BUILD = "true"
                    } finally {
                        echo "RUN_BUILD: ${RUN_BUILD}"
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
