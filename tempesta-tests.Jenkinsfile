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
                script {
                    env.RUN_BUILD = "true"
                    currentBuild.displayName = "${GIT_COMMIT}-$PARAMS"
                    currentBuild.displayName = "PR-${ghprbPullId}"
                    OLD_HASH=sh(script: "git rev-parse HEAD", returnStdout: true).trim()
                    echo "OLD HASH: $OLD_HASH"
                    try {
                        dir("/root/tempesta"){
                            NEW_HASH=sh(script: "git rev-parse HEAD", returnStdout: true).trim()
                            echo "NEW HASH: $NEW_HASH"
                        }
                        if (OLD_HASH == NEW_HASH){
                            echo 'New new hash detected - new build will run'
                            env.RUN_BUILD = "false"
                        }
                        def TEMPESTA_STATUS = sh(returnStatus: true, script: "/root/tempesta/scripts/tempesta.sh --start")
                        sh "/root/tempesta/scripts/tempesta.sh --stop"
                        if (TEMPESTA_STATUS == 1){
                            env.RUN_BUILD = "true"
                        }
                    } catch (Exception e) {
                        env.RUN_BUILD = "true"
                        echo "ERROR $e"
                    } finally {
                        sh 'rm -rf /root/tempesta'
                        sh 'cp -r . /root/tempesta'
                        env.RUN_BUILD = "true"
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
