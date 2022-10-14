pipeline {
    environment {
        TESTS_PATH = "/home/tempesta/tempesta-test"
    }

    agent {
       label "tempesta-test"
    }

    stages {
        stage('Set buildName'){
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'SUCCESS') {
                    script {
                        currentBuild.displayName = "${GIT_COMMIT}-$PARAMS"
                        currentBuild.displayName = "PR-${ghprbPullId}"
                    }
                    def old_hash='git rev-parse HEAD'
                    dir("${TESTS_PATH}"){
                        def new_hash='git rev-parse HEAD'
                    }
                    if (old_hash == new_hash){
                        echo 'New new hash detected - new build will run'
                        def run_build = "false"
                    }
                    else{
                        sh 'rm -rf /root/tempesta'
                        def run_build = "true"
                    }
                }
            }
        }

        stage('Build tempesta-fw') {
            when {
                environment name: 'run_build', value: 'true'
            }
            steps {
                sh 'cp -r . /root/tempesta'
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
