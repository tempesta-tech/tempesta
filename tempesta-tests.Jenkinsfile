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
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    script {
                        currentBuild.displayName = "PR-${ghprbPullId}"
                    }
                    sh 'rm -rf /root/tempesta'
                }
            }
        }

        stage('Build tempesta-fw') {
            steps {
                sh 'cp -r . /root/tempesta'
                dir("/root/tempesta"){
                    sh 'make'
                }
            }
        }

        stage('Checkout tempesta-tests') {
            steps {
                sh 'rm -rf ${TESTS_PATH}'
                sh 'git clone https://github.com/tempesta-tech/tempesta-test.git ${TESTS_PATH}'
            }
        }

        stage('Run tests') {
            options {
                timeout(time: 30, unit: 'MINUTES')   // timeout on this stage
            }
            steps {
                dir("${TESTS_PATH}"){
                    sh './run_tests.py -nv'
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
