pipeline {
    environment {
        TESTS_PATH = "/home/tempesta/tempesta-test"
    }

    agent {
       label "tempesta-test"
    }

    stages {
        stage('Set buildName and cleanWS'){
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    script {
                        currentBuild.displayName = "PR-${ghprbPullId}"
                    }
                    cleanWs()
                    sh 'rm -rf /root/tempesta'
                }
            }
        }

        stage('Build tempesta-fw') {
            steps {
                sh 'sudo git clone https://github.com/tempesta-tech/tempesta.git /root/tempesta'
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
            steps {
                dir("${TESTS_PATH}"){
                    sh './run_tests.py -n'
                }
            }
        }

    }
}
