pipeline {
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
                sh 'git clone https://github.com/tempesta-tech/tempesta.git'
                sh 'mv tempesta /root/tempesta'
                dir("/root/tempesta"){
                    sh 'make'
                }
            }
        }

        stage('Checkout tempesta-tests') {
            steps {
                sh 'rm -rf /home/tempesta/tempesta-test'
                sh 'git clone https://github.com/tempesta-tech/tempesta-test.git /home/tempesta/tempesta-test'
            }
        }

        stage('Run tests') {
            steps {
                dir("/home/tempesta/tempesta-test"){
                    sh './run_tests.py'
                }
            }
        }

    }
}
