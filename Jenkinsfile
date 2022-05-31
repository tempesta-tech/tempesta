pipeline {
    agent {
       label "epyc-tempesta-test"
    }

    stages {

        stage('make Tempesta') {
            steps {
                buildName '#PR-${ghprbPullId}'
                sh 'rm -rf /root/tempesta'
                sh 'cp -r . /root/tempesta'
                dir("/root/tempesta"){
                    sh 'make'
                }
            }
        }

        stage('Checkout Tempesta-tests') {
            steps {
                sh 'rm -rf /home/tempesta/tempesta-test'
                sh 'git clone https://github.com/tempesta-tech/tempesta-test.git /home/tempesta/tempesta-test'
            }
        }

        stage('Run tests') {
            steps {
                dir("/home/tempesta/tempesta-test"){
                    sh './run_tests.py ws'
                }
            }
        }

    }
}