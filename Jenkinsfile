pipeline {
    agent any

    tools {
        jdk 'jdk-23'
        maven 'Maven'
    }

    environment {
        DEPLOY_DIR = '/opt/services/iam'
        JAR_NAME = 'app.jar'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('Build') {
            steps { sh 'mvn -B clean package -DskipTests' }
        }
        stage('Deploy') {
            steps {
                script {
                    def jarFile = sh(
                        script: "find target -maxdepth 1 -name '*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1",
                        returnStdout: true
                    ).trim()
                    sh """
                        sudo mkdir -p ${DEPLOY_DIR}/keys
                        sudo cp '${jarFile}' ${DEPLOY_DIR}/${JAR_NAME}
                        sudo chown root:root ${DEPLOY_DIR}/${JAR_NAME}
                        sudo supervisorctl reread
                        sudo supervisorctl update iam || true
                        sudo supervisorctl start iam || sudo supervisorctl restart iam
                    """
                }
            }
        }
    }
}