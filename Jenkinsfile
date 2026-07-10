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
                    if (!jarFile) {
                        error 'No jar found in target/'
                    }
                    echo "Deploying ${jarFile} -> ${DEPLOY_DIR}/${JAR_NAME}"
                    sh """
                        sudo mkdir -p ${DEPLOY_DIR}/keys
                        # Stop first so the running JVM cannot keep the old code in memory
                        sudo supervisorctl stop iam || true
                        sudo cp '${jarFile}' ${DEPLOY_DIR}/${JAR_NAME}
                        sudo chown root:root ${DEPLOY_DIR}/${JAR_NAME}
                        sudo supervisorctl reread
                        sudo supervisorctl update iam || true
                        sudo supervisorctl start iam
                        sleep 3
                        sudo supervisorctl status iam
                    """
                }
            }
        }
        stage('Verify') {
            steps {
                sh '''
                    # build-info is permitAll on the jjwt build; must NOT be 401
                    code=$(curl -s -o /tmp/iam-build-info.json -w "%{http_code}" http://127.0.0.1:8082/api/v1/build-info || true)
                    echo "build-info HTTP $code"
                    cat /tmp/iam-build-info.json || true
                    echo
                    if [ "$code" != "200" ]; then
                      echo "IAM did not serve /api/v1/build-info (jjwt build). Check supervisor logs."
                      sudo supervisorctl tail iam stderr | tail -n 80 || true
                      exit 1
                    fi
                    grep -q 'jjwt-filter' /tmp/iam-build-info.json
                '''
            }
        }
    }
}
