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
                    // NOTE: jenkins sudoers allows cp/chown/reread/update/restart/start for some
                    // supervisorctl subcommands, but not always stop/status. Use restart so the
                    // running JVM reloads app.jar. Do not use `start || restart` — start succeeds
                    // when already running and the new jar never loads.
                    sh """
                        sudo mkdir -p ${DEPLOY_DIR}/keys
                        sudo cp '${jarFile}' ${DEPLOY_DIR}/${JAR_NAME}
                        sudo chown root:root ${DEPLOY_DIR}/${JAR_NAME}
                        sudo supervisorctl reread
                        sudo supervisorctl update iam || true
                        sudo supervisorctl restart iam
                        sleep 5
                    """
                }
            }
        }
        stage('Verify') {
            steps {
                sh '''
                    set +e
                    for i in 1 2 3 4 5 6 7 8 9 10; do
                      code=$(curl -s -o /tmp/iam-build-info.json -w "%{http_code}" http://127.0.0.1:8082/api/v1/build-info)
                      echo "attempt $i: build-info HTTP $code"
                      if [ "$code" = "200" ]; then
                        cat /tmp/iam-build-info.json
                        echo
                        grep -q 'jjwt-filter' /tmp/iam-build-info.json && exit 0
                        echo "build-info returned 200 but decoder is not jjwt-filter"
                        cat /tmp/iam-build-info.json
                        exit 1
                      fi
                      sleep 2
                    done
                    echo "IAM did not serve /api/v1/build-info after deploy."
                    echo "Jar was copied, but the process may still be the old JVM."
                    echo "On the host run: sudo supervisorctl restart iam"
                    exit 1
                '''
            }
        }
    }
}
