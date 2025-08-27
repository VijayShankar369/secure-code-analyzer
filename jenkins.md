# Jenkins SAST Pipeline Integration

## Jenkinsfile Configuration

```groovy
pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = "secure-code-analyzer:latest"
        REPORTS_DIR = "security-reports"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build Scanner Image') {
            steps {
                script {
                    docker.build("${DOCKER_IMAGE}", ".")
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    // Create reports directory
                    sh "mkdir -p ${REPORTS_DIR}"
                    
                    // Run SAST scan with failure control
                    def scanResult = sh(
                        script: """
                            docker run --rm \
                                -v \${PWD}:/code \
                                -v \${PWD}/${REPORTS_DIR}:/reports \
                                ${DOCKER_IMAGE} \
                                scan /code --json /reports/sast-report.json --fail-on critical
                        """,
                        returnStatus: true
                    )
                    
                    // Archive results regardless of scan outcome
                    archiveArtifacts artifacts: "${REPORTS_DIR}/**/*", allowEmptyArchive: true
                    
                    // Handle scan results
                    if (scanResult == 0) {
                        echo "✅ Security scan passed - no critical vulnerabilities found"
                    } else {
                        echo "⚠️ Security scan found issues - check report for details"
                        currentBuild.result = 'UNSTABLE'
                        
                        // Optional: fail build on critical issues
                        // error("Security scan failed with critical vulnerabilities")
                    }
                }
            }
        }
        
        stage('Process Results') {
            steps {
                script {
                    // Parse and display summary
                    if (fileExists("${REPORTS_DIR}/sast-report.json")) {
                        def report = readJSON file: "${REPORTS_DIR}/sast-report.json"
                        echo "Security Scan Summary:"
                        echo "Files Scanned: ${report.scan_summary?.files_scanned ?: 'N/A'}"
                        echo "Total Findings: ${report.scan_summary?.total_findings ?: 'N/A'}"
                        
                        // Create JIRA tickets for critical issues (optional)
                        // createSecurityTickets(report)
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Publish test results if using JUnit format
            // publishTestResults testResultsPattern: "${REPORTS_DIR}/*.xml"
            
            // Clean up Docker images
            sh "docker rmi ${DOCKER_IMAGE} || true"
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security vulnerabilities detected. Check build logs and reports.",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

## Shared Library Function

```groovy
// vars/securityScan.groovy
def call(Map config) {
    def image = config.image ?: "secure-code-analyzer:latest"
    def failOn = config.failOn ?: "high"
    def reportPath = config.reportPath ?: "security-reports"
    
    script {
        sh "mkdir -p ${reportPath}"
        
        def scanResult = sh(
            script: """
                docker run --rm \
                    -v \${PWD}:/code \
                    -v \${PWD}/${reportPath}:/reports \
                    ${image} \
                    scan /code --json /reports/sast-report.json --fail-on ${failOn}
            """,
            returnStatus: true
        )
        
        archiveArtifacts artifacts: "${reportPath}/**/*", allowEmptyArchive: true
        
        return scanResult
    }
}
```

Usage:
```groovy
stage('Security Scan') {
    steps {
        script {
            def result = securityScan([
                failOn: 'critical',
                reportPath: 'reports'
            ])
            
            if (result != 0) {
                currentBuild.result = 'UNSTABLE'
            }
        }
    }
}
```