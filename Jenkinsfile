pipeline {
    agent any
    
    environment {
        PYTHON_VERSION = '3.11'
        SCA_VERSION = '0.1.0'
        REPORTS_DIR = 'reports'
    }
    
    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    // Clean workspace and setup reports directory
                    deleteDir()
                    checkout scm
                    sh "mkdir -p ${REPORTS_DIR}"
                }
            }
        }
        
        stage('Install Dependencies') {
            steps {
                script {
                    // Setup Python virtual environment
                    sh '''
                        python3 -m venv venv
                        . venv/bin/activate
                        pip install --upgrade pip
                        pip install -e ".[dev]"
                    '''
                }
            }
        }
        
        stage('Lint and Test') {
            parallel {
                stage('Code Quality') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            black --check src/ tests/
                            isort --check-only src/ tests/
                            flake8 src/ tests/
                            mypy src/
                        '''
                    }
                }
                
                stage('Unit Tests') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            pytest tests/unit/ -v --junitxml=${REPORTS_DIR}/unit-tests.xml \
                                --cov=src/sca --cov-report=xml:${REPORTS_DIR}/coverage.xml \
                                --cov-report=html:${REPORTS_DIR}/coverage-html
                        '''
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: "${REPORTS_DIR}/unit-tests.xml"
                            publishCoverage adapters: [
                                coberturaAdapter("${REPORTS_DIR}/coverage.xml")
                            ], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                        }
                    }
                }
                
                stage('Integration Tests') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            pytest tests/integration/ -v --junitxml=${REPORTS_DIR}/integration-tests.xml
                        '''
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: "${REPORTS_DIR}/integration-tests.xml"
                        }
                    }
                }
            }
        }
        
        stage('Build Container') {
            steps {
                script {
                    // Build Docker image
                    def image = docker.build("secure-code-analyzer:${BUILD_NUMBER}")
                    env.DOCKER_IMAGE_ID = image.id
                }
            }
        }
        
        stage('Security Analysis') {
            parallel {
                stage('Self-Scan - Full') {
                    when {
                        branch 'main'
                    }
                    steps {
                        sh '''
                            . venv/bin/activate
                            sca scan . --json ${REPORTS_DIR}/self-scan.json \
                                --sarif ${REPORTS_DIR}/self-scan.sarif \
                                --config .sca-config.yaml
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/self-scan.*"
                            publishSarifReport sarifFile: "${REPORTS_DIR}/self-scan.sarif"
                        }
                    }
                }
                
                stage('PR Diff Scan') {
                    when {
                        changeRequest()
                    }
                    steps {
                        script {
                            // Get target branch for PR
                            def targetBranch = env.CHANGE_TARGET ?: 'main'
                            sh """
                                . venv/bin/activate
                                sca scan . --diff-base origin/${targetBranch} \
                                    --json ${REPORTS_DIR}/pr-diff.json \
                                    --sarif ${REPORTS_DIR}/pr-diff.sarif \
                                    --fail-on high
                            """
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/pr-diff.*"
                            publishSarifReport sarifFile: "${REPORTS_DIR}/pr-diff.sarif"
                        }
                        failure {
                            script {
                                // Add PR comment with scan results
                                def scanResults = readJSON file: "${REPORTS_DIR}/pr-diff.json"
                                def comment = generatePRComment(scanResults)
                                pullRequest.comment(comment)
                            }
                        }
                    }
                }
            }
        }
        
        stage('Baseline Management') {
            when {
                branch 'main'
            }
            steps {
                script {
                    // Update security baseline
                    sh '''
                        . venv/bin/activate
                        if [ -f security-baseline.sarif ]; then
                            sca scan . --baseline security-baseline.sarif \
                                --sarif ${REPORTS_DIR}/baseline-comparison.sarif
                        fi
                        
                        # Update baseline with current scan
                        cp ${REPORTS_DIR}/self-scan.sarif security-baseline.sarif
                    '''
                    
                    // Commit updated baseline
                    sh '''
                        git config user.name "Jenkins CI"
                        git config user.email "ci@company.com"
                        git add security-baseline.sarif
                        git commit -m "Update security baseline [skip ci]" || true
                        git push origin main || true
                    '''
                }
            }
        }
        
        stage('Deploy Artifacts') {
            when {
                branch 'main'
            }
            steps {
                script {
                    // Tag and push Docker image
                    docker.withRegistry('https://registry.company.com', 'docker-registry') {
                        def image = docker.image(env.DOCKER_IMAGE_ID)
                        image.push("${SCA_VERSION}")
                        image.push("latest")
                    }
                    
                    // Upload reports to artifact repository
                    sh '''
                        zip -r sca-reports-${BUILD_NUMBER}.zip ${REPORTS_DIR}/
                        curl -X PUT -T sca-reports-${BUILD_NUMBER}.zip \
                            "https://artifacts.company.com/sca/reports/"
                    '''
                }
            }
        }
    }
    
    post {
        always {
            // Archive all reports
            archiveArtifacts artifacts: "${REPORTS_DIR}/**/*", fingerprint: true
            
            // Clean up workspace
            cleanWs()
        }
        
        success {
            script {
                if (env.BRANCH_NAME == 'main') {
                    slackSend(
                        channel: '#security-alerts',
                        color: 'good',
                        message: """
                            ✅ SCA Build Successful - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                            Branch: ${env.BRANCH_NAME}
                            Security scan completed with no critical issues.
                            Reports: ${env.BUILD_URL}artifact/
                        """
                    )
                }
            }
        }
        
        failure {
            slackSend(
                channel: '#security-alerts',
                color: 'danger',
                message: """
                    ❌ SCA Build Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                    Branch: ${env.BRANCH_NAME}
                    Check console output: ${env.BUILD_URL}console
                """
            )
        }
        
        unstable {
            slackSend(
                channel: '#security-alerts',
                color: 'warning',
                message: """
                    ⚠️ SCA Build Unstable - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                    Branch: ${env.BRANCH_NAME}
                    Some tests failed or security issues found.
                    Reports: ${env.BUILD_URL}artifact/
                """
            )
        }
    }
}

def generatePRComment(scanResults) {
    def summary = scanResults.summary
    def findings = scanResults.findings
    
    def comment = """
## 🔒 Security Scan Results

**Scan Summary:**
- Files Scanned: ${summary.files_scanned}
- Total Findings: ${summary.total_findings}
- Duration: ${summary.duration_seconds}s

**Severity Breakdown:**
- Critical: ${summary.severity_counts.critical}
- High: ${summary.severity_counts.high}
- Medium: ${summary.severity_counts.medium}
- Low: ${summary.severity_counts.low}

"""

    if (summary.total_findings > 0) {
        comment += "\n**Top Issues:**\n"
        findings.take(5).each { finding ->
            comment += "- **${finding.severity.toUpperCase()}**: ${finding.message} (${finding.file}:${finding.line})\n"
        }
        
        if (findings.size() > 5) {
            comment += "\n*... and ${findings.size() - 5} more issues. See full report in build artifacts.*\n"
        }
        
        comment += "\n❌ **This PR introduces security vulnerabilities. Please review and fix before merging.**"
    } else {
        comment += "\n✅ **No security issues found in changed files.**"
    }
    
    return comment
}