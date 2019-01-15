try {
  library "asdf_common@${env.BRANCH_NAME}" _
}
catch (ex) {
  library 'asdf_common_default' _
}

def BUILDS = [
  'linux/64/shared',
  'windows/64/shared',
// 'windows/64/shared-fat',
  'windows/64/static',
  'windows/32/shared',
// 'windows/32/shared-fat',
  'windows/32/static'
]

def BASE_URL = 'ssh://git@stash.strozfriedberg.com/asdf'
def DOWNSTREAM_REPOS = [['asdf']]
def UPSTREAM_REPOS = [
  ['jenkins-setup', 'master'],
  ['liblightgrep', 'master'],
  ['ssdeep', 'master']
]

pipeline {
  agent none
  stages {
    stage('Handle Upstream Trigger') {
      steps {
        script {
          common.HandleUpstreamTrigger(env, params, BASE_URL, UPSTREAM_REPOS)
        }
      }
    }
    stage('Build') {
      steps {
        script {
          parallel common.makeConfigurations(scm, BUILDS, BASE_URL, UPSTREAM_REPOS)
        }
      }
    }
    stage('Trigger Downstream') {
      steps {
        script {
          common.TriggerDownstream(env, DOWNSTREAM_REPOS)
        }
      }
    }
  }
}
